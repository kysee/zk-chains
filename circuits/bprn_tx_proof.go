package circuit

import (
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// Circuit size constants
const (
	T0MaxSize         = 2048 // Maximum bytes for T0 (prefix)
	T1MaxSize         = 1024 // Maximum bytes for T1 (suffix)
	InternalBytesSize = 256  // Fixed size for InternalBytes

	// SHA256 constants
	BlockSize = 64
	// Max total size = 2048 + 256 + 1024 = 3328 bytes
	// Padding overhead = 1 byte (0x80) + 8 bytes (length) = 9 bytes
	// Max padded size = 3337 bytes -> ceil(3337/64) = 53 blocks
	MaxBlocks = 53
)

// BPrNTxProofCircuit verifies P256 ECDSA signature on transaction data
// and proves that InternalBytes is contained within the original transaction.
//
// Architecture:
// - Prover provides T0 (prefix) and T1 (suffix) as secret inputs with actual lengths
// - Circuit computes SHA256(T0[0:T0Len] || InternalBytes || T1[0:T1Len])
// - Verifies ECDSA P256 signature on the computed hash
//
// Uses PLONK + BN254
type BPrNTxProofCircuit struct {
	// Secret inputs - prover provides these directly
	T0    [T0MaxSize]uints.U8 // Data before InternalBytes (padded to max)
	T0Len frontend.Variable   // Actual length of T0 (0 <= T0Len <= T0MaxSize)
	T1    [T1MaxSize]uints.U8 // Data after InternalBytes (padded to max)
	T1Len frontend.Variable   // Actual length of T1 (0 <= T1Len <= T1MaxSize)

	// P256 Public Key (X, Y coordinates)
	Pub ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]

	// P256 Signature (R, S values)
	Sig ecdsa.Signature[emulated.P256Fr]

	// Public input
	InternalBytes [InternalBytesSize]uints.U8 `gnark:",public"` // Data proven to be in transaction
}

func (c *BPrNTxProofCircuit) Define(api frontend.API) error {
	// 1. Validate lengths
	api.AssertIsLessOrEqual(c.T0Len, T0MaxSize)
	api.AssertIsLessOrEqual(c.T1Len, T1MaxSize)

	// 2. Construct the padded data for SHA256 using a Hint
	// This avoids complex variable-index shifting logic by letting the prover supply the padded data.
	// Note: In a production circuit, you MUST verify that paddedData matches T0, InternalBytes, and T1.
	paddedData, numBlocks, err := c.constructPaddedDataHint(api)
	if err != nil {
		return err
	}

	// 3. Compute SHA256 on the padded blocks
	// We use a custom loop because standard sha2 gadget pads the input again.
	computedHash, err := computeSHA256(api, paddedData, numBlocks)
	if err != nil {
		return err
	}

	// 4. Convert computed hash to emulated.Element for P256Fr (scalar field)
	scalarApi, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return err
	}
	msgHash := hashBytesToElement(api, scalarApi, computedHash)

	// 5. Verify ECDSA P256 signature
	c.Pub.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), msgHash, &c.Sig)

	return nil
}

func (c *BPrNTxProofCircuit) constructPaddedDataHint(api frontend.API) ([]uints.U8, frontend.Variable, error) {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, nil, err
	}

	// Prepare inputs for the hint
	hintInputs := []frontend.Variable{c.T0Len, c.T1Len}
	for _, b := range c.T0 {
		hintInputs = append(hintInputs, b.Val)
	}
	for _, b := range c.InternalBytes {
		hintInputs = append(hintInputs, b.Val)
	}
	for _, b := range c.T1 {
		hintInputs = append(hintInputs, b.Val)
	}

	// Call Hint to get padded data AND number of blocks
	// Output[0] = numBlocks
	// Output[1:] = paddedData
	hintResults, err := api.Compiler().NewHint(GenPaddedDataHint, 1+MaxBlocks*BlockSize, hintInputs...)
	if err != nil {
		return nil, nil, err
	}

	numBlocks := hintResults[0]
	paddedVars := hintResults[1:]

	// Verify numBlocks
	// numBlocks = ceil((T0Len + 256 + T1Len + 9) / 64)
	// Formula: numBlocks = (TotalLen + 8 + 64) / 64 = (TotalLen + 72) / 64 (integer division)
	// We verify: numBlocks * 64 <= TotalLen + 72 < (numBlocks + 1) * 64
	// Or simply: TotalLen + 72 = numBlocks * 64 + remainder, where 0 <= remainder < 64
	totalLen := api.Add(c.T0Len, InternalBytesSize, c.T1Len)
	numerator := api.Add(totalLen, 72)

	// Check 1: numerator >= numBlocks * 64
	product := api.Mul(numBlocks, 64)
	api.AssertIsLessOrEqual(product, numerator)

	// Check 2: numerator < (numBlocks + 1) * 64 => numerator - product < 64
	remainder := api.Sub(numerator, product)
	api.AssertIsLessOrEqual(remainder, 63)

	paddedData := make([]uints.U8, len(paddedVars))
	paddedVals := make([]frontend.Variable, len(paddedVars))
	for i := 0; i < len(paddedVars); i++ {
		paddedData[i] = uints.U8{Val: paddedVars[i]}
		paddedVals[i] = paddedVars[i]
		uapi.ByteValueOf(paddedData[i].Val)
	}

	// --- Verification Logic ---

	// 1. Verify T0 prefix
	// paddedData[i] == T0[i] for i < T0Len
	for i := 0; i < T0MaxSize; i++ {
		// Check if i < T0Len (equivalent to T0Len > i)
		// api.Cmp returns 1 if T0Len > i, 0 if equal, -1 if less
		cmp := api.Cmp(c.T0Len, i)
		isT0 := api.IsZero(api.Sub(cmp, 1)) // 1 if T0Len > i, else 0

		// If isT0, diff must be 0. If not, we don't care (multiply by 0).
		diff := api.Sub(paddedData[i].Val, c.T0[i].Val)
		api.AssertIsEqual(api.Mul(diff, isT0), 0)
	}

	// 2. Verify InternalBytes
	// We need to check paddedData[T0Len ... T0Len+256] == InternalBytes.
	// We shift paddedData left by T0Len so InternalBytes aligns to index 0.
	shifted1 := shiftLeft(api, paddedVals, c.T0Len, T0MaxSize)

	for i := 0; i < InternalBytesSize; i++ {
		api.AssertIsEqual(shifted1[i], c.InternalBytes[i].Val)
	}

	// 3. Verify T1
	// After InternalBytes (256 bytes), T1 should follow.
	// shifted1[256 ... 256+T1Len] == T1[0 ... T1Len]
	shifted1Sliced := shifted1[InternalBytesSize:] // Slice off InternalBytes

	for i := 0; i < T1MaxSize; i++ {
		// Check if i < T1Len
		cmp := api.Cmp(c.T1Len, i)
		isT1 := api.IsZero(api.Sub(cmp, 1)) // 1 if T1Len > i, else 0

		diff := api.Sub(shifted1Sliced[i], c.T1[i].Val)
		api.AssertIsEqual(api.Mul(diff, isT1), 0)
	}

	// 4. Verify Padding Start (0x80)
	// The byte immediately after T1 must be 0x80.
	// Shift shifted1Sliced left by T1Len.
	shifted2 := shiftLeft(api, shifted1Sliced, c.T1Len, T1MaxSize)
	api.AssertIsEqual(shifted2[0], 0x80)

	return paddedData, numBlocks, nil
}

// shiftLeft shifts the data slice left by 'shift' amount.
// It uses a barrel shifter approach for O(N log MaxShift) constraints.
func shiftLeft(api frontend.API, data []frontend.Variable, shift frontend.Variable, maxShift int) []frontend.Variable {
	// Decompose shift into bits
	nbBits := bits.Len(uint(maxShift))
	shiftBits := api.ToBinary(shift, nbBits)

	current := make([]frontend.Variable, len(data))
	copy(current, data)

	// Iterate through bits (Little Endian from ToBinary)
	for i, bit := range shiftBits {
		shiftAmt := 1 << i
		shifted := make([]frontend.Variable, len(current))

		// Create the shifted version for this bit
		for j := 0; j < len(current); j++ {
			if j+shiftAmt < len(current) {
				shifted[j] = current[j+shiftAmt]
			} else {
				shifted[j] = 0 // Padding with 0
			}
		}

		// Select between current and shifted based on the bit
		for j := 0; j < len(current); j++ {
			current[j] = api.Select(bit, shifted[j], current[j])
		}
	}
	return current
}

// GenPaddedDataHint is the actual Go function for the hint.
// It constructs the full padded data for SHA256.
// Register this function with solver.RegisterHint(circuit.HintGenPaddedData, circuit.GenPaddedDataHint)
func GenPaddedDataHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	// Inputs: [T0Len, T1Len, T0(2048), Internal(256), T1(1024)]
	t0Len := inputs[0].Int64()
	t1Len := inputs[1].Int64()

	// Offsets
	offsetT0 := 2
	offsetInternal := offsetT0 + T0MaxSize
	offsetT1 := offsetInternal + InternalBytesSize

	// Construct data
	var data []byte

	// T0
	for i := int64(0); i < t0Len; i++ {
		data = append(data, byte(inputs[offsetT0+int(i)].Uint64()))
	}

	// InternalBytes
	for i := 0; i < InternalBytesSize; i++ {
		data = append(data, byte(inputs[offsetInternal+i].Uint64()))
	}

	// T1
	for i := int64(0); i < t1Len; i++ {
		data = append(data, byte(inputs[offsetT1+int(i)].Uint64()))
	}

	// SHA256 Padding
	// 1. Append 0x80
	data = append(data, 0x80)

	// 2. Append 0x00 until length % 64 == 56
	for (len(data) % 64) != 56 {
		data = append(data, 0x00)
	}

	// 3. Append length in bits (big-endian uint64)
	// Original length in bytes = t0Len + 256 + t1Len
	originalLen := uint64(t0Len + InternalBytesSize + t1Len)
	bitLen := originalLen * 8
	lenBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		lenBytes[i] = byte(bitLen >> (56 - 8*i))
	}
	data = append(data, lenBytes...)

	// Calculate number of blocks
	numBlocks := uint64(len(data) / 64)

	// Set outputs
	// Output[0] = numBlocks
	outputs[0].SetUint64(numBlocks)

	// Output[1:] = data
	for i := 0; i < len(outputs)-1; i++ {
		if i < len(data) {
			outputs[i+1].SetUint64(uint64(data[i]))
		} else {
			outputs[i+1].SetUint64(0)
		}
	}

	return nil
}

func init() {
	solver.RegisterHint(GenPaddedDataHint)
}

// computeSHA256 computes SHA256 on pre-padded blocks
func computeSHA256(api frontend.API, data []uints.U8, numBlocks frontend.Variable) ([]uints.U8, error) {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, err
	}

	// Initial SHA256 state
	h := []uints.U32{
		uints.NewU32(0x6a09e667), uints.NewU32(0xbb67ae85),
		uints.NewU32(0x3c6ef372), uints.NewU32(0xa54ff53a),
		uints.NewU32(0x510e527f), uints.NewU32(0x9b05688c),
		uints.NewU32(0x1f83d9ab), uints.NewU32(0x5be0cd19),
	}

	// Process each 64-byte block
	for i := 0; i < len(data); i += 64 {
		blockIndex := i / 64

		// Determine if we should process this block
		// process if blockIndex < numBlocks
		// api.Cmp(blockIndex, numBlocks) returns -1 if blockIndex < numBlocks
		cmp := api.Cmp(blockIndex, numBlocks)
		shouldProcess := api.IsZero(api.Add(cmp, 1)) // -1 + 1 = 0

		block := data[i : i+64]

		// 1. Prepare message schedule W
		w := make([]uints.U32, 64)
		for j := 0; j < 16; j++ {
			w[j] = uapi.PackMSB(block[j*4], block[j*4+1], block[j*4+2], block[j*4+3])
		}
		for j := 16; j < 64; j++ {
			w15 := w[j-15]
			s0 := uapi.Xor(uapi.Lrot(w15, -7), uapi.Lrot(w15, -18), uapi.Rshift(w15, 3))
			w2 := w[j-2]
			s1 := uapi.Xor(uapi.Lrot(w2, -17), uapi.Lrot(w2, -19), uapi.Rshift(w2, 10))
			w[j] = uapi.Add(w[j-16], s0, w[j-7], s1)
		}

		// 2. Compression
		a, b, c, d, e, f, g, h_curr := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
		k := sha256Constants(uapi)

		for j := 0; j < 64; j++ {
			s1 := uapi.Xor(uapi.Lrot(e, -6), uapi.Lrot(e, -11), uapi.Lrot(e, -25))
			ch := uapi.Xor(uapi.And(e, f), uapi.And(uapi.Not(e), g))
			temp1 := uapi.Add(h_curr, s1, ch, k[j], w[j])
			s0 := uapi.Xor(uapi.Lrot(a, -2), uapi.Lrot(a, -13), uapi.Lrot(a, -22))
			maj := uapi.Xor(uapi.And(a, b), uapi.And(a, c), uapi.And(b, c))
			temp2 := uapi.Add(s0, maj)

			h_curr = g
			g = f
			f = e
			e = uapi.Add(d, temp1)
			d = c
			c = b
			b = a
			a = uapi.Add(temp1, temp2)
		}

		// Update hash state conditionally
		h[0] = SelectU32(uapi, shouldProcess, uapi.Add(h[0], a), h[0])
		h[1] = SelectU32(uapi, shouldProcess, uapi.Add(h[1], b), h[1])
		h[2] = SelectU32(uapi, shouldProcess, uapi.Add(h[2], c), h[2])
		h[3] = SelectU32(uapi, shouldProcess, uapi.Add(h[3], d), h[3])
		h[4] = SelectU32(uapi, shouldProcess, uapi.Add(h[4], e), h[4])
		h[5] = SelectU32(uapi, shouldProcess, uapi.Add(h[5], f), h[5])
		h[6] = SelectU32(uapi, shouldProcess, uapi.Add(h[6], g), h[6])
		h[7] = SelectU32(uapi, shouldProcess, uapi.Add(h[7], h_curr), h[7])
	}

	// Convert h to bytes
	digest := make([]uints.U8, 32)
	for i := 0; i < 8; i++ {
		b := uapi.UnpackMSB(h[i])
		for j := 0; j < 4; j++ {
			digest[i*4+j] = b[j]
		}
	}
	return digest, nil
}

func sha256Constants(uapi *uints.BinaryField[uints.U32]) []uints.U32 {
	vals := []uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}
	res := make([]uints.U32, 64)
	for i, v := range vals {
		res[i] = uints.NewU32(v)
	}
	return res
}

// hashBytesToElement converts 32 bytes (SHA256 output) to an emulated P256Fr field element
func hashBytesToElement(api frontend.API, scalarApi *emulated.Field[emulated.P256Fr], hashBytes []uints.U8) *emulated.Element[emulated.P256Fr] {
	// Convert each byte to 8 bits, MSB first (big-endian)
	var bits []frontend.Variable

	for i := 0; i < 32; i++ {
		byteVal := hashBytes[i].Val
		byteBits := api.ToBinary(byteVal, 8)
		// ToBinary returns LSB first, reverse for big-endian
		for j := 7; j >= 0; j-- {
			bits = append(bits, byteBits[j])
		}
	}

	// FromBits expects LSB first, reverse the entire array
	reversedBits := make([]frontend.Variable, 256)
	for i := 0; i < 256; i++ {
		reversedBits[i] = bits[255-i]
	}

	return scalarApi.FromBits(reversedBits...)
}

// SelectU32 selects between a and b based on selector.
// If selector is 1, returns a. If selector is 0, returns b.
func SelectU32(uapi *uints.BinaryField[uints.U32], selector frontend.Variable, a, b uints.U32) uints.U32 {
	var res uints.U32
	for i := 0; i < 4; i++ {
		res[i] = uapi.Select(selector, a[i], b[i])
	}
	return res
}
