package circuit

import (
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"math/big"
	"math/bits"
)

// Circuit size constants
const (
	TxMaxSize         = 3072 // Maximum bytes for Transaction
	TxLimbSize        = 384  // 3072 / 8 = 384 limbs (uint64)
	InternalBytesSize = 256  // Fixed size for InternalBytes

	// SHA256 constants
	BlockSize = 64
	// Max total size = 3072 bytes
	// Padding overhead = 1 byte (0x80) + 8 bytes (length) = 9 bytes
	// Max padded size = 3081 bytes -> ceil(3081/64) = 49 blocks
	MaxBlocks = 49
)

// BPrNTxProofCircuit verifies P256 ECDSA signature on transaction data
// and proves that InternalBytes is contained within the original transaction.
//
// Architecture:
// - Prover provides TxLimbs (8-byte chunks) as secret input
// - Circuit computes SHA256(TxLimbs -> Bytes)
// - Verifies ECDSA P256 signature on the computed hash
// - Verifies InternalBytes is a substring of TxLimbs (converted to bytes) at InternalOffset
//
// Uses PLONK + BN254
type BPrNTxProofCircuit struct {
	// Secret inputs
	TxLimbs        [TxLimbSize]frontend.Variable // Transaction data in 8-byte limbs
	TxLen          frontend.Variable             // Actual length of TxBytes (in bytes)
	InternalOffset frontend.Variable             // Offset where InternalBytes starts in TxBytes

	// P256 Public Key (X, Y coordinates)
	Pub ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]

	// P256 Signature (R, S values)
	Sig ecdsa.Signature[emulated.P256Fr]

	// Public input
	InternalBytes [InternalBytesSize]uints.U8 `gnark:",public"` // Data proven to be in transaction
}

func (c *BPrNTxProofCircuit) Define(api frontend.API) error {
	// 1. Validate lengths
	api.AssertIsLessOrEqual(c.TxLen, TxMaxSize)

	// 2. Validate InternalOffset
	// InternalOffset + InternalBytesSize <= TxLen
	endOffset := api.Add(c.InternalOffset, InternalBytesSize)
	api.AssertIsLessOrEqual(endOffset, c.TxLen)

	// 3. Construct the padded data for SHA256 using a Hint
	paddedData, numBlocks, err := c.constructPaddedDataHint(api)
	if err != nil {
		return err
	}

	// 4. Compute SHA256 on the padded blocks
	computedHash, err := computeSHA256(api, paddedData, numBlocks)
	if err != nil {
		return err
	}

	// 5. Convert computed hash to emulated.Element for P256Fr (scalar field)
	scalarApi, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return err
	}
	msgHash := hashBytesToElement(api, scalarApi, computedHash)

	// 6. Verify ECDSA P256 signature
	// This implicitly verifies that the paddedData from the hint corresponds to the TxLimbs
	// for which the prover has a valid signature.
	c.Pub.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), msgHash, &c.Sig)

	return nil
}

func (c *BPrNTxProofCircuit) constructPaddedDataHint(api frontend.API) ([]uints.U8, frontend.Variable, error) {
	// Prepare inputs for the hint
	hintInputs := []frontend.Variable{c.TxLen}
	for _, l := range c.TxLimbs {
		hintInputs = append(hintInputs, l)
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
	// numBlocks = ceil((TxLen + 9) / 64)
	// Formula: numBlocks = (TxLen + 8 + 64) / 64 = (TxLen + 72) / 64 (integer division)
	numerator := api.Add(c.TxLen, 72)

	// Check 1: numerator >= numBlocks * 64
	product := api.Mul(numBlocks, 64)
	api.AssertIsLessOrEqual(product, numerator)

	// Check 2: numerator < (numBlocks + 1) * 64 => numerator - product < 64
	remainder := api.Sub(numerator, product)
	api.AssertIsLessOrEqual(remainder, 63)

	paddedData := make([]uints.U8, len(paddedVars))
	for i := 0; i < len(paddedVars); i++ {
		// We don't explicitly enforce width here to save constraints.
		// Invalid values (>= 256) will cause failures in SHA256 computation or signature verification.
		paddedData[i] = uints.U8{Val: paddedVars[i]}
	}

	// --- Verification Logic ---

	// 1. Verify InternalBytes inclusion
	// We need to check paddedData[InternalOffset : InternalOffset + InternalBytesSize] == InternalBytes
	// Shift paddedData left by InternalOffset so InternalBytes aligns to index 0
	shiftedInternal := shiftLeft(api, paddedVars, c.InternalOffset, len(paddedVars))

	for i := 0; i < InternalBytesSize; i++ {
		api.AssertIsEqual(shiftedInternal[i], c.InternalBytes[i].Val)
	}

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
func GenPaddedDataHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	// Inputs: [TxLen, TxLimbs...]
	txLen := inputs[0].Int64()

	// Offsets
	offsetTx := 1

	// Construct data
	var data []byte

	// TxLimbs (uint64) -> bytes (Little Endian)
	// We need to extract exactly txLen bytes.
	// We iterate through limbs and extract bytes.

	currentLen := int64(0)
	for i := 0; currentLen < txLen; i++ {
		limb := inputs[offsetTx+i].Uint64()
		for j := 0; j < 8; j++ {
			if currentLen >= txLen {
				break
			}
			data = append(data, byte(limb>>(j*8)))
			currentLen++
		}
	}

	// SHA256 Padding
	// 1. Append 0x80
	data = append(data, 0x80)

	// 2. Append 0x00 until length % 64 == 56
	for (len(data) % 64) != 56 {
		data = append(data, 0x00)
	}

	// 3. Append length in bits (big-endian uint64)
	// Original length in bytes = txLen
	originalLen := uint64(txLen)
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

	// Precompute constants
	k := sha256Constants(uapi)

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
