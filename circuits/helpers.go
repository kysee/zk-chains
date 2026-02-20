package circuits

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test/unsafekzg"
)

const (
	MaxMerkleDepth = 4
)

func LoadOrSetupCircuit_Groth16(outDir string, c frontend.Circuit) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var err error

	t := reflect.TypeOf(c)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	circuitName := t.Name()

	ccsPath := filepath.Join(outDir, fmt.Sprintf("%s_groth16.ccs", circuitName))
	pkPath := filepath.Join(outDir, fmt.Sprintf("%s_groth16.pk", circuitName))
	vkPath := filepath.Join(outDir, fmt.Sprintf("%s_groth16.vk", circuitName))

	// Step 1: Circuit compile
	fCcs, err := os.Open(ccsPath)
	defer fCcs.Close()

	if err != nil {
		fmt.Println("[groth16] Compiling", circuitName, "...")
		// Compile with BN254 scalar field (for emulated BLS12-381)
		ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
		if err != nil {
			panic(err)
		}
		fCcs, err = os.Create(ccsPath)
		_, _ = ccs.WriteTo(fCcs)
	} else {
		fmt.Println("[groth16] Loading", circuitName, "...")

		ccs = groth16.NewCS(ecc.BN254)
		_, err = ccs.ReadFrom(fCcs)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("[groth16] Number of constraints: %d\n", ccs.GetNbConstraints())
	fmt.Printf("[groth16] Number of public inputs: %d\n", ccs.GetNbPublicVariables())
	fmt.Printf("[groth16] Number of secret inputs: %d\n", ccs.GetNbSecretVariables())
	fmt.Printf("[groth16] Circuit commitments: %v\n", ccs.GetCommitments().CommitmentIndexes())

	// Step 2: Setup (generate proving and verifying keys)
	fpk, err0 := os.Open(pkPath)
	defer fpk.Close()
	fvk, err1 := os.Open(vkPath)
	defer fvk.Close()

	if err0 != nil || err1 != nil {
		fmt.Println("[groth16] Generating proving and verifying keys...")

		tm0 := time.Now()
		pk, vk, err = groth16.Setup(ccs)
		fmt.Printf("Setup time: %v\n", time.Since(tm0))

		if err != nil {
			panic(err)
		}
		fpk, _ = os.Create(pkPath)
		_, _ = pk.WriteTo(fpk)

		fvk, _ = os.Create(vkPath)
		_, _ = vk.WriteTo(fvk)
	} else {
		fmt.Println("[groth16] Loading proving and verifying keys...")
		pk = groth16.NewProvingKey(ecc.BN254)
		vk = groth16.NewVerifyingKey(ecc.BN254)

		tm0 := time.Now()
		if _, err := pk.ReadFrom(fpk); err != nil {
			panic(err)
		}
		fmt.Printf("[groth16] Load ProvingKey time: %v\n", time.Since(tm0))
		tm0 = time.Now()
		if _, err := vk.ReadFrom(fvk); err != nil {
			panic(err)
		}
		fmt.Printf("[groth16] Load VerifyingKey time: %v\n", time.Since(tm0))
	}
	fmt.Println("[groth16] ✓ Setup complete")
	return ccs, pk, vk
}

func LoadOrSetupCircuit_Plonk(outDir string, c frontend.Circuit) (constraint.ConstraintSystem, plonk.ProvingKey, plonk.VerifyingKey) {
	var ccs constraint.ConstraintSystem
	var pk plonk.ProvingKey
	var vk plonk.VerifyingKey
	var err error

	t := reflect.TypeOf(c)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	circuitName := t.Name()

	ccsPath := filepath.Join(outDir, fmt.Sprintf("%s_plonk.ccs", circuitName))
	pkPath := filepath.Join(outDir, fmt.Sprintf("%s_plonk.pk", circuitName))
	vkPath := filepath.Join(outDir, fmt.Sprintf("%s_plonk.vk", circuitName))

	// Step 1: Circuit compile
	fCcs, err := os.Open(ccsPath)
	defer fCcs.Close()

	if err != nil {
		fmt.Println("[plonk] Compiling", circuitName, "...")
		// Compile with BN254 scalar field (for emulated BLS12-381)
		ccs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, c)
		if err != nil {
			panic(err)
		}
		fCcs, err = os.Create(ccsPath)
		_, _ = ccs.WriteTo(fCcs)
	} else {
		fmt.Println("[plonk] Loading", circuitName, "...")

		ccs = groth16.NewCS(ecc.BN254)
		_, err = ccs.ReadFrom(fCcs)
		if err != nil {
			panic(err)
		}
	}

	fmt.Printf("[plonk] Number of constraints: %d\n", ccs.GetNbConstraints())
	fmt.Printf("[plonk] Number of public inputs: %d\n", ccs.GetNbPublicVariables())
	fmt.Printf("[plonk] Number of secret inputs: %d\n", ccs.GetNbSecretVariables())
	fmt.Printf("[plonk] Circuit commitments: %v\n", ccs.GetCommitments().CommitmentIndexes())

	// Step 2: Setup (generate proving and verifying keys)
	fpk, err0 := os.Open(pkPath)
	defer fpk.Close()
	fvk, err1 := os.Open(vkPath)
	defer fvk.Close()

	if err0 != nil || err1 != nil {

		fmt.Println("[plonk] Generating SRS (this may take a while)...")
		srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
		if err != nil {
			panic(err)
		}
		fmt.Println("[plonk] Generating proving and verifying keys...")
		pk, vk, err = plonk.Setup(ccs, srs, srsLagrange)
		if err != nil {
			panic(err)
		}
		fpk, _ = os.Create(pkPath)
		_, _ = pk.WriteTo(fpk)

		fvk, _ = os.Create(vkPath)
		_, _ = vk.WriteTo(fvk)
	} else {
		fmt.Println("[plonk] Loading proving and verifying keys...")
		pk = plonk.NewProvingKey(ecc.BN254)
		vk = plonk.NewVerifyingKey(ecc.BN254)
		if _, err := pk.ReadFrom(fpk); err != nil {
			panic(err)
		}
		if _, err := vk.ReadFrom(fvk); err != nil {
			panic(err)
		}
	}
	fmt.Println("[plonk] ✓ Setup complete")
	return ccs, pk, vk
}

func ToU8Array32(data []byte) [32]uints.U8 {
	var res [32]uints.U8
	for i, b := range data {
		if i >= 32 {
			break
		}
		res[i] = uints.NewU8(b)
	}
	for i := len(data); i < 32; i++ {
		res[i] = uints.NewU8(0)
	}
	return res
}

// shiftLeft shifts the data slice left by 'shift' amount.
// It uses a barrel shifter approach for O(N log MaxShift) constraints.
func ShiftLeft(api frontend.API, data []frontend.Variable, shift frontend.Variable, maxShift int) []frontend.Variable {
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

// computeSHA256 computes SHA256 on pre-padded blocks
func ComputeSHA256(api frontend.API, data []uints.U8, numBlocks frontend.Variable) ([]uints.U8, error) {
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

// HashBytesToElement converts 32 bytes (SHA256 output) to an emulated P256Fr field element
func HashBytesToElement(api frontend.API, scalarApi *emulated.Field[emulated.P256Fr], hashBytes []uints.U8) *emulated.Element[emulated.P256Fr] {
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
func SelectU32(api *uints.BinaryField[uints.U32], selector frontend.Variable, a, b uints.U32) uints.U32 {
	var res uints.U32
	for i := 0; i < 4; i++ {
		res[i] = api.Select(selector, a[i], b[i])
	}
	return res
}

// hashPair computes the SHA256 hash of two 32-byte arrays (left and right) and returns the resulting 32-byte hash.
func sha256Pair(api frontend.API, left, right [32]uints.U8) [32]uints.U8 {
	// Create a new SHA256 hasher
	hasher, err := sha2.New(api)
	if err != nil {
		panic(err)
	}

	// Write 64 bytes total (left || right)
	hasher.Write(left[:])
	hasher.Write(right[:])

	// Compute SHA256 hash
	hashResult := hasher.Sum()
	return [32]uints.U8(hashResult)
}

// VerifyMerkleProof verifies a SHA256-based Merkle proof
// Parameters:
//   - proof: sibling hashes along the path (MaxMerkleDepth elements)
//   - leafIdx: index of the leaf in the tree (determines left/right direction at each level)
//   - leaf: the leaf hash (32 bytes)
//   - root: the expected Merkle root (32 bytes)
func VerifyMerkleProof(api frontend.API, proof [MaxMerkleDepth][32]uints.U8, leafIdx frontend.Variable, leafHash, root []uints.U8) {
	indexBits := api.ToBinary(leafIdx, MaxMerkleDepth)

	current := [32]uints.U8(leafHash)

	for i := 0; i < MaxMerkleDepth; i++ {
		sibling := proof[i]

		var left, right [32]uints.U8
		for j := 0; j < 32; j++ {
			left[j] = uints.U8{Val: api.Select(indexBits[i], sibling[j].Val, current[j].Val)}
			right[j] = uints.U8{Val: api.Select(indexBits[i], current[j].Val, sibling[j].Val)}
		}

		current = sha256Pair(api, left, right)
	}

	for i := 0; i < 32; i++ {
		api.AssertIsEqual(current[i].Val, root[i].Val)
	}
}

// ConvertToU8Array32 converts [2]frontend.Variable (high, low 128-bit each) to [32]uints.U8
// input[0] = high 128 bits (becomes bytes 0-15)
// input[1] = low 128 bits (becomes bytes 16-31)
func ConvertToU8Array32(api frontend.API, input [2]frontend.Variable) [32]uints.U8 {
	var result [32]uints.U8

	// Decompose high 128 bits -> bytes 0-15
	highBits := api.ToBinary(input[0], 128) // LSB first

	// Decompose low 128 bits -> bytes 16-31
	lowBits := api.ToBinary(input[1], 128) // LSB first

	// Convert high bits to bytes (big-endian: byte 0 is MSB)
	for byteIdx := 0; byteIdx < 16; byteIdx++ {
		// byte 0 = bits[127:120], byte 1 = bits[119:112], ..., byte 15 = bits[7:0]
		// In LSB-first array: byte 0 uses bits[120..127], byte 15 uses bits[0..7]
		byteVal := frontend.Variable(0)
		for bitPos := 0; bitPos < 8; bitPos++ {
			bitIdx := (15-byteIdx)*8 + bitPos
			// bitPos 0 is LSB of byte, contributes 2^0
			// bitPos 7 is MSB of byte, contributes 2^7
			coeff := int64(1 << bitPos)
			byteVal = api.Add(byteVal, api.Mul(highBits[bitIdx], coeff))
		}
		result[byteIdx] = uints.U8{Val: byteVal}
	}

	// Convert low bits to bytes (big-endian)
	for byteIdx := 0; byteIdx < 16; byteIdx++ {
		byteVal := frontend.Variable(0)
		for bitPos := 0; bitPos < 8; bitPos++ {
			bitIdx := (15-byteIdx)*8 + bitPos
			coeff := int64(1 << bitPos)
			byteVal = api.Add(byteVal, api.Mul(lowBits[bitIdx], coeff))
		}
		result[16+byteIdx] = uints.U8{Val: byteVal}
	}

	return result
}

func MerkleVerify(idx int, leafHash []byte, proofHashes [][]byte, root []byte) bool {
	index := uint64(idx) + (1 << uint(len(proofHashes)))
	computed := [32]byte(leafHash)

	for _, proofHash := range proofHashes {
		if index%2 == 0 {
			computed = sha256.Sum256(append(computed[:], proofHash[:]...))
		} else {
			computed = sha256.Sum256(append(proofHash[:], computed[:]...))
		}
		index >>= 1
	}
	return bytes.Equal(computed[:], root)
}

// ReconstructTargetHFromWitnessBN254 reconstructs 4 x 64-bit limbs from 32 U8 witness elements (BN254 version)
func ReconstructTargetHFromWitnessBN254(api frontend.API, publicInputs []emulated.Element[sw_bn254.ScalarField]) [4]frontend.Variable {
	var result [4]frontend.Variable

	for limbIdx := 0; limbIdx < 4; limbIdx++ {
		limbValue := frontend.Variable(0)
		for byteIdx := 0; byteIdx < 8; byteIdx++ {
			globalIdx := limbIdx*8 + byteIdx
			byteVal := publicInputs[globalIdx].Limbs[0]

			shift := new(big.Int).Exp(big.NewInt(256), big.NewInt(int64(7-byteIdx)), nil)
			shifted := api.Mul(byteVal, shift)
			limbValue = api.Add(limbValue, shifted)
		}
		result[limbIdx] = limbValue
	}

	return result
}
