package circuit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// DOMAIN is the hardcoded domain for Ethereum mainnet Fulu fork
// Domain = 0x07000000f52c15272cff99835cd05aa522af469210b5b2c8807e372b6b9ca539
// Computed as: domain_type || fork_data_root[:28]
// where fork_data_root = hash_tree_root(ForkData(fork_version, genesis_validators_root))
//
// Parameters used:
// - domainType: 0x07000000 (DOMAIN_SYNC_COMMITTEE)
// - forkVersion: 0x90000075 (Fulu fork)
// - genesisValidatorsRoot: 0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078
var DOMAIN = [32]uint8{
	0x07, 0x00, 0x00, 0x00, 0xf5, 0x2c, 0x15, 0x27,
	0x2c, 0xff, 0x99, 0x83, 0x5c, 0xd0, 0x5a, 0xa5,
	0x22, 0xaf, 0x46, 0x92, 0x10, 0xb5, 0xb2, 0xc8,
	0x80, 0x7e, 0x37, 0x2b, 0x6b, 0x9c, 0xa5, 0x39,
}

// Eth2ScUpdateCircuit verifies Ethereum beacon chain sync committee BLS signatures
//
// This circuit performs the complete verification flow:
// 1. Computes blockRoot from BeaconBlockHeader fields
// 2. Computes signingRoot = hash(blockRoot, domain)
// 3. Computes signingRootG2 = hash-to-curve(signingRoot) IN-CIRCUIT
// 4. Verifies sync committee pubkey hash(sha2)
// 5. Aggregates public keys based on sync committee bits
// 6. Verifies BLS signature: e(aggregatedPubKey, H(signingRoot)) == e(G1, signature)
// 7. Verifies next_sync_committee is included in StateRoot via SSZ Merkle proof
//
// NOTE: For complete verification of next_sync_committee, the following checks must be performed OUTSIDE the circuit:
// - Slot(Period) validation
// - Verification that the number of validators who signed the AggregatedSig exceeds 2/3 of the total
type Eth2ScUpdateCircuit struct {
	// BeaconBlockHeader fields (private inputs)
	Slot          frontend.Variable // uint64
	ProposerIndex frontend.Variable // uint64
	ParentRoot    [32]uints.U8      // bytes32
	StateRoot     [32]uints.U8      // bytes32
	BodyRoot      [32]uints.U8      // bytes32

	// Sync committee data (private inputs)
	ScPubKeys     [512]sw_bls12381.G1Affine // 512 sync committee public keys
	ScBits        [512]frontend.Variable    // Bit array indicating which validators signed (0 or 1)
	AggregatedSig sw_bls12381.G2Affine      // Aggregated signature

	// Next sync committee Merkle proof data
	NextScBranch [6][32]uints.U8 // Merkle branch proving inclusion in StateRoot

	// Public inputs - verified by the circuit
	ScPubKeysHash [32]uints.U8 `gnark:",public"` // SHA2 hash to sync committee pubkeys
	NextScRoot    [32]uints.U8 `gnark:",public"` // SSZ root of next_sync_committee
}

// Define implements the circuit constraints
func (c *Eth2ScUpdateCircuit) Define(api frontend.API) error {
	// Step 1: Verify sync committee pubkeys hash using SHA2
	err := c.verifyScPubKeysHash(api)
	if err != nil {
		return fmt.Errorf("sync committee pubkeys hash verification failed: %w", err)
	}

	// Step 2: Aggregate public keys based on sync committee bits
	aggregatedPubKey, err := c.aggregatePubKeys(api)
	if err != nil {
		return fmt.Errorf("public key aggregation failed: %w", err)
	}

	// Step 3: Compute blockRoot from BeaconBlockHeader
	blockRoot := c.computeBlockRoot(api)

	// Step 4: Compute signingRoot = hash(blockRoot, domain)
	signingRoot := c.computeSigningRoot(api, blockRoot)

	// Step 5: Compute signingRootG2 = hash-to-curve(signingRoot) IN-CIRCUIT
	signingRootG2, err := c.hashToG2InCircuit(api, signingRoot)
	if err != nil {
		return fmt.Errorf("hash-to-curve failed: %w", err)
	}

	// Step 6: Verify BLS signature using the aggregated public key
	// If the BeaconBlockHeader fields are incorrect, the blockRoot will be wrong,
	// leading to wrong signingRoot and signingRootG2, which will fail signature verification
	err = c.verifyBLSSignature(api, aggregatedPubKey, signingRootG2)
	if err != nil {
		return fmt.Errorf("BLS signature verification failed: %w", err)
	}

	// Step 7: Verify next_sync_committee is included in StateRoot via SSZ Merkle proof
	err = c.verifyNextSyncCommitteeMerkleProof(api)
	if err != nil {
		return fmt.Errorf("next_sync_committee Merkle proof verification failed: %w", err)
	}

	return nil
}

// computeBlockRoot computes the SSZ hash_tree_root of the beacon block header
// This reuses the same logic as BlockRootHasher
func (c *Eth2ScUpdateCircuit) computeBlockRoot(api frontend.API) [32]uints.U8 {
	// Convert each field to a 32-byte chunk
	slotChunk := c.serializeUint64ToChunk(api, c.Slot)
	proposerChunk := c.serializeUint64ToChunk(api, c.ProposerIndex)
	zeroChunk := c.zeroChunk()

	// Build Merkle tree (5 leaves + 3 zeros = 8 leaves total)
	// Layer 1: Hash adjacent pairs
	h01 := c.hashPair(api, slotChunk, proposerChunk)
	h23 := c.hashPair(api, c.ParentRoot, c.StateRoot)
	h45 := c.hashPair(api, c.BodyRoot, zeroChunk)
	h67 := c.hashPair(api, zeroChunk, zeroChunk)

	// Layer 2: Hash pairs from layer 1
	h0123 := c.hashPair(api, h01, h23)
	h4567 := c.hashPair(api, h45, h67)

	// Layer 3 (root): Final hash
	root := c.hashPair(api, h0123, h4567)

	return root
}

// computeSigningRoot computes the signing root used in BLS signature verification
// signingRoot = hash_tree_root(SigningData(blockRoot, domain))
//
// SigningData structure:
//
//	object_root: blockRoot (32 bytes)
//	domain: domain (32 bytes)
//
// Note: domain is hardcoded as a constant for Ethereum mainnet Fulu fork
func (c *Eth2ScUpdateCircuit) computeSigningRoot(api frontend.API, blockRoot [32]uints.U8) [32]uints.U8 {
	// Convert DOMAIN bytes to []uints.U8
	domain := uints.NewU8Array(DOMAIN[:])

	// Compute signingRoot = hash(blockRoot || domain)
	signingRoot := c.hashPair(api, blockRoot, [32]uints.U8(domain))
	return signingRoot
}

// hashToG2InCircuit performs RFC 9380 hash_to_G2 for BLS12-381 G2
// using expand_message_xmd(SHA-256) and ETH2 DST.
func (c *Eth2ScUpdateCircuit) hashToG2InCircuit(
	api frontend.API,
	signingRoot [32]uints.U8,
) (*sw_bls12381.G2Affine, error) {

	// 1) G2 helper
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return nil, fmt.Errorf("new G2: %w", err)
	}

	// 2) hash_to_field(msg, 2) in Fp2
	u, err := c.hashToFieldBLS12381Fp2(api, signingRoot)
	if err != nil {
		return nil, fmt.Errorf("hashToFieldFp2: %w", err)
	}

	// 3) map_to_curve2 for each u[i]
	//    주의: MapToG2 인자는 *fields_bls12381.E2 (포인터)
	Q0, err := g2.MapToG2(&u[0])
	if err != nil {
		return nil, fmt.Errorf("MapToG2(u[0]): %w", err)
	}
	Q1, err := g2.MapToG2(&u[1])
	if err != nil {
		return nil, fmt.Errorf("MapToG2(u[1]): %w", err)
	}

	// 4) R = Q0 + Q1   (group law on G2)
	// G2에는 Add가 없고 AddUnified만 있습니다.
	R := g2.AddUnified(Q0, Q1)

	return R, nil
}

// hashToFieldBLS12381Fp2 implements RFC 9380 hash_to_field for BLS12-381 Fp2.
//
// It takes `msg = signingRoot` (32 bytes) and DST
// "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
// and returns two Fp2 elements u[0], u[1] such that:
//
// uniform_bytes = expand_message_xmd(msg, DST, 256)
// tv[i][j] = uniform_bytes[L*(j + i*m) : L*(j + i*m) + L]   (i=0..1, j=0..1)
// u[i].A0 = OS2IP(tv[i][0]) mod p
// u[i].A1 = OS2IP(tv[i][1]) mod p
func (c *Eth2ScUpdateCircuit) hashToFieldBLS12381Fp2(
	api frontend.API,
	signingRoot [32]uints.U8,
) ([2]fields_bls12381.E2, error) {

	const (
		m     = 2 // extension degree (Fp2)
		L     = 64
		count = 2
	)

	// 1) convert signingRoot -> []uints.U8 (message)
	msg := signingRoot

	// 2) DST for Ethereum BLS signatures
	dstBytes := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
	dst := make([]uints.U8, len(dstBytes))
	for i, b := range dstBytes {
		dst[i] = uints.NewU8(b)
	}

	// pre-allocate helpers for OS2IP reduction
	fp, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return [2]fields_bls12381.E2{}, fmt.Errorf("new emulated field: %w", err)
	}
	byteAPI, err := uints.NewBytes(api)
	if err != nil {
		return [2]fields_bls12381.E2{}, fmt.Errorf("new bytes api: %w", err)
	}

	// 3) expand_message_xmd(SHA-256)
	lenInBytes := count * m * L // 256
	uniform, err := expandMessageXMD_SHA256(api, msg[:], dst, lenInBytes)
	if err != nil {
		return [2]fields_bls12381.E2{}, fmt.Errorf("expand_message_xmd: %w", err)
	}
	if len(uniform) != lenInBytes {
		return [2]fields_bls12381.E2{}, fmt.Errorf("uniform_bytes length mismatch")
	}

	// 4) slice uniform_bytes into tv blocks and convert to Fp elements
	var out [2]fields_bls12381.E2

	for i := 0; i < count; i++ {
		// each u[i] has m (=2) coordinates: tv0 -> A0, tv1 -> A1
		for j := 0; j < m; j++ {
			offset := L * (j + i*m)
			tv := uniform[offset : offset+L] // []uints.U8 length 64

			// OS2IP(tv) mod p using Horner reduction to avoid overflow width issues
			el, err := c.bytesToBLS12381FpMod(api, fp, byteAPI, tv)
			if err != nil {
				return [2]fields_bls12381.E2{}, fmt.Errorf("hashToFieldFp2 os2ip(%d,%d): %w", i, j, err)
			}

			if j == 0 {
				out[i].A0 = *el
			} else {
				out[i].A1 = *el
			}
		}
	}

	return out, nil
}

// expandMessageXMD_SHA256 implements expand_message_xmd(msg, DST, len_in_bytes)
// from RFC 9380, with H = SHA-256 (B = 32, r_in_bytes = 64).
//
// All inputs/outputs are uints.U8 in-circuit.
func expandMessageXMD_SHA256(
	api frontend.API,
	msg []uints.U8,
	dst []uints.U8,
	lenInBytes int,
) ([]uints.U8, error) {

	const (
		B        = 32 // SHA-256 output size in bytes
		rInBytes = 64
		maxLen   = 255 * B
	)

	if lenInBytes <= 0 || lenInBytes > maxLen {
		return nil, fmt.Errorf("len_in_bytes out of range")
	}

	ell := (lenInBytes + B - 1) / B

	// DST' = DST || I2OSP(len(DST), 1)
	dstPrime := make([]uints.U8, 0, len(dst)+1)
	dstPrime = append(dstPrime, dst...)
	dstPrime = append(dstPrime, uints.NewU8(uint8(len(dst))))

	// Z_pad = I2OSP(0, r_in_bytes)
	zPad := make([]uints.U8, rInBytes)
	for i := 0; i < rInBytes; i++ {
		zPad[i] = uints.NewU8(0)
	}

	// l_i_b_str = I2OSP(len_in_bytes, 2) (big-endian)
	lIB := []uints.U8{
		uints.NewU8(uint8(lenInBytes >> 8)),
		uints.NewU8(uint8(lenInBytes & 0xff)),
	}

	// bytes gadget for XOR and such
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return nil, fmt.Errorf("NewBytes: %w", err)
	}

	// b0 = H(Z_pad || msg || l_i_b_str || 0x00 || DST')
	h0, err := sha2.New(api)
	if err != nil {
		return nil, fmt.Errorf("sha2.New(b0): %w", err)
	}
	h0.Write(zPad)
	h0.Write(msg)
	h0.Write(lIB)
	h0.Write([]uints.U8{uints.NewU8(0x00)})
	h0.Write(dstPrime)
	b0 := h0.Sum() // len 32

	// b1 = H(b0 || 0x01 || DST')
	h1, err := sha2.New(api)
	if err != nil {
		return nil, fmt.Errorf("sha2.New(b1): %w", err)
	}
	h1.Write(b0)
	h1.Write([]uints.U8{uints.NewU8(0x01)})
	h1.Write(dstPrime)
	b1 := h1.Sum() // len 32

	// uniform_bytes = b1 || b2 || ... || b_ell (truncated)
	uniform := make([]uints.U8, 0, ell*B)
	uniform = append(uniform, b1...)

	prev := b1
	for i := 2; i <= ell; i++ {
		// t = strxor(b0, prev)
		if len(b0) != len(prev) {
			return nil, fmt.Errorf("b0 and prev length mismatch")
		}
		t := make([]uints.U8, len(b0))
		for j := range b0 {
			t[j] = bapi.Xor(b0[j], prev[j])
		}

		// b_i = H(t || I2OSP(i,1) || DST')
		hi, err := sha2.New(api)
		if err != nil {
			return nil, fmt.Errorf("sha2.New(b_%d): %w", i, err)
		}
		hi.Write(t)
		hi.Write([]uints.U8{uints.NewU8(uint8(i))})
		hi.Write(dstPrime)
		bi := hi.Sum()

		uniform = append(uniform, bi...)
		prev = bi
	}

	return uniform[:lenInBytes], nil
}

// bytesToBLS12381FpMod reduces a big-endian byte slice to a BLS12-381 Fp element.
// Implements res = OS2IP(b) mod p via Horner evaluation to stay within limb width constraints.
func (c *Eth2ScUpdateCircuit) bytesToBLS12381FpMod(
	api frontend.API,
	fp *emulated.Field[sw_bls12381.BaseField],
	byteAPI *uints.Bytes,
	b []uints.U8,
) (*emulated.Element[sw_bls12381.BaseField], error) {
	radix := big.NewInt(256)
	res := fp.Zero()
	nbLimbs := len(fp.Modulus().Limbs)
	limbBuf := make([]frontend.Variable, nbLimbs)

	for _, by := range b {
		res = fp.MulConst(res, radix) // res *= 256
		for i := range limbBuf {
			limbBuf[i] = 0
		}
		limbBuf[0] = byteAPI.Value(by)
		digit := fp.NewElement(limbBuf)
		res = fp.Add(res, digit) // res += byte
	}

	// normalize; keeps width bounded even after long Horner accumulation
	res = fp.Reduce(res)
	return res, nil
}

//// verifyScPubKeysHash verifies that the commitment to sync committee pubkeys matches
//// Uses SHA2 hash for compatibility
//// Only hashes the first two limbs (Limbs[0], Limbs[1]) of each X coordinate for efficiency
//func (c *Eth2ScUpdateCircuit) verifyScPubKeysHash(api frontend.API) error {
//	// Create SHA2 hasher
//	hasher, err := sha2.New(api)
//	if err != nil {
//		return fmt.Errorf("failed to create SHA2 hasher: %w", err)
//	}
//
//	// BLS public key is 48 bytes long, so we hash the last two limbs of x coordinate.
//	// Limbs[0] is the least significant limb of x coordinate.
//	for i := 0; i < 512; i++ {
//		xbytes := c.serializeLimbTo8Bytes(api, c.ScPubKeys[i].X.Limbs[1])
//		hasher.Write(xbytes)
//		xbytes = c.serializeLimbTo8Bytes(api, c.ScPubKeys[i].X.Limbs[0])
//		hasher.Write(xbytes)
//	}
//
//	// Compute hash
//	hashResult := hasher.Sum() // Returns []uints.U8 of length 32
//
//	for i := 0; i < 32; i++ {
//		api.AssertIsEqual(hashResult[i].Val, c.ScPubKeysHash[i].Val)
//	}
//
//	return nil
//}

func (c *Eth2ScUpdateCircuit) verifyScPubKeysHash(api frontend.API) error {
	// Create SHA2 hasher
	hasher, err := sha2.New(api)
	if err != nil {
		return fmt.Errorf("failed to create SHA2 hasher: %w", err)
	}

	// BLS public key is 48 bytes long, so we hash the last two limbs of x coordinate.
	// Limbs[0] is the least significant limb of x coordinate.
	for i := 0; i < 512; i++ {
		xbytes := c.serializeLimbTo8Bytes(api, c.ScPubKeys[i].X.Limbs[1])
		hasher.Write(xbytes)
		xbytes = c.serializeLimbTo8Bytes(api, c.ScPubKeys[i].X.Limbs[0])
		hasher.Write(xbytes)
	}

	// Compute hash
	hashResult := hasher.Sum() // Returns []uints.U8 of length 32

	for i := 0; i < 32; i++ {
		api.AssertIsEqual(hashResult[i].Val, c.ScPubKeysHash[i].Val)
	}

	return nil
}

// aggregatePubKeys aggregates public keys based on sync_committee_bits
// Returns the aggregated public key for validators who participated in signing
func (c *Eth2ScUpdateCircuit) aggregatePubKeys(api frontend.API) (*sw_bls12381.G1Affine, error) {
	// Create curve for G1 operations
	curve, err := sw_emulated.New[sw_bls12381.BaseField, sw_bls12381.ScalarField](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return nil, fmt.Errorf("failed to create curve: %w", err)
	}

	// Find the first validator that participated to initialize the accumulator
	accumulator := &c.ScPubKeys[0]
	hasInitialized := c.ScBits[0]

	// Process remaining validators
	for i := 1; i < 512; i++ {
		bit := c.ScBits[i]

		// If we haven't initialized yet and this bit is set, use this as initial value
		isFirstSelected := api.And(api.IsZero(hasInitialized), bit)

		// If hasInitialized is true and bit is set, we should add
		shouldAdd := api.And(hasInitialized, bit)

		// Compute sum = accumulator + pubkey[i]
		sum := curve.Add(accumulator, &c.ScPubKeys[i])

		// If shouldAdd, use sum; otherwise keep accumulator
		tempResult := curve.Select(shouldAdd, sum, accumulator)

		// If this is the first selected key, replace with pubkey[i]; otherwise use tempResult
		accumulator = curve.Select(isFirstSelected, &c.ScPubKeys[i], tempResult)

		// Update hasInitialized flag
		hasInitialized = api.Or(hasInitialized, bit)
	}

	// Ensure at least one validator participated
	api.AssertIsEqual(hasInitialized, 1)

	return accumulator, nil
}

// verifyBLSSignature verifies the BLS signature using pairing check
// Verifies: e(pubkey, H(msg)) == e(G1, signature)
// Or equivalently: e(pubkey, H(msg)) * e(-G1, signature) == 1
func (c *Eth2ScUpdateCircuit) verifyBLSSignature(api frontend.API, aggregatedPubKey *sw_bls12381.G1Affine, signingRootG2 *sw_bls12381.G2Affine) error {
	// Create pairing instance
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("failed to create pairing: %w", err)
	}

	// Verify inputs are in correct subgroups
	pairing.AssertIsOnG1(aggregatedPubKey)
	pairing.AssertIsOnG2(signingRootG2)
	pairing.AssertIsOnG2(&c.AggregatedSig)

	// Create curve for G1 operations
	curve, err := sw_emulated.New[sw_bls12381.BaseField, sw_bls12381.ScalarField](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return fmt.Errorf("failed to create curve: %w", err)
	}

	// Get G1 generator and negate it
	g1Gen := curve.Generator()
	negG1Gen := curve.Neg(g1Gen)

	// Pairing check: e(pubkey, H(msg)) * e(-G1, signature) == 1
	err = pairing.PairingCheck(
		[]*sw_bls12381.G1Affine{aggregatedPubKey, negG1Gen},
		[]*sw_bls12381.G2Affine{signingRootG2, &c.AggregatedSig},
	)
	if err != nil {
		return fmt.Errorf("pairing check failed: %w", err)
	}

	return nil
}

// verifyNextSyncCommitteeMerkleProof verifies that next_sync_committee root is included in StateRoot
// using the SSZ Merkle proof (next_sync_committee_branch).
//
// The next_sync_committee field is at generalized index 87 in the BeaconState (Fulu).
// Position 23 (0-indexed) in the BeaconState structure.
// Generalized index = 2^depth + position = 64 + 23 = 87
// Position 23 in binary: 0b10111
//
// For a Merkle branch of length 6, we verify by:
// 1. Starting with leaf = NextScRoot
// 2. For each branch node, compute parent = hash(left, right) where left/right depends on the path
// 3. Final result should equal StateRoot
func (c *Eth2ScUpdateCircuit) verifyNextSyncCommitteeMerkleProof(api frontend.API) error {
	// NextSyncCommittee generalized index in Fulu BeaconState
	// Position 23 (0-indexed) in BeaconState structure
	// Generalized index = 2^depth + position = 64 + 23 = 87
	//
	// Extract the path from position 23 = 0b10111
	// Path bits (LSB first): [1, 1, 1, 0, 1, 0]
	// This means at each level: if bit is 1, current node is on the right; if 0, on the left
	//
	// The branch contains 6 sibling hashes needed to compute the path to the root
	path := [6]int{1, 1, 1, 0, 1, 0}

	// Start with the leaf (next_sync_committee root)
	current := c.NextScRoot

	// Traverse up the tree using the branch
	for i := 0; i < 6; i++ {
		sibling := c.NextScBranch[i]

		// Compute parent hash based on path direction
		if path[i] == 1 {
			// Current node is on the right, sibling is on the left
			current = c.hashPair(api, sibling, current)
		} else {
			// Current node is on the left, sibling is on the right
			current = c.hashPair(api, current, sibling)
		}
	}

	// The final computed root must equal the StateRoot from the BeaconBlockHeader
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(current[i].Val, c.StateRoot[i].Val)
	}

	return nil
}

// Helper functions (reused from BlockRootHasher)

// serializeLimbTo8Bytes converts a limb (frontend.Variable) to 8 bytes (64 bits, big-endian)
func (c *Eth2ScUpdateCircuit) serializeLimbTo8Bytes(api frontend.API, limb frontend.Variable) []uints.U8 {
	// Convert limb to 64 bits (little-endian)
	bits := api.ToBinary(limb, 64)
	bytes := make([]uints.U8, 8)

	// Pack bits into bytes and reverse for big-endian
	for byteIdx := 0; byteIdx < 8; byteIdx++ {
		var byteValue frontend.Variable = 0
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			bit := bits[byteIdx*8+bitIdx]
			power := 1 << bitIdx
			byteValue = api.Add(byteValue, api.Mul(bit, power))
		}
		// Store in reverse order for big-endian
		bytes[7-byteIdx] = uints.U8{Val: byteValue}
	}

	return bytes
}

// serializeUint64ToChunk converts a 64-bit unsigned integer into a 32-byte array chunk with little-endian encoding.
func (c *Eth2ScUpdateCircuit) serializeUint64ToChunk(api frontend.API, value frontend.Variable) [32]uints.U8 {
	var chunk [32]uints.U8

	// Convert value to 64 bits (little-endian)
	bits := api.ToBinary(value, 64)

	// Pack bits into bytes (8 bits per byte, little-endian)
	for byteIdx := 0; byteIdx < 8; byteIdx++ {
		var byteValue frontend.Variable = 0
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			bit := bits[byteIdx*8+bitIdx]
			power := 1 << bitIdx
			byteValue = api.Add(byteValue, api.Mul(bit, power))
		}
		chunk[byteIdx] = uints.U8{Val: byteValue}
	}

	// Remaining 24 bytes are zero-padded
	for i := 8; i < 32; i++ {
		chunk[i] = uints.NewU8(0)
	}

	return chunk
}

func (c *Eth2ScUpdateCircuit) zeroChunk() [32]uints.U8 {
	var chunk [32]uints.U8
	for i := 0; i < 32; i++ {
		chunk[i] = uints.NewU8(0)
	}
	return chunk
}

// hashPair computes the SHA256 hash of two 32-byte arrays (left and right) and returns the resulting 32-byte hash.
func (c *Eth2ScUpdateCircuit) hashPair(api frontend.API, left, right [32]uints.U8) [32]uints.U8 {
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
