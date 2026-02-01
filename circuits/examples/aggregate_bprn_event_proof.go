package examples

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// MaxAggregateProofs is the maximum number of inner BPrNMsgHCircuit proofs to aggregate
const MaxAggregateProofs = 8

// AggregateBPrNEventProofCircuit aggregates multiple BPrNMsgHCircuit proofs
// All inner proofs must share the same TargetH (verified via public inputs)
//
// IMPORTANT: Inner circuit (BPrNMsgHCircuit) must be compiled with BLS12-377 curve
// This outer circuit should be compiled with BW6-761 curve for efficient native pairing verification
//
// Curve cycle: BLS12-377 (inner) -> BW6-761 (outer)
type AggregateBPrNEventProofCircuit struct {
	// Public: common TargetH that all inner proofs share (32 bytes as 4 x 64-bit limbs)
	// Using 4 limbs because BW6-761 scalar field is large enough
	TargetH [4]frontend.Variable `gnark:",public"`

	// Number of actual proofs to verify (must be <= MaxAggregateProofs)
	NumProofs frontend.Variable `gnark:",public"`

	// Inner Groth16 proofs from BPrNMsgHCircuit (compiled with BLS12-377)
	Proofs [MaxAggregateProofs]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]

	// Inner witnesses (public inputs for each inner proof)
	// Each witness contains TargetH [32]U8 as public input
	Witnesses [MaxAggregateProofs]stdgroth16.Witness[sw_bls12377.ScalarField]

	// Verifying key for BPrNMsgHCircuit (same for all proofs)
	VK stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]
}

func (c *AggregateBPrNEventProofCircuit) Define(api frontend.API) error {
	// Create verifier for BLS12-377 Groth16 proofs (native on BW6-761)
	verifier, err := stdgroth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return err
	}

	// Verify each inner proof and check EventPayloadH consistency
	for i := 0; i < MaxAggregateProofs; i++ {
		// Determine if this slot is active (i < NumProofs)
		// isActive = 1 if NumProofs > i, 0 otherwise
		iConst := frontend.Variable(i)
		cmpResult := api.Cmp(c.NumProofs, iConst) // 1 if NumProofs > i, 0 if equal, -1 if less
		isActive := api.IsZero(api.Sub(cmpResult, 1))

		// Verify the proof (for inactive slots, dummy proofs must be provided)
		err = verifier.AssertProof(c.VK, c.Proofs[i], c.Witnesses[i], stdgroth16.WithCompleteArithmetic())
		if err != nil {
			return err
		}

		// Extract EventPayloadH from inner witness public inputs
		// BPrNMsgHCircuit has EventPayloadH [32]uints.U8 as public input
		// Witness.Public contains these 32 emulated elements

		// Reconstruct 4 x 64-bit limbs from 32 x 8-bit values
		innerTargetH := reconstructTargetHFromWitness(api, c.Witnesses[i].Public)

		// Check EventPayloadH matches (only for active slots)
		for j := 0; j < 4; j++ {
			diff := api.Sub(c.TargetH[j], innerTargetH[j])
			// For active slots: diff must be 0
			// For inactive slots: diff can be anything (multiply by isActive to ignore)
			api.AssertIsEqual(api.Mul(isActive, diff), 0)
		}
	}

	return nil
}

// reconstructTargetHFromWitness reconstructs 4 x 64-bit limbs from 32 U8 witness elements
func reconstructTargetHFromWitness(api frontend.API, publicInputs []emulated.Element[sw_bls12377.ScalarField]) [4]frontend.Variable {
	var result [4]frontend.Variable

	// publicInputs[0..31] are the 32 bytes of EventPayloadH
	// Group into 4 limbs of 8 bytes each (64 bits)
	// Limb 0: bytes 0-7 (most significant)
	// Limb 1: bytes 8-15
	// Limb 2: bytes 16-23
	// Limb 3: bytes 24-31 (least significant)

	for limbIdx := 0; limbIdx < 4; limbIdx++ {
		limbValue := frontend.Variable(0)
		for byteIdx := 0; byteIdx < 8; byteIdx++ {
			globalIdx := limbIdx*8 + byteIdx
			// Each emulated element has Limbs, use first limb for small values
			byteVal := publicInputs[globalIdx].Limbs[0]

			// Shift: byte * 256^(7-byteIdx)
			shift := new(big.Int).Exp(big.NewInt(256), big.NewInt(int64(7-byteIdx)), nil)
			shifted := api.Mul(byteVal, shift)
			limbValue = api.Add(limbValue, shifted)
		}
		result[limbIdx] = limbValue
	}

	return result
}

// ============================================================================
// BN254 Emulated Version - For Ethereum verification
// ============================================================================
// AggregateBPrNEventProofCircuitBN254 aggregates multiple BPrNMsgHCircuit proofs
// using emulated BN254 arithmetic. This allows the outer circuit to be compiled
// with BN254 curve for Ethereum smart contract verification.
//
// NOTE: This is computationally expensive due to emulated pairing operations.
// Use AggregateBPrNEventProofCircuit (BLS12-377/BW6-761) for off-chain verification.
//
// Curve: BN254 (inner, emulated) -> BN254 (outer)
type AggregateBPrNEventProofCircuitBN254 struct {
	// Public: common EventPayloadH that all inner proofs share (32 bytes as 4 x 64-bit limbs)
	EventPayloadH [4]frontend.Variable `gnark:",public"`

	// Number of actual proofs to verify (must be <= MaxAggregateProofs)
	NumProofs frontend.Variable `gnark:",public"`

	// Inner Groth16 proofs from BPrNMsgHCircuit (compiled with BN254)
	Proofs [MaxAggregateProofs]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]

	// Inner witnesses (public inputs for each inner proof)
	// Each witness contains EventPayloadH [32]U8 as public input
	Witnesses [MaxAggregateProofs]stdgroth16.Witness[sw_bn254.ScalarField]

	// Verifying key for BPrNMsgHCircuit (same for all proofs)
	VK stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
}

func (c *AggregateBPrNEventProofCircuitBN254) Define(api frontend.API) error {
	// Create verifier for BN254 Groth16 proofs (emulated)
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}

	// Verify each inner proof and check EventPayloadH consistency
	for i := 0; i < MaxAggregateProofs; i++ {
		// Determine if this slot is active (i < NumProofs)
		iConst := frontend.Variable(i)
		cmpResult := api.Cmp(c.NumProofs, iConst)
		isActive := api.IsZero(api.Sub(cmpResult, 1))

		// Verify the proof (for inactive slots, dummy proofs must be provided)
		err = verifier.AssertProof(c.VK, c.Proofs[i], c.Witnesses[i], stdgroth16.WithCompleteArithmetic())
		if err != nil {
			return err
		}

		// Extract and compare EventPayloadH
		innerTargetH := reconstructTargetHFromWitnessBN254(api, c.Witnesses[i].Public)

		for j := 0; j < 4; j++ {
			diff := api.Sub(c.EventPayloadH[j], innerTargetH[j])
			api.AssertIsEqual(api.Mul(isActive, diff), 0)
		}
	}

	return nil
}

// reconstructTargetHFromWitnessBN254 reconstructs 4 x 64-bit limbs from 32 U8 witness elements (BN254 version)
func reconstructTargetHFromWitnessBN254(api frontend.API, publicInputs []emulated.Element[sw_bn254.ScalarField]) [4]frontend.Variable {
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

// ============================================================================
// Helper functions for EventPayloadH conversion
// ============================================================================

// ToLimbs converts a 32-byte EventPayloadH to 4 x 64-bit limbs
func ToLimbs(targetH [32]byte) [4]*big.Int {
	var limbs [4]*big.Int
	for i := 0; i < 4; i++ {
		limbs[i] = new(big.Int).SetBytes(targetH[i*8 : (i+1)*8])
	}
	return limbs
}
