package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// Circuit size constants
const (
	MaxMerkleDepth = 4
	MaxP256Proofs  = 2
)

// BPrNEventProofCircuit verifies P256 ECDSA signature on OriginPayloadH + EventPayloadH
type BPrNEventProofCircuit struct {
	//
	// InnerCircuit: P256ProofCircuit

	// Number of actual proofs to verify (must be <= MaxP256Proofs)
	NumProofs frontend.Variable

	// Inner Groth16 proofs from BPrNMsgHCircuit (compiled with BN254)
	Proofs [MaxP256Proofs]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]

	// Inner witnesses (public inputs for each inner proof)
	// Each witness contains EventPayloadH [32]U8 as public input
	Witnesses [MaxP256Proofs]stdgroth16.Witness[sw_bn254.ScalarField]

	// Verifying key for BPrNMsgHCircuit (same for all proofs)
	VK stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]

	// Secret inputs
	EventPayloadH [32]uints.U8

	EventLogIdx          frontend.Variable
	EventLogRootBranches [MaxMerkleDepth][32]uints.U8
	EventLogRoot         [32]uints.U8

	EventElemIdx       frontend.Variable
	EventElemHBranches [MaxMerkleDepth][32]uints.U8
	EventElemH         [32]uints.U8 `gnark:",public"`
}

func (c *BPrNEventProofCircuit) Define(api frontend.API) error {
	//
	// Check the inner circuit(P256ProofCircuit) to verify P256 signature
	//

	// Create verifier for BN254 Groth16 proofs (emulated)
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}

	// Verify each inner proof and check EventPayloadH consistency
	for i := 0; i < MaxP256Proofs; i++ {
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

		// Extract and compare EventPayloadH from witness public inputs
		// P256ProofCircuit's public input is MsgH [32]uints.U8
		for j := 0; j < 32; j++ {
			witnessByte := c.Witnesses[i].Public[j].Limbs[0]
			diff := api.Sub(witnessByte, c.EventPayloadH[j].Val)
			// If active, diff must be 0; if not active, skip check
			api.AssertIsEqual(api.Mul(isActive, diff), 0)
		}
	}

	// Now, EventPayloadH is trusted by verifying P256 signature
	// Verify merkle proof that
	//  1) EventPayloadH contains EventLogRoot and
	//  2) EventLogRoot contains EventElemH.

	// Create a new SHA256 hasher
	hasher, err := sha2.New(api)
	if err != nil {
		panic(err)
	}

	hasher.Write(c.EventLogRoot[:])
	eventLogRootH := hasher.Sum()

	api.AssertIsEqual(
		VerifyMerkleProof(api, c.EventLogIdx, eventLogRootH, c.EventPayloadH[:], c.EventLogRootBranches, MaxMerkleDepth),
		1,
	)

	api.AssertIsEqual(
		VerifyMerkleProof(api, c.EventElemIdx, c.EventElemH[:], c.EventLogRoot[:], c.EventElemHBranches, MaxMerkleDepth),
		1,
	)

	return nil
}
