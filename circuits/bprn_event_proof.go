package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	gnark_ecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// Circuit size constants
const (
	MaxMerkleDepth = 4
	MaxP256Proofs  = 8
)

// BPrNEventProofCircuit verifies P256 ECDSA signature on OriginPayloadH + EventPayloadH
type BPrNEventProofCircuit struct {
	// Number of actual proofs to verify (must be <= MaxP256Proofs)
	NumProofs frontend.Variable `gnark:",public"`

	// Inner Groth16 proofs from BPrNMsgHCircuit (compiled with BLS12-377)
	Proofs [MaxP256Proofs]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]

	// Inner witnesses (public inputs for each inner proof)
	// Each witness contains TargetH [32]U8 as public input
	Witnesses [MaxP256Proofs]stdgroth16.Witness[sw_bls12377.ScalarField]

	// Verifying key for BPrNMsgHCircuit (same for all proofs)
	VK stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]

	// Secret inputs

	// P256 Public Key (X, Y coordinates)
	Pub gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]

	// P256 Signature (R, S values)
	Sig gnark_ecdsa.Signature[emulated.P256Fr]

	OriginPayloadH [32]uints.U8
	EventPayloadH  [32]uints.U8

	EventLogRootBranches [MaxMerkleDepth][32]uints.U8
	EventLogIdx          frontend.Variable
	EventLogRoot         [32]uints.U8

	EventElemHBranches [MaxMerkleDepth][32]uints.U8
	EventElemIdx       frontend.Variable
	EventElemH         [32]uints.U8 `gnark:",public"`
}

func (c *BPrNEventProofCircuit) Define(api frontend.API) error {

	// Create a new SHA256 hasher
	hasher, err := sha2.New(api)
	if err != nil {
		panic(err)
	}

	// Write 64 bytes total (left || right)
	hasher.Write(c.OriginPayloadH[:])
	hasher.Write(c.EventPayloadH[:])

	// Compute SHA256 hash
	computedHash := hasher.Sum()

	// Convert computed hash to emulated.Element for P256Fr (scalar field)
	scalarApi, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return err
	}
	msgHash := hashBytesToElement(api, scalarApi, computedHash)

	// Verify ECDSA P256 signature
	// This implicitly verifies that the paddedData from the hint corresponds to the TxLimbs
	// for which the prover has a valid signature.
	c.Pub.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), msgHash, &c.Sig)

	// Verify EventLogRootH
	hasher, err = sha2.New(api)
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
