package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	gnark_ecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// Circuit size constants
const (
	MaxMerkleDepth = 4
)

// BPrNEventProofCircuit verifies P256 ECDSA signature on OriginPayloadH + EventPayloadH
type BPrNEventProofCircuit struct {
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
