package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// Circuit size constants
const (
	MaxDepth = 4
)

// BPrNEventProofCircuit verifies P256 ECDSA signature on OriginPayloadH + EventPayloadH
type MerkleProofCircuit struct {
	LeafHash     [32]uints.U8 `gnark:",public"`
	LeafSiblings [MaxDepth][32]uints.U8
	LeafIdx      frontend.Variable
	Root         [32]uints.U8
}

func (c *MerkleProofCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(
		VerifyMerkleProof(api, c.LeafIdx, c.LeafHash[:], c.Root[:], c.LeafSiblings, MaxDepth),
		1,
	)
	return nil
}
