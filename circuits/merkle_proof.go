package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type MerkleProofCircuit struct {
	LeafHash     [32]uints.U8 `gnark:",public"`
	LeafSiblings [MaxMerkleDepth][32]uints.U8
	LeafIdx      frontend.Variable
	Root         [32]uints.U8
}

func (c *MerkleProofCircuit) Define(api frontend.API) error {
	VerifyMerkleProof(api, c.LeafSiblings, c.LeafIdx, c.LeafHash[:], c.Root[:])
	return nil
}
