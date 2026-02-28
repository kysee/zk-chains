package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type BPrNEventProofCircuit struct {
	EventRoot     [32]uints.U8
	Siblings      [MaxMerkleDepth][32]uints.U8
	EventElemIdx  frontend.Variable
	EventElemHash [32]uints.U8 `gnark:",public"`
}

func (c *BPrNEventProofCircuit) Define(api frontend.API) error {
	VerifyMerkleProof(api, c.Siblings, c.EventElemIdx, c.EventElemHash[:], c.EventRoot[:])
	return nil
}
