package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

type BPrNEventProofCircuit struct {
	Siblings [MaxMerkleDepth][32]uints.U8
	LeafIdx  frontend.Variable
	LogRoot  [32]uints.U8

	LogRootSiblings [MaxMerkleDepth][32]uints.U8
	LogRootIdx      frontend.Variable

	LeafHash   [32]uints.U8 `gnark:",public"`
	LogSetRoot [32]uints.U8 `gnark:",public"`
}

func (c *BPrNEventProofCircuit) Define(api frontend.API) error {
	VerifyMerkleProof(api, c.Siblings, c.LeafIdx, c.LeafHash[:], c.LogRoot[:])

	// Hash(LogRoot) == LogRootH
	hasher, err := sha2.New(api)
	if err != nil {
		panic(err)
	}
	hasher.Write(c.LogRoot[:])
	logRootH := hasher.Sum()

	VerifyMerkleProof(api, c.LogRootSiblings, c.LogRootIdx, logRootH, c.LogSetRoot[:])

	return nil
}
