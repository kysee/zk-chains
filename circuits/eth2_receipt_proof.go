package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/uints"
)

type Eth2ReceiptProofCircuit struct {
	// BeaconBlockHeader fields (private inputs)
	Slot          frontend.Variable // uint64
	ProposerIndex frontend.Variable // uint64
	ParentRoot    [32]uints.U8      // bytes32
	StateRoot     [32]uints.U8      // bytes32
	BodyRoot      [32]uints.U8      // bytes32

	// Sync committee data (private inputs)
	ScPubKeys     [512]sw_bls12381.G1Affine // 512 sync committee public keys
	ScBits        [512]frontend.Variable    // Bit array indicating which validators signed (0 or 1)
	AggregatedSig sw_bls12381.G2Affine

	ExeHeaderRootBranch [4][32]uints.U8
	ExeHeaderRoot       [32]uints.U8
	ReceiptsRootBranch  [4][32]uints.U8
	ReceiptsRoot        [32]uints.U8
	ReceiptRLPBranch    [4][32]uints.U8
	ReceiptRLP          [32]uints.U8
}

func (c *Eth2ReceiptProofCircuit) Define(api frontend.API) error {
	return nil
}
