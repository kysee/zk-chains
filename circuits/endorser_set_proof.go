package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"

	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// Circuit size constants
const (
	MaxEndorserProof = 4
)

// EndorserSetProofCircuit - 디버깅용 최소 버전
type EndorserSetProofCircuit struct {
	Proofs    [MaxEndorserProof]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	Witnesses [MaxEndorserProof]stdgroth16.Witness[sw_bn254.ScalarField]
	VK        stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
}

func (c *EndorserSetProofCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	for i := 0; i < MaxEndorserProof; i++ {
		err = verifier.AssertProof(c.VK, c.Proofs[i], c.Witnesses[i], stdgroth16.WithCompleteArithmetic())
		if err != nil {
			return err
		}
	}
	return nil
}
