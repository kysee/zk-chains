package bprn

import (
	"fmt"
	"path/filepath"

	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/kysee/zk-chains/circuits"
	types2 "github.com/kysee/zk-chains/types"
)

func init() {

}

type TxProverPlonk struct {
	ccs constraint.ConstraintSystem
	pk  plonk.ProvingKey
	vk  plonk.VerifyingKey
}

func NewTxProverPlonk() *TxProverPlonk {
	fmt.Println("Create TxProverPlonk ...")

	var circuit circuits.BPrNEventProofCircuit

	rootDir, _ := types2.ProjectRoot()
	//ccs, pk, vk := circuits.LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &circuit)
	ccs, pk, vk := circuits.LoadOrSetupCircuit_Plonk(filepath.Join(rootDir, ".build"), &circuit)

	return &TxProverPlonk{
		ccs: ccs,
		pk:  pk,
		vk:  vk,
	}
}

func (prover *TxProverPlonk) Prove(data interface{}) ([][]byte, error) {
	var bzProofs [][]byte
	//action := data.(*peer.ChaincodeEndorsedAction)
	//
	//// for test
	//innerBytes := []byte("PostMessageEvent_")
	//innerBytesOffset := bytes.Index(action.ProposalResponsePayload, innerBytes)
	//innerDataPadded := action.ProposalResponsePayload[innerBytesOffset : innerBytesOffset+circuits.InnerBytesSize]
	//
	//for _, endorsement := range action.Endorsements {
	//	msg := append(action.ProposalResponsePayload, endorsement.Endorser...)
	//	r, s, _ := types.ParseDERSignature(endorsement.Signature)
	//	pubKey, _ := types.PubkeyFromCert(endorsement.Endorser)
	//
	//	assignment := circuits.BPrNTxProofCircuit{
	//		TxLimbs:     circuits.TxToLimbs(msg),
	//		TxLen:       len(msg),
	//		InnerOffset: innerBytesOffset,
	//		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
	//			X: emulated.ValueOf[emulated.P256Fp](pubKey.X),
	//			Y: emulated.ValueOf[emulated.P256Fp](pubKey.Y),
	//		},
	//		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
	//			R: emulated.ValueOf[emulated.P256Fr](r),
	//			S: emulated.ValueOf[emulated.P256Fr](s),
	//		},
	//		InnerBytes: circuits.To256U8Array(innerDataPadded),
	//	}
	//
	//	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	//	proof, err := plonk.Prove(prover.ccs, prover.pk, witness)
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//	bzProof := proof.(interface{ MarshalSolidity() []byte }).MarshalSolidity()
	//
	//	bzProofs = append(bzProofs, bzProof)
	//}

	return bzProofs, nil
}
