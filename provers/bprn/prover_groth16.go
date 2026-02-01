package bprn

import (
	"fmt"
	"path/filepath"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/kysee/zk-chains/circuits"
	types2 "github.com/kysee/zk-chains/types"
)

func init() {

}

type TxProverGroth16 struct {
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
}

func NewTxProverGroth16() *TxProverGroth16 {
	fmt.Println("Create TxProverGroth16 ...")

	var circuit circuits.BPrNEventProofCircuit
	rootDir, _ := types2.ProjectRoot()
	ccs, pk, vk := circuits.LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &circuit)

	return &TxProverGroth16{
		ccs: ccs,
		pk:  pk,
		vk:  vk,
	}
}

func (prover *TxProverGroth16) Prove(data interface{}) ([][]byte, error) {
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
	//	tm0 := time.Now()
	//	proof, err := groth16.Prove(prover.ccs, prover.pk, witness)
	//	since := time.Since(tm0)
	//	fmt.Printf("Proof generation time: %v\n", since)
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//	// for test
	//	pubWtn, err := witness.Public()
	//	if err != nil {
	//		return nil, err
	//	}
	//	tm0 = time.Now()
	//	err = groth16.Verify(proof, prover.vk, pubWtn)
	//	since = time.Since(tm0)
	//	fmt.Printf("Verify time: %v\n", since)
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
