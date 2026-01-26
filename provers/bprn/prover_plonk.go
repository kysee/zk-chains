package bprn

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	ecdsaCircuit "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/kysee/zk-chains/circuits"
	"github.com/kysee/zk-chains/provers/types"
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

	var circuit circuits.BPrNTxProofCircuit

	rootDir, _ := types2.ProjectRoot()
	//ccs, pk, vk := circuits.LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &circuit)
	ccs, pk, vk := circuits.LoadOrSetupCircuit_Plonk(filepath.Join(rootDir, ".build"), &circuit)

	//ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	//if err != nil {
	//	panic(err)
	//}

	fmt.Println("Circuit compiled successfully")
	fmt.Printf("Tx max size: %d bytes\n", circuits.TxMaxSize)
	fmt.Printf("Tx limb size: %d limbs\n", circuits.TxLimbSize)
	fmt.Printf("InnerBytes size: %d bytes\n", circuits.InnerBytesSize)

	//// Generate proving key and verifying key using PLONK
	//fmt.Println("Generating SRS (this may take a while)...")

	//srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	//if err != nil {
	//	panic(err)
	//}

	fmt.Println("Generating proving key and verifying key...")

	//pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	//if err != nil {
	//	panic(err)
	//}

	return &TxProverPlonk{
		ccs: ccs,
		pk:  pk,
		vk:  vk,
	}
}

func (prover *TxProverPlonk) Prove(data interface{}) ([][]byte, error) {
	var bzProofs [][]byte
	action := data.(*peer.ChaincodeEndorsedAction)

	// for test
	innerBytes := []byte("PostMessageEvent_")
	innerBytesOffset := bytes.Index(action.ProposalResponsePayload, innerBytes)
	innerDataPadded := action.ProposalResponsePayload[innerBytesOffset : innerBytesOffset+circuits.InnerBytesSize]

	for _, endorsement := range action.Endorsements {
		msg := append(action.ProposalResponsePayload, endorsement.Endorser...)
		r, s, _ := types.ParseDERSignature(endorsement.Signature)
		pubKey, _ := types.PubkeyFromCert(endorsement.Endorser)

		assignment := circuits.BPrNTxProofCircuit{
			TxLimbs:     circuits.ToLimbs(msg),
			TxLen:       len(msg),
			InnerOffset: innerBytesOffset,
			Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
				X: emulated.ValueOf[emulated.P256Fp](pubKey.X),
				Y: emulated.ValueOf[emulated.P256Fp](pubKey.Y),
			},
			Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
				R: emulated.ValueOf[emulated.P256Fr](r),
				S: emulated.ValueOf[emulated.P256Fr](s),
			},
			InnerBytes: circuits.ToU8Array(innerDataPadded),
		}

		witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		proof, err := plonk.Prove(prover.ccs, prover.pk, witness)
		if err != nil {
			return nil, err
		}

		bzProof := proof.(interface{ MarshalSolidity() []byte }).MarshalSolidity()

		bzProofs = append(bzProofs, bzProof)
	}

	return bzProofs, nil
}
