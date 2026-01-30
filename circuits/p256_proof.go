package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	gnark_ecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

type P256ProofCircuit struct {
	// P256 Public Key (X, Y coordinates)
	Pub gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]

	// P256 Signature (R, S values)
	Sig gnark_ecdsa.Signature[emulated.P256Fr]

	MsgH [32]uints.U8 `gnark:",public"`
}

func (c *P256ProofCircuit) Define(api frontend.API) error {
	// Convert computed hash to emulated.Element for P256Fr (scalar field)
	scalarApi, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return err
	}
	msgHash := hashBytesToElement(api, scalarApi, c.MsgH[:])

	// Verify ECDSA P256 signature
	// This implicitly verifies that the paddedData from the hint corresponds to the TxLimbs
	// for which the prover has a valid signature.
	c.Pub.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), msgHash, &c.Sig)

	return nil
}
