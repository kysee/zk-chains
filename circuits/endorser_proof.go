package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	gnark_ecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

const (
	MaxMsgSize = 1024
)

type EndorserProofCircuit struct {
	CertBytes [MaxMsgSize]uints.U8
	CertLen   frontend.Variable

	// P256 Signature (R, S values)
	Sig gnark_ecdsa.Signature[emulated.P256Fr]

	// P256 Public Key (X, Y coordinates)
	RootPubK gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr] `gnark:",public"`

	OUIdx      frontend.Variable
	OULen      frontend.Variable
	PubKOffset frontend.Variable

	OUBytes   [32]uints.U8 `gnark:",public"`
	PubKBytes [32]uints.U8 `gnark:",public"`
}

func (c *EndorserProofCircuit) Define(api frontend.API) error {
	// Step 1: Compute SHA256(CertBytes[0:CertLen])
	// CertBytes must be pre-padded by the prover with SHA256 padding.
	// numBlocks = floor((CertLen + 72) / 64)
	temp := api.Add(c.CertLen, 72)
	tempBits := api.ToBinary(temp, 11) // max: 1024 + 72 = 1096 < 2^11
	numBlocks := frontend.Variable(0)
	for i := 6; i < 11; i++ {
		numBlocks = api.Add(numBlocks, api.Mul(tempBits[i], 1<<(i-6)))
	}

	certDigest, err := ComputeSHA256(api, c.CertBytes[:], numBlocks)
	if err != nil {
		return err
	}

	// Step 2: Verify P256 signature: RootPubK.Verify(certDigest, Sig)
	scalarApi, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return err
	}
	msgHash := HashBytesToElement(api, scalarApi, certDigest)
	c.RootPubK.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), msgHash, &c.Sig)

	// Step 3: OU and PubK inclusion checks
	certVars := make([]frontend.Variable, MaxMsgSize)
	for i := 0; i < MaxMsgSize; i++ {
		certVars[i] = c.CertBytes[i].Val
	}

	// CertBytes[OUIdx:OUIdx+OULen] == OUBytes
	ouShifted := ShiftLeft(api, certVars, c.OUIdx, MaxMsgSize)
	for i := 0; i < 32; i++ {
		isInRange := api.IsZero(api.Add(api.Cmp(i, c.OULen), 1)) // 1 if i < OULen
		diff := api.Sub(ouShifted[i], c.OUBytes[i].Val)
		api.AssertIsEqual(api.Mul(isInRange, diff), 0)
	}

	// CertBytes[PubKOffset:PubKOffset+32] == PubKBytes
	pubkShifted := ShiftLeft(api, certVars, c.PubKOffset, MaxMsgSize)
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(pubkShifted[i], c.PubKBytes[i].Val)
	}

	return nil
}
