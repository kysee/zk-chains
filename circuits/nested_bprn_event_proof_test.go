package circuits

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	ecdsaCircuit "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/kysee/zk-chains/provers/types"
	"github.com/stretchr/testify/require"
)

func TestNestedBPrNMsgH2Circuit(t *testing.T) {
	// Generate 2 P256 key pairs
	privKey0, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Common EventPayloadH
	targetH := sha256.Sum256([]byte("common_target_hash"))

	// Different PreHs for each signature
	preH0 := sha256.Sum256([]byte("preH_for_signature_0"))
	preH1 := sha256.Sum256([]byte("preH_for_signature_1"))

	// Compute digests and sign
	digest0 := sha256.Sum256(append(preH0[:], targetH[:]...))
	digest1 := sha256.Sum256(append(preH1[:], targetH[:]...))

	sigDER0, err := privKey0.Sign(rand.Reader, digest0[:], nil)
	require.NoError(t, err)
	sigDER1, err := privKey1.Sign(rand.Reader, digest1[:], nil)
	require.NoError(t, err)

	r0, s0, err := types.ParseDERSignature(sigDER0)
	require.NoError(t, err)
	r1, s1, err := types.ParseDERSignature(sigDER1)
	require.NoError(t, err)

	// Create circuit
	var circuit NestedBPrNMsgH2Circuit

	// Create witness
	witness := NestedBPrNMsgH2Circuit{
		TargetH: ToU8Array32(targetH[:]),

		PreH0: ToU8Array32(preH0[:]),
		Pub0: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey0.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey0.PublicKey.Y),
		},
		Sig0: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r0),
			S: emulated.ValueOf[emulated.P256Fr](s0),
		},

		PreH1: ToU8Array32(preH1[:]),
		Pub1: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey1.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey1.PublicKey.Y),
		},
		Sig1: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r1),
			S: emulated.ValueOf[emulated.P256Fr](s1),
		},
	}

	// Test that the circuit is satisfied
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	t.Log("NestedBPrNMsgH2Circuit test passed - 2 signatures verified in single circuit")
}

func TestNestedBPrNMsgH4Circuit(t *testing.T) {
	// Generate 4 P256 key pairs
	privKeys := make([]*ecdsa.PrivateKey, 4)
	for i := 0; i < 4; i++ {
		var err error
		privKeys[i], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
	}

	// Common EventPayloadH
	targetH := sha256.Sum256([]byte("common_target_hash_for_4"))

	// Different PreHs
	preHs := make([][32]byte, 4)
	for i := 0; i < 4; i++ {
		preHs[i] = sha256.Sum256([]byte("preH_" + string(rune('0'+i))))
	}

	// Sign
	rs := make([]*struct{ R, S []byte }, 4)
	for i := 0; i < 4; i++ {
		digest := sha256.Sum256(append(preHs[i][:], targetH[:]...))
		sigDER, err := privKeys[i].Sign(rand.Reader, digest[:], nil)
		require.NoError(t, err)
		r, s, err := types.ParseDERSignature(sigDER)
		require.NoError(t, err)
		rs[i] = &struct{ R, S []byte }{R: r.Bytes(), S: s.Bytes()}
	}

	r0, s0, _ := types.ParseDERSignature(mustSign(t, privKeys[0], append(preHs[0][:], targetH[:]...)))
	r1, s1, _ := types.ParseDERSignature(mustSign(t, privKeys[1], append(preHs[1][:], targetH[:]...)))
	r2, s2, _ := types.ParseDERSignature(mustSign(t, privKeys[2], append(preHs[2][:], targetH[:]...)))
	r3, s3, _ := types.ParseDERSignature(mustSign(t, privKeys[3], append(preHs[3][:], targetH[:]...)))

	var circuit NestedBPrNMsgH4Circuit

	witness := NestedBPrNMsgH4Circuit{
		TargetH: ToU8Array32(targetH[:]),

		PreH0: ToU8Array32(preHs[0][:]),
		Pub0: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKeys[0].PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKeys[0].PublicKey.Y),
		},
		Sig0: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r0),
			S: emulated.ValueOf[emulated.P256Fr](s0),
		},

		PreH1: ToU8Array32(preHs[1][:]),
		Pub1: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKeys[1].PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKeys[1].PublicKey.Y),
		},
		Sig1: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r1),
			S: emulated.ValueOf[emulated.P256Fr](s1),
		},

		PreH2: ToU8Array32(preHs[2][:]),
		Pub2: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKeys[2].PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKeys[2].PublicKey.Y),
		},
		Sig2: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r2),
			S: emulated.ValueOf[emulated.P256Fr](s2),
		},

		PreH3: ToU8Array32(preHs[3][:]),
		Pub3: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKeys[3].PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKeys[3].PublicKey.Y),
		},
		Sig3: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r3),
			S: emulated.ValueOf[emulated.P256Fr](s3),
		},
	}

	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	t.Log("NestedBPrNMsgH4Circuit test passed - 4 signatures verified in single circuit")
}

func mustSign(t *testing.T, privKey *ecdsa.PrivateKey, data []byte) []byte {
	digest := sha256.Sum256(data)
	sig, err := privKey.Sign(rand.Reader, digest[:], nil)
	require.NoError(t, err)
	return sig
}

func TestNestedBPrNMsgH2Circuit_Compile(t *testing.T) {
	var circuit NestedBPrNMsgH2Circuit

	t.Log("Compiling NestedBPrNMsgH2Circuit...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	require.NoError(t, err)

	t.Logf("Number of constraints: %d", ccs.GetNbConstraints())
	t.Logf("Number of public inputs: %d", ccs.GetNbPublicVariables())
	t.Logf("Number of secret inputs: %d", ccs.GetNbSecretVariables())

	// Compare with single BPrNMsgHCircuit
	var singleCircuit BPrNEventProofCircuit
	singleCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &singleCircuit)
	require.NoError(t, err)

	t.Logf("")
	t.Logf("Comparison:")
	t.Logf("  Single BPrNMsgHCircuit constraints: %d", singleCcs.GetNbConstraints())
	t.Logf("  Nested 2x constraints: %d", ccs.GetNbConstraints())
	t.Logf("  Ratio: %.2fx", float64(ccs.GetNbConstraints())/float64(singleCcs.GetNbConstraints()))
}

func TestNestedBPrNMsgH4Circuit_Compile(t *testing.T) {
	var circuit NestedBPrNMsgH4Circuit

	t.Log("Compiling NestedBPrNMsgH4Circuit...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	require.NoError(t, err)

	t.Logf("Number of constraints: %d", ccs.GetNbConstraints())
	t.Logf("Number of public inputs: %d", ccs.GetNbPublicVariables())
	t.Logf("Number of secret inputs: %d", ccs.GetNbSecretVariables())

	// Compare with single BPrNMsgHCircuit
	var singleCircuit BPrNEventProofCircuit
	singleCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &singleCircuit)
	require.NoError(t, err)

	t.Logf("")
	t.Logf("Comparison:")
	t.Logf("  Single BPrNMsgHCircuit constraints: %d", singleCcs.GetNbConstraints())
	t.Logf("  Nested 4x constraints: %d", ccs.GetNbConstraints())
	t.Logf("  Ratio: %.2fx", float64(ccs.GetNbConstraints())/float64(singleCcs.GetNbConstraints()))
}
