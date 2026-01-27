package circuits

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	ecdsaCircuit "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	proverTypes "github.com/kysee/zk-chains/provers/types"
	types2 "github.com/kysee/zk-chains/types"
	"github.com/stretchr/testify/require"
)

func TestBPrNMsgHCircuit_P256(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Prepare data
	preMsgH := sha256.Sum256([]byte("premessage_message"))
	msgH := sha256.Sum256([]byte("public_message"))

	// Concatenate PreH and MsgH
	data := append(preMsgH[:], msgH[:]...)

	// Hash the concatenated data
	hash := sha256.Sum256(data)

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, hash[:], nil)
	require.NoError(t, err)

	// Parse DER signature to get R and S
	r, s, err := proverTypes.ParseDERSignature(sigDER)
	require.NoError(t, err)

	// Verify signature outside circuit first
	valid := ecdsa.Verify(&privKey.PublicKey, hash[:], r, s)
	require.True(t, valid, "signature should be valid")

	// Create circuit
	var circuit BPrNMsgHCircuit

	// Create witness
	witness := BPrNMsgHCircuit{
		PreH: ToU8Array32(preMsgH[:]),
		MsgH: ToU8Array32(msgH[:]),
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
	}

	// Test that the circuit is satisfied
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	t.Logf("P256 ECDSA signature verification circuit test passed")
	t.Logf("PreH: %x", preMsgH)
	t.Logf("MsgH: %x", msgH)
	t.Logf("Hash: %x", hash)
}

func TestBPrNMsgHCircuit_WrongMsgH(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Prepare data
	preMsgH := sha256.Sum256([]byte("premessage_message"))
	msgH := sha256.Sum256([]byte("public_message"))
	wrongMsgH := sha256.Sum256([]byte("wrong_message"))

	// Concatenate PreH and MsgH (correct data for signature)
	data := append(preMsgH[:], msgH[:]...)

	// Hash the concatenated data
	hash := sha256.Sum256(data)

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, hash[:], nil)
	require.NoError(t, err)

	r, s, err := proverTypes.ParseDERSignature(sigDER)
	require.NoError(t, err)

	var circuit BPrNMsgHCircuit

	// Create witness with Wrong MsgH
	witness := BPrNMsgHCircuit{
		PreH: ToU8Array32(preMsgH[:]),
		MsgH: ToU8Array32(wrongMsgH[:]), // Wrong!
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
	}

	// Test that the circuit FAILS
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "circuit should fail when MsgH is wrong")

	t.Logf("Wrong MsgH - correctly rejected")
}

func TestBPrNMsgHCircuit_InvalidSignature(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Prepare data
	preMsgH := sha256.Sum256([]byte("premessage_message"))
	msgH := sha256.Sum256([]byte("public_message"))

	// Concatenate PreH and MsgH
	data := append(preMsgH[:], msgH[:]...)

	// Hash the concatenated data
	hash := sha256.Sum256(data)

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, hash[:], nil)
	require.NoError(t, err)

	r, s, err := proverTypes.ParseDERSignature(sigDER)
	require.NoError(t, err)

	// Modify S to make signature invalid
	invalidS := new(big.Int).Add(s, big.NewInt(1))

	var circuit BPrNMsgHCircuit

	// Create witness with invalid signature
	witness := BPrNMsgHCircuit{
		PreH: ToU8Array32(preMsgH[:]),
		MsgH: ToU8Array32(msgH[:]),
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](invalidS), // Invalid!
		},
	}

	// Test that the circuit FAILS
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "circuit should fail with invalid signature")

	t.Logf("Invalid signature correctly rejected")
}

func TestBPrNMsgHCircuit_Setup_Groth16(t *testing.T) {
	rootDir, _ := types2.ProjectRoot()
	var c BPrNMsgHCircuit
	_, _, _ = LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &c)
}

func TestBPrNMsgHCircuit_Setup_Plonk(t *testing.T) {
	var c BPrNMsgHCircuit

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &c)
	require.NoError(t, err)

	t.Logf("Circuit compiled successfully")
	t.Logf("Number of constraints: %d", ccs.GetNbConstraints())
	t.Logf("Number of public inputs: %d", ccs.GetNbPublicVariables())
	t.Logf("Number of secret inputs: %d", ccs.GetNbSecretVariables())

	// Generate proving key and verifying key using PLONK
	t.Log("Generating SRS (this may take a while)...")

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	require.NoError(t, err)

	t.Log("Generating proving key and verifying key...")

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	require.NoError(t, err)

	t.Logf("Proving key generated successfully")
	t.Logf("Verifying key generated successfully")

	// Log sizes
	var pkBuf, vkBuf bytes.Buffer
	_, err = pk.WriteTo(&pkBuf)
	require.NoError(t, err)
	_, err = vk.WriteTo(&vkBuf)
	require.NoError(t, err)

	t.Logf("Proving key size: %d bytes (%.2f MB)", pkBuf.Len(), float64(pkBuf.Len())/(1024*1024))
	t.Logf("Verifying key size: %d bytes (%.2f KB)", vkBuf.Len(), float64(vkBuf.Len())/1024)
}
