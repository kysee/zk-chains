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
	"github.com/kysee/zk-chains/provers/types"
	zkTypes "github.com/kysee/zk-chains/types"
	"github.com/stretchr/testify/require"
)

func TestP256ProofCircuit(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create message and hash it
	msg := []byte("test message for P256 signature verification")
	msgHash := sha256.Sum256(msg)

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, msgHash[:], nil)
	require.NoError(t, err)

	// Parse DER signature to get R and S
	r, s, err := types.ParseDERSignature(sigDER)
	require.NoError(t, err)

	// Verify signature outside circuit first
	valid := ecdsa.Verify(&privKey.PublicKey, msgHash[:], r, s)
	require.True(t, valid, "signature should be valid")

	// Create circuit
	var circuit P256ProofCircuit

	// Create witness
	witness := P256ProofCircuit{
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		MsgH: ToU8Array32(msgHash[:]),
	}

	// Test that the circuit is satisfied
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	t.Logf("P256 signature verification circuit test passed")
	t.Logf("MsgHash: %x", msgHash)
}

func TestP256ProofCircuit_InvalidSignature(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create message and hash it
	msg := []byte("test message")
	msgHash := sha256.Sum256(msg)

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, msgHash[:], nil)
	require.NoError(t, err)

	// Parse DER signature to get R and S
	r, s, err := types.ParseDERSignature(sigDER)
	require.NoError(t, err)

	// Modify S to make signature invalid
	invalidS := new(big.Int).Add(s, big.NewInt(1))

	// Create circuit
	var circuit P256ProofCircuit

	// Create witness with invalid signature
	witness := P256ProofCircuit{
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](invalidS), // Invalid!
		},
		MsgH: ToU8Array32(msgHash[:]),
	}

	// Test that the circuit FAILS with invalid signature
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "circuit should fail with invalid signature")

	t.Logf("Invalid signature correctly rejected")
}

func TestP256ProofCircuit_WrongHash(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create message and hash it
	msg := []byte("original message")
	msgHash := sha256.Sum256(msg)

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, msgHash[:], nil)
	require.NoError(t, err)

	// Parse DER signature to get R and S
	r, s, err := types.ParseDERSignature(sigDER)
	require.NoError(t, err)

	// Use a different hash in the witness
	wrongMsg := []byte("different message")
	wrongHash := sha256.Sum256(wrongMsg)

	// Create circuit
	var circuit P256ProofCircuit

	// Create witness with wrong hash
	witness := P256ProofCircuit{
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		MsgH: ToU8Array32(wrongHash[:]), // Wrong hash!
	}

	// Test that the circuit FAILS with wrong hash
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "circuit should fail with wrong message hash")

	t.Logf("Wrong hash correctly rejected")
}

func TestP256ProofCircuit_Setup_Groth16(t *testing.T) {
	rootDir, _ := zkTypes.ProjectRoot()
	var c P256ProofCircuit
	_, _, _ = LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &c)
}

func TestP256ProofCircuit_Setup_Plonk(t *testing.T) {
	rootDir, _ := zkTypes.ProjectRoot()
	var c P256ProofCircuit
	_, _, _ = LoadOrSetupCircuit_Plonk(filepath.Join(rootDir, ".build"), &c)
}

func TestP256ProofCircuit_Compile(t *testing.T) {
	var circuit P256ProofCircuit

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
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
