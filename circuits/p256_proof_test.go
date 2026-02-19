package circuits

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	ecdsaCircuit "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/kysee/zk-chains/provers/types"
	zkTypes "github.com/kysee/zk-chains/types"
	"github.com/stretchr/testify/require"
)

func TestP256ProofCircuit(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create message and hash it
	msgH := sha256.Sum256([]byte("target message"))

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, msgH[:], nil)
	require.NoError(t, err)

	// Parse DER signature to get R and S
	r, s, err := types.ParseDERSignature(sigDER)
	require.NoError(t, err)

	// Verify signature outside circuit first
	valid := ecdsa.Verify(&privKey.PublicKey, msgH[:], r, s)
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
		MsgH: ToU8Array32(msgH[:]),
	}

	// Test that the circuit is satisfied
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	t.Logf("P256 signature verification circuit test passed")
}

func TestP256ProofCircuit_InvalidSignature(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create message and hash it
	msgH := sha256.Sum256([]byte("target message"))

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, msgH[:], nil)
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
		MsgH: ToU8Array32(msgH[:]),
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
	msgH := sha256.Sum256([]byte("target message"))

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, msgH[:], nil)
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

func TestP256ProofCircuit_ProveAndVerify(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create message and hash it
	msgH := sha256.Sum256([]byte("target message"))

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, msgH[:], nil)
	require.NoError(t, err)

	// Parse DER signature to get R and S
	r, s, err := types.ParseDERSignature(sigDER)
	require.NoError(t, err)

	// Verify signature outside circuit first
	valid := ecdsa.Verify(&privKey.PublicKey, msgH[:], r, s)
	require.True(t, valid, "signature should be valid")

	// Create circuit
	rootDir, _ := zkTypes.ProjectRoot()
	ccs, pk, vk := LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &P256ProofCircuit{})

	// Create witness
	assignment := &P256ProofCircuit{
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		MsgH: ToU8Array32(msgH[:]),
	}

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err, "Failed to create witness")

	// Prove using pre-compiled circuit and keys
	fmt.Println("Proving...")

	start := time.Now()
	proof, err := groth16.Prove(ccs, pk, fullWitness)
	require.NoError(t, err, "Proof generation failed")
	fmt.Println("Proof generation time:", time.Since(start))

	// Extract public inputs for verification
	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	require.NoError(t, err, "Failed to create public witness")

	// Verify proof using pre-compiled verifying key
	fmt.Println("Verifying...")
	start = time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	require.NoError(t, err, "Proof verification failed")
	fmt.Println("Verify time:", time.Since(start))
}

func TestP256ProofCircuit_Setup_Groth16(t *testing.T) {
	rootDir, _ := zkTypes.ProjectRoot()
	var c P256ProofCircuit
	_, _, _ = LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &c)
}

//func TestP256ProofCircuit_Setup_Plonk(t *testing.T) {
//	rootDir, _ := zkTypes.ProjectRoot()
//	var c P256ProofCircuit
//	_, _, _ = LoadOrSetupCircuit_Plonk(filepath.Join(rootDir, ".build"), &c)
//}
