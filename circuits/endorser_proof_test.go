package circuits

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	ecdsaCircuit "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/kysee/zk-chains/provers/types"
	zkTypes "github.com/kysee/zk-chains/types"
	"github.com/stretchr/testify/require"
)

// sha256PadMessage pads a message according to SHA256 padding rules.
func sha256PadMessage(msg []byte) []byte {
	msgLen := len(msg)
	paddedLen := ((msgLen + 9 + 63) / 64) * 64
	padded := make([]byte, paddedLen)
	copy(padded, msg)
	padded[msgLen] = 0x80
	binary.BigEndian.PutUint64(padded[paddedLen-8:], uint64(msgLen)*8)
	return padded
}

func newEndorserProofWitness(
	certBytes []byte,
	certLength int,
	privKey *ecdsa.PrivateKey,
	ouOffset, ouLength int,
	ouData []byte,
	pubkOffset int,
	pubkData []byte,
) EndorserProofCircuit {
	// SHA256 pad the cert
	paddedCert := sha256PadMessage(certBytes)
	var certU8 [MaxMsgSize]uints.U8
	for i := 0; i < MaxMsgSize; i++ {
		if i < len(paddedCert) {
			certU8[i] = uints.NewU8(paddedCert[i])
		} else {
			certU8[i] = uints.NewU8(0)
		}
	}

	// Compute SHA256 and sign
	certHash := sha256.Sum256(certBytes)
	sigDER, err := privKey.Sign(rand.Reader, certHash[:], nil)
	if err != nil {
		panic(err)
	}
	r, s, err := types.ParseDERSignature(sigDER)
	if err != nil {
		panic(err)
	}

	// OU bytes
	var ouBytes [32]uints.U8
	for i := 0; i < 32; i++ {
		if i < len(ouData) {
			ouBytes[i] = uints.NewU8(ouData[i])
		} else {
			ouBytes[i] = uints.NewU8(0)
		}
	}

	// PubK bytes
	var pubkBytes [32]uints.U8
	for i := 0; i < 32; i++ {
		if i < len(pubkData) {
			pubkBytes[i] = uints.NewU8(pubkData[i])
		} else {
			pubkBytes[i] = uints.NewU8(0)
		}
	}

	return EndorserProofCircuit{
		CertBytes: certU8,
		CertLen:   certLength,
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		RootPubK: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		OUIdx:      ouOffset,
		OULen:      ouLength,
		PubKOffset: pubkOffset,
		OUBytes:    ouBytes,
		PubKBytes:  pubkBytes,
	}
}

// buildCertData builds a fake cert byte array with OU and PubK at specified positions.
func buildCertData(ouOffset int, ouData []byte, pubkOffset int, pubkData []byte, totalLen int) []byte {
	cert := make([]byte, totalLen)
	rand.Read(cert)
	copy(cert[ouOffset:], ouData)
	copy(cert[pubkOffset:], pubkData)
	return cert
}

func TestEndorserProofCircuit(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ouData := []byte("org-unit-name")
	pubkData := make([]byte, 32)
	rand.Read(pubkData)

	ouOffset := 50
	pubkOffset := 200
	certLen := 400

	cert := buildCertData(ouOffset, ouData, pubkOffset, pubkData, certLen)

	var circuit EndorserProofCircuit
	witness := newEndorserProofWitness(cert, certLen, privKey, ouOffset, len(ouData), ouData, pubkOffset, pubkData)

	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	t.Logf("Endorser proof circuit test passed")
}

func TestEndorserProofCircuit_WrongOU(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ouData := []byte("org-unit-name")
	pubkData := make([]byte, 32)
	rand.Read(pubkData)

	ouOffset := 50
	pubkOffset := 200
	certLen := 400

	cert := buildCertData(ouOffset, ouData, pubkOffset, pubkData, certLen)

	// Use wrong OU data
	wrongOU := []byte("wrong-ou-name")
	witness := newEndorserProofWitness(cert, certLen, privKey, ouOffset, len(wrongOU), wrongOU, pubkOffset, pubkData)

	var circuit EndorserProofCircuit
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "circuit should fail with wrong OU")

	t.Logf("Wrong OU correctly rejected")
}

func TestEndorserProofCircuit_WrongPubK(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ouData := []byte("org-unit-name")
	pubkData := make([]byte, 32)
	rand.Read(pubkData)

	ouOffset := 50
	pubkOffset := 200
	certLen := 400

	cert := buildCertData(ouOffset, ouData, pubkOffset, pubkData, certLen)

	// Use wrong PubK data
	wrongPubK := make([]byte, 32)
	rand.Read(wrongPubK)
	witness := newEndorserProofWitness(cert, certLen, privKey, ouOffset, len(ouData), ouData, pubkOffset, wrongPubK)

	var circuit EndorserProofCircuit
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "circuit should fail with wrong PubK")

	t.Logf("Wrong PubK correctly rejected")
}

func TestEndorserProofCircuit_InvalidSignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ouData := []byte("org-unit-name")
	pubkData := make([]byte, 32)
	rand.Read(pubkData)

	ouOffset := 50
	pubkOffset := 200
	certLen := 400

	cert := buildCertData(ouOffset, ouData, pubkOffset, pubkData, certLen)

	// Create valid witness then tamper with signature
	witness := newEndorserProofWitness(cert, certLen, privKey, ouOffset, len(ouData), ouData, pubkOffset, pubkData)

	// Invalidate S
	witness.Sig.S = emulated.ValueOf[emulated.P256Fr](new(big.Int).SetInt64(12345))

	var circuit EndorserProofCircuit
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "circuit should fail with invalid signature")

	t.Logf("Invalid signature correctly rejected")
}

func TestEndorserProofCircuit_ProveAndVerify(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ouData := []byte("org-unit-name")
	pubkData := make([]byte, 32)
	rand.Read(pubkData)

	ouOffset := 50
	pubkOffset := 200
	certLen := 400

	cert := buildCertData(ouOffset, ouData, pubkOffset, pubkData, certLen)

	// Setup circuit
	rootDir, _ := zkTypes.ProjectRoot()
	ccs, pk, vk := LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &EndorserProofCircuit{})

	// Create witness
	assignment := newEndorserProofWitness(cert, certLen, privKey, ouOffset, len(ouData), ouData, pubkOffset, pubkData)

	fullWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	require.NoError(t, err, "Failed to create witness")

	// Prove
	fmt.Println("Proving...")
	start := time.Now()
	proof, err := groth16.Prove(ccs, pk, fullWitness)
	require.NoError(t, err, "Proof generation failed")
	fmt.Println("Proof generation time:", time.Since(start))

	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	require.True(t, ok, "proof does not implement MarshalSolidity()")

	proofSolidity := _proof.MarshalSolidity()
	fmt.Println("proofSolidity length:", len(proofSolidity))

	// Verify
	publicWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	require.NoError(t, err, "Failed to create public witness")

	fmt.Println("Verifying...")
	start = time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	require.NoError(t, err, "Proof verification failed")
	fmt.Println("Verify time:", time.Since(start))
}

func TestEndorserProofCircuit_Setup_Groth16(t *testing.T) {
	rootDir, _ := zkTypes.ProjectRoot()
	var c EndorserProofCircuit
	_, _, _ = LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &c)
}
