package circuits

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
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
	"github.com/stretchr/testify/require"
)

func TestBPrNTxProofCircuit_P256(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Transaction data: T0 + InnerBytes + T1
	t0Data := []byte("prefix_")
	internalData := []byte("important_event_data")

	// Pad internalData to InnerBytesSize (256)
	internalDataPadded := make([]byte, InnerBytesSize)
	copy(internalDataPadded, internalData)

	t1Data := []byte("_suffix_padding")
	txData := append(append(t0Data, internalDataPadded...), t1Data...)

	// Hash the transaction data with SHA256
	txHash := sha256.Sum256(txData)

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, txHash[:], nil)
	require.NoError(t, err)

	// Parse DER signature to get R and S
	r, s, err := types.ParseDERSignature(sigDER)
	require.NoError(t, err)

	// Verify signature outside circuits first
	valid := ecdsa.Verify(&privKey.PublicKey, txHash[:], r, s)
	require.True(t, valid, "signature should be valid")

	// Create circuits with fixed lengths (zero values are fine for definition)
	var circuit BPrNTxProofCircuit

	// Create witness
	witness := BPrNTxProofCircuit{
		TxLimbs:     ToLimbs(txData),
		TxLen:       len(txData),
		InnerOffset: len(t0Data),
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		InnerBytes: ToU8Array(internalDataPadded),
	}

	// Test that the circuits is satisfied
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	t.Logf("P256 ECDSA signature verification circuits test passed")
	t.Logf("Tx length: %d bytes", len(txData))
	t.Logf("InnerOffset: %d", len(t0Data))
	t.Logf("TxHash: %x", txHash)
}

func TestBPrNTxProofCircuit_WrongInternalBytes(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Correct transaction data
	t0Data := []byte("prefix_")
	internalData := []byte("correct_data")

	// Pad internalData to InnerBytesSize (256)
	internalDataPadded := make([]byte, InnerBytesSize)
	copy(internalDataPadded, internalData)

	t1Data := []byte("_suffix")
	txData := append(append(t0Data, internalDataPadded...), t1Data...)

	// Wrong internal data (different from what's in txData)
	wrongInternalData := []byte("wrong_data!!")
	wrongInternalDataPadded := make([]byte, InnerBytesSize)
	copy(wrongInternalDataPadded, wrongInternalData)

	txHash := sha256.Sum256(txData)

	sigDER, err := privKey.Sign(rand.Reader, txHash[:], nil)
	require.NoError(t, err)

	r, s, err := types.ParseDERSignature(sigDER)
	require.NoError(t, err)

	var circuit BPrNTxProofCircuit

	witness := BPrNTxProofCircuit{
		TxLimbs:     ToLimbs(txData),
		TxLen:       len(txData),
		InnerOffset: len(t0Data),
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		InnerBytes: ToU8Array(wrongInternalDataPadded), // Wrong!
	}

	// Test that the circuits FAILS when InnerBytes doesn't match
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "circuits should fail when InnerBytes doesn't match")

	t.Logf("Wrong InnerBytes - correctly rejected")
}

func TestBPrNTxProofCircuit_InvalidSignature(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t0Data := []byte("tx_")
	internalData := []byte("event")

	// Pad internalData to InnerBytesSize (256)
	internalDataPadded := make([]byte, InnerBytesSize)
	copy(internalDataPadded, internalData)

	t1Data := []byte("_data")
	txData := append(append(t0Data, internalDataPadded...), t1Data...)

	txHash := sha256.Sum256(txData)

	sigDER, err := privKey.Sign(rand.Reader, txHash[:], nil)
	require.NoError(t, err)

	r, s, err := types.ParseDERSignature(sigDER)
	require.NoError(t, err)

	// Modify S to make signature invalid
	invalidS := new(big.Int).Add(s, big.NewInt(1))

	var circuit BPrNTxProofCircuit

	witness := BPrNTxProofCircuit{
		TxLimbs:     ToLimbs(txData),
		TxLen:       len(txData),
		InnerOffset: len(t0Data),
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](invalidS), // Invalid!
		},
		InnerBytes: ToU8Array(internalDataPadded),
	}

	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "circuits should fail with invalid signature")

	t.Logf("Invalid signature correctly rejected")
}

func TestBPrNTxProofCircuit_Compile(t *testing.T) {
	// Test compilation with default sizes
	var circuit BPrNTxProofCircuit

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	require.NoError(t, err)

	t.Logf("Circuit compiled successfully")
	t.Logf("Tx max size: %d bytes", TxMaxSize)
	t.Logf("Tx limb size: %d limbs", TxLimbSize)
	t.Logf("InnerBytes size: %d bytes", InnerBytesSize)
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
