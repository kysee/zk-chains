package circuit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	ecdsaCircuit "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func TestBPrNTxProofCircuit_P256(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Transaction data: T0 + InternalBytes + T1
	t0Data := []byte("prefix_")
	internalData := []byte("important_event_data")

	// Pad internalData to InternalBytesSize (256)
	internalDataPadded := make([]byte, InternalBytesSize)
	copy(internalDataPadded, internalData)

	t1Data := []byte("_suffix_padding")
	txData := append(append(t0Data, internalDataPadded...), t1Data...)

	// Hash the transaction data with SHA256
	txHash := sha256.Sum256(txData)

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, txHash[:], nil)
	require.NoError(t, err)

	// Parse DER signature to get R and S
	r, s := parseDERSignature(t, sigDER)

	// Verify signature outside circuit first
	valid := ecdsa.Verify(&privKey.PublicKey, txHash[:], r, s)
	require.True(t, valid, "signature should be valid")

	// Create circuit with fixed lengths (zero values are fine for definition)
	var circuit BPrNTxProofCircuit

	// Create witness
	witness := BPrNTxProofCircuit{
		TxLimbs:        toTxLimbs(txData),
		TxLen:          len(txData),
		InternalOffset: len(t0Data),
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		InternalBytes: toInternalBytesArray(internalDataPadded),
	}

	// Test that the circuit is satisfied
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	t.Logf("P256 ECDSA signature verification circuit test passed")
	t.Logf("Tx length: %d bytes", len(txData))
	t.Logf("InternalOffset: %d", len(t0Data))
	t.Logf("TxHash: %x", txHash)
}

func TestBPrNTxProofCircuit_WrongInternalBytes(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Correct transaction data
	t0Data := []byte("prefix_")
	internalData := []byte("correct_data")

	// Pad internalData to InternalBytesSize (256)
	internalDataPadded := make([]byte, InternalBytesSize)
	copy(internalDataPadded, internalData)

	t1Data := []byte("_suffix")
	txData := append(append(t0Data, internalDataPadded...), t1Data...)

	// Wrong internal data (different from what's in txData)
	wrongInternalData := []byte("wrong_data!!")
	wrongInternalDataPadded := make([]byte, InternalBytesSize)
	copy(wrongInternalDataPadded, wrongInternalData)

	txHash := sha256.Sum256(txData)

	sigDER, err := privKey.Sign(rand.Reader, txHash[:], nil)
	require.NoError(t, err)

	r, s := parseDERSignature(t, sigDER)

	var circuit BPrNTxProofCircuit

	witness := BPrNTxProofCircuit{
		TxLimbs:        toTxLimbs(txData),
		TxLen:          len(txData),
		InternalOffset: len(t0Data),
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		InternalBytes: toInternalBytesArray(wrongInternalDataPadded), // Wrong!
	}

	// Test that the circuit FAILS when InternalBytes doesn't match
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "circuit should fail when InternalBytes doesn't match")

	t.Logf("Wrong InternalBytes - correctly rejected")
}

func TestBPrNTxProofCircuit_InvalidSignature(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t0Data := []byte("tx_")
	internalData := []byte("event")

	// Pad internalData to InternalBytesSize (256)
	internalDataPadded := make([]byte, InternalBytesSize)
	copy(internalDataPadded, internalData)

	t1Data := []byte("_data")
	txData := append(append(t0Data, internalDataPadded...), t1Data...)

	txHash := sha256.Sum256(txData)

	sigDER, err := privKey.Sign(rand.Reader, txHash[:], nil)
	require.NoError(t, err)

	r, s := parseDERSignature(t, sigDER)

	// Modify S to make signature invalid
	invalidS := new(big.Int).Add(s, big.NewInt(1))

	var circuit BPrNTxProofCircuit

	witness := BPrNTxProofCircuit{
		TxLimbs:        toTxLimbs(txData),
		TxLen:          len(txData),
		InternalOffset: len(t0Data),
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](invalidS), // Invalid!
		},
		InternalBytes: toInternalBytesArray(internalDataPadded),
	}

	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "circuit should fail with invalid signature")

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
	t.Logf("InternalBytes size: %d bytes", InternalBytesSize)
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

// parseDERSignature parses a DER-encoded ECDSA signature
func parseDERSignature(t *testing.T, sigDER []byte) (*big.Int, *big.Int) {
	var (
		r, s  = new(big.Int), new(big.Int)
		inner cryptobyte.String
	)
	input := cryptobyte.String(sigDER)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		t.Fatal("invalid DER signature")
	}
	return r, s
}

// Helper functions to create arrays from slices

func toTxLimbs(data []byte) [TxLimbSize]frontend.Variable {
	var res [TxLimbSize]frontend.Variable

	// Pad data to multiple of 8
	paddedLen := (len(data) + 7) / 8 * 8
	paddedData := make([]byte, paddedLen)
	copy(paddedData, data)

	for i := 0; i < TxLimbSize; i++ {
		if i*8 >= len(paddedData) {
			res[i] = 0
			continue
		}
		// Little Endian packing
		limbBytes := paddedData[i*8 : i*8+8]
		res[i] = binary.LittleEndian.Uint64(limbBytes)
	}
	return res
}

func toInternalBytesArray(data []byte) [InternalBytesSize]uints.U8 {
	var res [InternalBytesSize]uints.U8
	for i, b := range data {
		if i >= InternalBytesSize {
			break
		}
		res[i] = uints.NewU8(b)
	}
	for i := len(data); i < InternalBytesSize; i++ {
		res[i] = uints.NewU8(0)
	}
	return res
}
