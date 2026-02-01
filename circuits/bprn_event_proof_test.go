package circuits

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	mrand "math/rand"
	"path/filepath"
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
	bprnEvent "github.com/kysee/zk-chains/provers/bprn/event"
	proverTypes "github.com/kysee/zk-chains/provers/types"
	types2 "github.com/kysee/zk-chains/types"
	"github.com/stretchr/testify/require"
)

var evtPayload *bprnEvent.EventPayload

func init() {
	evtLogs := make([]*bprnEvent.EventLog, 11)
	for i := 0; i < len(evtLogs); i++ {
		evtLogValue := bprnEvent.NewPostMessageEventLogValueWith(
			fmt.Sprintf("srcChainId-%d", i),
			fmt.Sprintf("srcDappId-%d", i),
			fmt.Sprintf("srcAcctId-%d", i),
			fmt.Sprintf("dstChainId-%d", i),
			fmt.Sprintf("dstDappId-%d", i),
			fmt.Sprintf("dstAcctId-%d", i),
			uint64(i*100),
			[]byte(fmt.Sprintf("hello world-%d", i)),
		)

		evtLogs[i] = &bprnEvent.EventLog{
			Type:  "PostMessageEventLogValue",
			Value: evtLogValue,
		}
	}

	evtPayload = bprnEvent.NewEventPayload(evtLogs...)
}

func TestBPrNEventProofCircuit_P256(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Prepare data
	originPayloadH := sha256.Sum256([]byte("any_random_bytes"))
	eventPayloadH, err := evtPayload.Root()
	require.NoError(t, err)

	evtLogIdx := mrand.Intn(len(evtPayload.Logs))
	evtLog := evtPayload.Logs[evtLogIdx]
	evtLogRoot, err := evtLog.Root()
	require.NoError(t, err)
	evtLogRootH := sha256.Sum256(evtLogRoot[:])
	evtLogRootBranches, err := evtPayload.Proof(evtLogIdx)
	require.NoError(t, err)

	require.True(t, MerkleVerify(evtLogIdx, evtLogRootH[:], evtLogRootBranches, eventPayloadH))

	elems, _ := evtLog.Leaves()
	elemIdx := mrand.Intn(len(elems))
	evtElemH := sha256.Sum256(elems[elemIdx])
	evtElemBranches, err := evtLog.Proof(elemIdx)

	require.True(t, MerkleVerify(elemIdx, evtElemH[:], evtElemBranches, evtLogRoot))

	// Concatenate OriginPayloadH and EventPayloadH
	// and hash the concatenated data
	msgh := sha256.Sum256(append(originPayloadH[:], eventPayloadH[:]...))

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, msgh[:], nil)
	require.NoError(t, err)

	// Parse DER signature to get R and S
	r, s, err := proverTypes.ParseDERSignature(sigDER)
	require.NoError(t, err)

	// Verify signature outside circuit first
	valid := ecdsa.Verify(&privKey.PublicKey, msgh[:], r, s)
	require.True(t, valid, "signature should be valid")

	// Create circuit
	var circuit BPrNEventProofCircuit

	// Create witness
	witness := BPrNEventProofCircuit{
		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		OriginPayloadH: ToU8Array32(originPayloadH[:]),
		EventPayloadH:  ToU8Array32(eventPayloadH[:]),
		EventLogIdx:    evtLogIdx,
		EventLogRootBranches: [MaxMerkleDepth][32]uints.U8{
			ToU8Array32(evtLogRootBranches[0]),
			ToU8Array32(evtLogRootBranches[1]),
			ToU8Array32(evtLogRootBranches[2]),
			ToU8Array32(evtLogRootBranches[3]),
		},
		EventLogRoot: ToU8Array32(evtLogRoot[:]),
		EventElemIdx: elemIdx,
		EventElemHBranches: [MaxMerkleDepth][32]uints.U8{
			ToU8Array32(evtElemBranches[0]),
			ToU8Array32(evtElemBranches[1]),
			ToU8Array32(evtElemBranches[2]),
			ToU8Array32(evtElemBranches[3]),
		},
		EventElemH: ToU8Array32(evtElemH[:]),
	}

	// Test that the circuit is satisfied
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	t.Logf("P256 ECDSA signature verification circuit test passed")
	t.Logf("OriginPayloadH: %x", originPayloadH)
	t.Logf("EventPayloadH: %x", eventPayloadH)
	t.Logf("EventLog Index: %v", evtLogIdx)
	t.Logf("EventLog Leaf[%v], %v", elemIdx, string(elems[elemIdx]))
}

func TestBPrNEventProofCircuit_WrongMsgH(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Prepare data
	preMsgH := sha256.Sum256([]byte("premessage_message"))
	msgH := sha256.Sum256([]byte("public_message"))
	wrongMsgH := sha256.Sum256([]byte("wrong_message"))

	// Concatenate OriginPayloadH and EventPayloadH (correct data for signature)
	data := append(preMsgH[:], msgH[:]...)

	// Hash the concatenated data
	hash := sha256.Sum256(data)

	// Sign the hash
	sigDER, err := privKey.Sign(rand.Reader, hash[:], nil)
	require.NoError(t, err)

	r, s, err := proverTypes.ParseDERSignature(sigDER)
	require.NoError(t, err)

	var circuit BPrNEventProofCircuit

	// Create witness with Wrong EventPayloadH
	witness := BPrNEventProofCircuit{
		OriginPayloadH: ToU8Array32(preMsgH[:]),
		EventPayloadH:  ToU8Array32(wrongMsgH[:]), // Wrong!
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
	assert.Error(err, "circuit should fail when EventPayloadH is wrong")

	t.Logf("Wrong EventPayloadH - correctly rejected")
}

func TestBPrNEventProofCircuit_InvalidSignature(t *testing.T) {
	// Generate P256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Prepare data
	preMsgH := sha256.Sum256([]byte("premessage_message"))
	msgH := sha256.Sum256([]byte("public_message"))

	// Concatenate OriginPayloadH and EventPayloadH
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

	var circuit BPrNEventProofCircuit

	// Create witness with invalid signature
	witness := BPrNEventProofCircuit{
		OriginPayloadH: ToU8Array32(preMsgH[:]),
		EventPayloadH:  ToU8Array32(msgH[:]),
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

func TestBPrNEventProofCircuit_Setup_Groth16(t *testing.T) {
	rootDir, _ := types2.ProjectRoot()
	var c BPrNEventProofCircuit
	_, _, _ = LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &c)
}

func TestBPrNEventProofCircuit_Setup_Plonk(t *testing.T) {
	var c BPrNEventProofCircuit

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
