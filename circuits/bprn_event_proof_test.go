package circuits

import (
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"testing"

	bprnevt "github.com/beatoz/bprn-sdk-go/chaincodes/event"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	zkTypes "github.com/kysee/zk-chains/types"
	"github.com/stretchr/testify/require"
)

var evtLog *bprnevt.EventLog
var gidx int

func init() {
	evtLog = bprnevt.NewEventLog("channelId", "chaincodeName", "txId")

	log := &bprnevt.PostMessageEventLog{
		SrcChainId: fmt.Sprintf("srcChainId"),
		SrcDappId:  fmt.Sprintf("srcDappId"),
		SrcAcctId:  fmt.Sprintf("srcAcctId"),
		DstChainId: fmt.Sprintf("dstChainId"),
		DstDappId:  fmt.Sprintf("dstDappId"),
		DstAcctId:  fmt.Sprintf("dstAcctId"),
		MsgIdx:     uint64(123),
		MsgPayload: []byte(fmt.Sprintf("hello world")),
	}
	evtLog.AddLeaves(log)
	gidx = rand.IntN(3 + 8) // 3 header's leaves length + 8 leaf index
}

func TestBPrNEventProof_Setup_Groth16(t *testing.T) {
	rootDir, _ := zkTypes.ProjectRoot()
	var c BPrNEventProofCircuit
	_, _, _ = LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &c)
}

func TestBPrNEventProof(t *testing.T) {
	witness := buildValidWitness(t, gidx)

	var circuit BPrNEventProofCircuit
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	require.NoError(t, err)

	t.Logf("BPrNEventProofCircuit test passed (gidx=%d)", gidx)
}

func TestBPrNEventProof_WrongLeafHash(t *testing.T) {
	witness := buildValidWitness(t, gidx)

	// Tamper EventElemHash: flip a byte
	witness.EventElemHash[0] = uints.NewU8(witness.EventElemHash[0].Val.(uint8) ^ 0xff)

	var circuit BPrNEventProofCircuit
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	require.Error(t, err, "circuit should not be satisfied with wrong EventElemHash")
	t.Log("correctly rejected wrong EventElemHash")
}

func TestBPrNEventProof_WrongRoot(t *testing.T) {
	witness := buildValidWitness(t, gidx)

	// Use a different EventLog's root as EventRoot
	wrongRoot := evtLog.Root()
	wrongRoot[0] ^= 0xff
	witness.EventRoot = ToU8Array32(wrongRoot)

	var circuit BPrNEventProofCircuit
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	require.Error(t, err, "circuit should not be satisfied with wrong EventRoot")
	t.Log("correctly rejected wrong EventRoot")
}

// buildValidWitness creates a valid BPrNEventProofCircuit witness for the given logIdx and gidx.
func buildValidWitness(t *testing.T, gidx int) BPrNEventProofCircuit {
	t.Helper()

	evtLogRoot := evtLog.Root()
	_, siblings, err := evtLog.Proof(gidx)
	require.NoError(t, err)

	elem := evtLog.Leaf(gidx)
	elemHash := sha256.Sum256(elem)

	witness := BPrNEventProofCircuit{
		EventRoot:     ToU8Array32(evtLogRoot),
		EventElemIdx:  gidx,
		EventElemHash: ToU8Array32(elemHash[:]),
	}
	for i := 0; i < MaxMerkleDepth && i < len(siblings); i++ {
		witness.Siblings[i] = ToU8Array32(siblings[i])
	}
	return witness
}
