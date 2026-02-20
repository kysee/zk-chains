package circuits

import (
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"testing"

	bprnevt "github.com/beatoz/chaincode-base/event"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	zkTypes "github.com/kysee/zk-chains/types"
	"github.com/stretchr/testify/require"
)

var evtLogSet bprnevt.EventLogSet
var logIdx, leafIdx int

func init() {
	bprnevt.RegisterEventLogValueType((*bprnevt.PostMessageEventLogValue)(nil))

	for i := 0; i < 11; i++ {
		logVal := &bprnevt.PostMessageEventLogValue{
			SrcChainId: fmt.Sprintf("srcChainId-%d", i),
			SrcDappId:  fmt.Sprintf("srcDappId-%d", i),
			SrcAcctId:  fmt.Sprintf("srcAcctId-%d", i),
			DstChainId: fmt.Sprintf("dstChainId-%d", i),
			DstDappId:  fmt.Sprintf("dstDappId-%d", i),
			DstAcctId:  fmt.Sprintf("dstAcctId-%d", i),
			MsgIdx:     uint64(i * 100),
			MsgPayload: []byte(fmt.Sprintf("hello world-%d", i)),
		}
		evtLogSet = append(evtLogSet, bprnevt.NewEventLog(logVal))
	}

	logIdx = rand.IntN(len(evtLogSet))
	leafIdx = rand.IntN(8)
}

func TestBPrNEventProof_Setup_Groth16(t *testing.T) {
	rootDir, _ := zkTypes.ProjectRoot()
	var c BPrNEventProofCircuit
	_, _, _ = LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &c)
}

func TestBPrNEventProof(t *testing.T) {
	witness := buildValidWitness(t, logIdx, leafIdx)

	var circuit BPrNEventProofCircuit
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	require.NoError(t, err)

	t.Logf("BPrNEventProofCircuit test passed (logIdx=%d, leafIdx=%d)", logIdx, leafIdx)
}

func TestBPrNEventProof_WrongLeafHash(t *testing.T) {
	witness := buildValidWitness(t, logIdx, leafIdx)

	// Tamper LeafHash: flip a byte
	witness.LeafHash[0] = uints.NewU8(witness.LeafHash[0].Val.(uint8) ^ 0xff)

	var circuit BPrNEventProofCircuit
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	require.Error(t, err, "circuit should not be satisfied with wrong LeafHash")
	t.Log("correctly rejected wrong LeafHash")
}

func TestBPrNEventProof_WrongLogSetRoot(t *testing.T) {
	witness := buildValidWitness(t, logIdx, leafIdx)

	// Tamper LogSetRoot: flip a byte
	witness.LogSetRoot[0] = uints.NewU8(witness.LogSetRoot[0].Val.(uint8) ^ 0xff)

	var circuit BPrNEventProofCircuit
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	require.Error(t, err, "circuit should not be satisfied with wrong LogSetRoot")
	t.Log("correctly rejected wrong LogSetRoot")
}

func TestBPrNEventProof_WrongLogRoot(t *testing.T) {
	witness := buildValidWitness(t, logIdx, leafIdx)

	// Use a different EventLog's root as LogRoot
	wrongTree := bprnevt.NewMerkleTreeType(evtLogSet[(logIdx+1)%len(evtLogSet)])
	wrongRoot, err := wrongTree.Root()
	require.NoError(t, err)

	witness.LogRoot = ToU8Array32(wrongRoot)

	var circuit BPrNEventProofCircuit
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	require.Error(t, err, "circuit should not be satisfied with wrong LogRoot")
	t.Log("correctly rejected wrong LogRoot")
}

// buildValidWitness creates a valid BPrNEventProofCircuit witness for the given logIdx and leafIdx.
func buildValidWitness(t *testing.T, logIdx, leafIdx int) BPrNEventProofCircuit {
	t.Helper()

	innerTree := bprnevt.NewMerkleTreeType(evtLogSet[logIdx])
	innerLeaves := evtLogSet[logIdx].Leaves()
	leafHash := sha256.Sum256(innerLeaves[leafIdx])

	innerProof, err := innerTree.Proof(leafIdx)
	require.NoError(t, err)

	logRoot, err := innerTree.Root()
	require.NoError(t, err)

	outerTree := bprnevt.NewMerkleTreeType(evtLogSet)
	outerProof, err := outerTree.Proof(logIdx)
	require.NoError(t, err)

	logSetRoot, err := outerTree.Root()
	require.NoError(t, err)

	witness := BPrNEventProofCircuit{
		LeafIdx:    leafIdx,
		LeafHash:   ToU8Array32(leafHash[:]),
		LogRoot:    ToU8Array32(logRoot),
		LogRootIdx: logIdx,
		LogSetRoot: ToU8Array32(logSetRoot),
	}
	for i := 0; i < MaxMerkleDepth && i < len(innerProof); i++ {
		witness.Siblings[i] = ToU8Array32(innerProof[i])
	}
	for i := 0; i < MaxMerkleDepth && i < len(outerProof); i++ {
		witness.LogRootSiblings[i] = ToU8Array32(outerProof[i])
	}
	return witness
}
