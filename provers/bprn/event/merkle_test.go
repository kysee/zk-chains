package event

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var evtPayload *EventPayload

func init() {
	evtLogs := make([]*EventLog, 11)
	for i := 0; i < len(evtLogs); i++ {
		evtLogValue := NewPostMessageEventLogValueWith(
			fmt.Sprintf("srcChainId-%d", i),
			fmt.Sprintf("srcDappId-%d", i),
			fmt.Sprintf("srcAcctId-%d", i),
			fmt.Sprintf("dstChainId-%d", i),
			fmt.Sprintf("dstDappId-%d", i),
			fmt.Sprintf("dstAcctId-%d", i),
			uint64(i*100),
			[]byte(fmt.Sprintf("hello world-%d", i)),
		)

		evtLogs[i] = &EventLog{
			Type:  "PostMessageEventLogValue",
			Value: evtLogValue,
		}
	}

	evtPayload = NewEventPayload(evtLogs...)
}

func TestMerkle_PoostMessageEventLogValue(t *testing.T) {
	evtPayloadRoot, err := evtPayload.Root()
	require.NoError(t, err)
	fmt.Printf("evtPayloadRoot: %x\n", evtPayloadRoot)

	for i, evtLog := range evtPayload.Logs {
		logRoot, err := evtLog.Root()
		logProofHashes, err := evtPayload.Proof(i)
		require.NoError(t, err)
		fmt.Println("======================================================")
		fmt.Printf("EventLog[%d].Value root: %x\n", i, logRoot)

		ret, err := Verify(i, logRoot, logProofHashes, evtPayloadRoot)
		require.NoError(t, err)
		require.True(t, ret)

		leaf := sha256.Sum256(logRoot[:])
		require.True(t, localVerify(i, leaf[:], logProofHashes, evtPayloadRoot))

		elems, err := evtLog.Leaves()
		require.NoError(t, err)

		for idx, elem := range elems {
			elemProofHashes, err := evtLog.Proof(idx)
			require.NoError(t, err)

			fmt.Println("---")
			fmt.Printf("elem[%d]: %s, %x\n", idx, elem, sha256.Sum256(elem))
			for i, proofHash := range elemProofHashes {
				fmt.Printf("proofHashes[%d]: %x\n", i, proofHash)
			}

			require.NoError(t, err)
			ret, err := Verify(idx, elem, elemProofHashes, logRoot)
			require.NoError(t, err)
			require.True(t, ret)

			leafH := sha256.Sum256(elem)
			require.True(t, localVerify(idx, leafH[:], elemProofHashes, logRoot))
		}

	}
}

func localVerify(idx int, leafHash []byte, proofHashes [][]byte, root []byte) bool {
	index := uint64(idx) + (1 << uint(len(proofHashes)))
	computed := [32]byte(leafHash)

	for _, proofHash := range proofHashes {
		if index%2 == 0 {
			computed = sha256.Sum256(append(computed[:], proofHash[:]...))
		} else {
			computed = sha256.Sum256(append(proofHash[:], computed[:]...))
		}
		index >>= 1
	}
	return bytes.Equal(computed[:], root)
}
