package event

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var evtPayload EventPayload

func init() {
	for i := 0; i < 11; i++ {
		evtValue := NewPostMessageEventLogValueWith(
			fmt.Sprintf("srcChainId-%d", i),
			fmt.Sprintf("srcDappId-%d", i),
			fmt.Sprintf("srcAcctId-%d", i),
			fmt.Sprintf("dstChainId-%d", i),
			fmt.Sprintf("dstDappId-%d", i),
			fmt.Sprintf("dstAcctId-%d", i),
			uint64(i*100),
			[]byte(fmt.Sprintf("hello world-%d", i)),
		)

		evtPayload.Logs = append(evtPayload.Logs, &EventLog{
			Type:  "PostMessageEventLogValue",
			Value: evtValue,
		})
	}
}

func TestMerkle_PoostMessageEventLogValue(t *testing.T) {
	evtPayloadRoot, err := evtPayload.Root()
	require.NoError(t, err)
	fmt.Printf("evtPayloadRoot: %x\n", evtPayloadRoot)

	for i, evtLog := range evtPayload.Logs {
		logProofHashes, err := evtPayload.Proof(i)
		logRoot, err := evtLog.Root()
		require.NoError(t, err)
		fmt.Println("======================================================")
		fmt.Printf("EventLog[%d].Value root: %x\n", i, logRoot)

		ret, err := Verify(i, logRoot, logProofHashes, evtPayloadRoot)
		require.NoError(t, err)
		require.True(t, ret)

		leaves := evtLog.Leaves()

		for idx, leaf := range leaves {

			proofHashes, err := evtLog.Proof(idx)
			require.NoError(t, err)

			fmt.Println("---")
			fmt.Printf("leaf[%d]: %s, %x\n", idx, leaf, sha256.Sum256(leaf))
			for i, proofHash := range proofHashes {
				fmt.Printf("proofHashes[%d]: %x\n", i, proofHash)
			}

			ret, err := Verify(idx, evtLog.Leaves()[idx], proofHashes, logRoot)
			require.NoError(t, err)
			require.True(t, ret)
		}

	}

}
