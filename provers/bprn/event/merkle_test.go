package event

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var evtPayload EventPayload

func init() {
	for i := 0; i < 11; i++ {
		evtValue := &PostMessageEventLogValue{
			SrcChainId: fmt.Sprintf("srcChainId-%d", i),
			SrcDappId:  fmt.Sprintf("srcDappId-%d", i),
			SrcAcctId:  fmt.Sprintf("srcAcctId-%d", i),
			DstChainId: fmt.Sprintf("dstChainId-%d", i),
			DstDappId:  fmt.Sprintf("dstDappId-%d", i),
			DstAcctId:  fmt.Sprintf("dstAcctId-%d", i),
			MsgIdx:     uint64(i * 100),
			MsgPayload: []byte(fmt.Sprintf("hello world-%d", i)),
		}

		jz, err := json.Marshal(evtValue)
		if err != nil {
			panic(err)
		}
		evtPayload.Logs = append(evtPayload.Logs, &EventLog{
			Type:  "PostMessageEventLogValue",
			Value: jz,
		})
	}
}

func TestMerkle_PoostMessageEventLogValue(t *testing.T) {
	evtPayloadRoot, err := evtPayload.Root()
	require.NoError(t, err)
	fmt.Printf("evtPayloadRoot: %x\n", evtPayloadRoot)

	for i, evtLog := range evtPayload.Logs {
		evtLogValue := &PostMessageEventLogValue{}
		require.NoError(t, json.Unmarshal(evtLog.Value, evtLogValue))

		logProofHashes, err := evtPayload.Proof(i)
		logRoot, err := evtLogValue.Root()
		require.NoError(t, err)
		fmt.Println("======================================================")
		fmt.Printf("EventLog[%d].Value root: %x\n", i, logRoot)

		ret, err := Verify(i, logRoot, logProofHashes, evtPayloadRoot)
		require.NoError(t, err)
		require.True(t, ret)

		leaves := evtLogValue.leaves()

		for idx, leaf := range leaves {

			proofHashes, err := evtLogValue.Proof(idx)
			require.NoError(t, err)

			fmt.Println("---")
			fmt.Printf("leaf[%d]: %s, %x\n", idx, leaf, sha256.Sum256(leaf))
			for i, proofHash := range proofHashes {
				fmt.Printf("proofHashes[%d]: %x\n", i, proofHash)
			}

			ret, err := Verify(idx, evtLogValue.leaves()[idx], proofHashes, logRoot)
			require.NoError(t, err)
			require.True(t, ret)
		}

	}

}
