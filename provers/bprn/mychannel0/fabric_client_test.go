package mychannel0

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/kysee/zk-chains/provers/bprn"
	"github.com/stretchr/testify/require"
)

func TestBlock(t *testing.T) {
	client, err := bprn.NewFabricClient("./connection-profile.json")
	require.NoError(t, err)

	block, err := client.GetBlockByNumber("mychannel0", "User1", "peerOrg1", 1)
	require.NoError(t, err)

	jsonBlock, err := json.MarshalIndent(block, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(jsonBlock))
}
