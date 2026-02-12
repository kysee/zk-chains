package bprn

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	"github.com/stretchr/testify/require"
)

func TestBlock(t *testing.T) {
	client, err := NewFabricClient("./localchannel0/connection-profile.json")
	require.NoError(t, err)

	block, err := client.GetBlockByNumber("bpn", "User1", "peerOrg1", 1,
		ledger.WithTargetEndpoints("peer0.org1.bc"))
	require.NoError(t, err)

	jsonBlock, err := json.MarshalIndent(block, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(jsonBlock))
}
