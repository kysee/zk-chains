package bprn

import (
	"fmt"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

// FabricClient handles interactions with a Hyperledger Fabric network
type FabricClient struct {
	sdk *fabsdk.FabricSDK
}

// NewFabricClient creates a new FabricClient instance using the provided connection profile
func NewFabricClient(configPath string) (*FabricClient, error) {
	configProvider := config.FromFile(configPath)
	sdk, err := fabsdk.New(configProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create fabric sdk: %w", err)
	}

	return &FabricClient{sdk: sdk}, nil
}

// Close closes the Fabric SDK connection
func (c *FabricClient) Close() {
	if c.sdk != nil {
		c.sdk.Close()
	}
}

// GetBlockByNumber queries a block by its number from the specified channel
func (c *FabricClient) GetBlockByNumber(channelID string, userName string, orgName string, blockNumber uint64) (*common.Block, error) {
	// Create a ledger client context
	// Note: You might need to adjust WithUser and WithOrg depending on your configuration
	ctxProvider := c.sdk.ChannelContext(channelID, fabsdk.WithUser(userName), fabsdk.WithOrg(orgName))

	ledgerClient, err := ledger.New(ctxProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create ledger client: %w", err)
	}

	// Query the block
	block, err := ledgerClient.QueryBlock(blockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to query block %d: %w", blockNumber, err)
	}

	return block, nil
}

// GetBlockByHash queries a block by its hash from the specified channel
func (c *FabricClient) GetBlockByHash(channelID string, userName string, orgName string, blockHash []byte) (*common.Block, error) {
	ctxProvider := c.sdk.ChannelContext(channelID, fabsdk.WithUser(userName), fabsdk.WithOrg(orgName))

	ledgerClient, err := ledger.New(ctxProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create ledger client: %w", err)
	}

	block, err := ledgerClient.QueryBlockByHash(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to query block by hash: %w", err)
	}

	return block, nil
}
