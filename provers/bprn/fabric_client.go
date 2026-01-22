package bprn

import (
	"encoding/json"
	"fmt"
	"os"

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
	// Read and parse the config file manually to fix potential issues
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(content, &configMap); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Fix: 'clients' array to 'client' object if 'client' is missing
	// Some profiles use 'clients' array, but the SDK expects 'client' object
	if _, ok := configMap["client"]; !ok {
		if clients, ok := configMap["clients"].([]interface{}); ok && len(clients) > 0 {
			configMap["client"] = clients[0]
		}
	}

	// Fix: Remove 'OrdererOrg' from organizations if it lacks required fields (mspid, cryptoPath)
	// This prevents "failed to initialize identity manager" error for OrdererOrg
	if orgs, ok := configMap["organizations"].(map[string]interface{}); ok {
		if _, ok := orgs["OrdererOrg"]; ok {
			delete(orgs, "OrdererOrg")
		}
	}

	// Fix: Add users to organizations from clients array
	if clients, ok := configMap["clients"].([]interface{}); ok {
		if orgs, ok := configMap["organizations"].(map[string]interface{}); ok {
			for _, clientInterface := range clients {
				client, ok := clientInterface.(map[string]interface{})
				if !ok {
					continue
				}

				// Find the corresponding organization
				for orgName, orgInterface := range orgs {
					org, ok := orgInterface.(map[string]interface{})
					if !ok {
						continue
					}

					// Check if this client belongs to this organization
					clientMspId, _ := client["mspId"].(string)
					orgMspId, _ := org["mspid"].(string)
					if clientMspId == orgMspId {
						// Extract user information
						userId, _ := client["id"].(string)
						privateKeyPath, _ := client["privateKeyPath"].(string)
						signedCertPath, _ := client["signedCertPath"].(string)

						// Parse username from id (e.g., "User1@org1.example.com" -> "User1")
						username := userId
						if atIndex := len(userId); atIndex > 0 {
							for i, c := range userId {
								if c == '@' {
									username = userId[:i]
									break
								}
							}
						}

						// Add users map if it doesn't exist
						if _, ok := org["users"]; !ok {
							org["users"] = make(map[string]interface{})
						}

						users := org["users"].(map[string]interface{})
						users[username] = map[string]interface{}{
							"cert": map[string]interface{}{
								"path": signedCertPath,
							},
							"key": map[string]interface{}{
								"path": privateKeyPath,
							},
						}

						orgs[orgName] = org
					}
				}
			}
		}
	}

	modifiedConfig, err := json.Marshal(configMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal modified config: %w", err)
	}

	configProvider := config.FromRaw(modifiedConfig, "json")
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
