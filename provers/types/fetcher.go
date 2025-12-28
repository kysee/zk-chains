package types

import (
	"github.com/kysee/zk-chains/types"
	"github.com/protolambda/zrnt/eth2/beacon/electra"
)

// ScUpdateAPIResponse represents the Beacon API response structure
type ScUpdateAPIResponse = []types.LightClientUpdate

// BlockAPIResponse represents the Beacon API v2 response for blocks
type BlockAPIResponse struct {
	Version             string                    `json:"version"`
	ExecutionOptimistic bool                      `json:"execution_optimistic"`
	Finalized           bool                      `json:"finalized"`
	Data                electra.SignedBeaconBlock `json:"data"`
}

// Fetcher defines the interface for fetching light client update data
type Fetcher interface {
	// FetchUpdate retrieves a light client update
	ScUpdate(period uint64) (*types.LightClientUpdate, error)
	Block(slot uint64) (*BlockAPIResponse, error)
}
