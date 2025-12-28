package relayer

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kysee/zk-chains/types"
)

// FileFetcher implements Fetcher by reading from a local JSON file
type FileFetcher struct {
	FilePath string
}

// NewFileFetcher creates a new FileFetcher with the given file path
func NewFileFetcher(filePath string) *FileFetcher {
	return &FileFetcher{
		FilePath: filePath,
	}
}

// FetchUpdate reads and parses the light client update from the file
func (f *FileFetcher) FetchUpdate(period uint64) (*types.LightClientUpdate, error) {
	// Read the file
	data, err := os.ReadFile(f.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", f.FilePath, err)
	}

	// Parse JSON
	var update types.LightClientUpdate
	if err := json.Unmarshal(data, &update); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &update, nil
}
