package relayer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	types2 "github.com/kysee/zk-chains/provers/types"
	"github.com/kysee/zk-chains/types"
)

// APIFetcher implements Fetcher by calling Beacon API REST endpoint
type APIFetcher struct {
	BaseURL string
	Client  *http.Client
}

// NewAPIFetcher creates a new APIFetcher with the given base URL
func NewAPIFetcher(baseURL string) *APIFetcher {
	return &APIFetcher{
		BaseURL: baseURL,
		Client:  &http.Client{},
	}
}

// FetchUpdate retrieves the light client update via Beacon API
// GET /eth/v1/beacon/light_client/updates?start_period=&count=
func (a *APIFetcher) ScUpdate(period uint64) (*types.LightClientUpdate, error) {
	return a.FetchUpdateWithParams(period, 1)
}

// FetchUpdateWithParams retrieves light client updates with specific parameters
func (a *APIFetcher) FetchUpdateWithParams(startPeriod uint64, count int) (*types.LightClientUpdate, error) {
	// Build URL with query parameters
	endpoint, err := url.Parse(a.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	endpoint.Path = "/eth/v1/beacon/light_client/updates"
	query := endpoint.Query()
	query.Set("start_period", strconv.FormatUint(startPeriod, 10))
	query.Set("count", strconv.Itoa(count))
	endpoint.RawQuery = query.Encode()

	// Send HTTP GET request
	resp, err := a.Client.Get(endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse API response
	var apiResponse types2.ScUpdateAPIResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	// Check if we got any updates
	if len(apiResponse) == 0 {
		return nil, fmt.Errorf("no light client updates found")
	}

	// Return the first update
	return &apiResponse[0], nil
}

// FetchBlock retrieves a beacon block by slot
// GET /eth/v2/beacon/blocks/{slot}
func (a *APIFetcher) Block(slot uint64) (*types2.BlockAPIResponse, error) {
	// Build URL with slot parameter
	endpoint, err := url.Parse(a.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	endpoint.Path = fmt.Sprintf("/eth/v2/beacon/blocks/%d", slot)

	// Send HTTP GET request
	resp, err := a.Client.Get(endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse API response
	var blockResponse types2.BlockAPIResponse
	if err := json.Unmarshal(body, &blockResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Return the full BlockAPIResponse
	return &blockResponse, nil
}
