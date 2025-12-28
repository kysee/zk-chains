package types

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds the relayer configuration
type Config struct {
	RootDir string

	// RPCEndpoint is used when DataSource is "rpc"
	RPCEndpoint string
	// InitPeriod is the period to start fetching updates from
	InitPeriod uint64

	Slot uint64
}

func NewConfig(args ...string) *Config {
	// Parse configuration from environment variables or command line args
	config := Config{
		RootDir:     getEnv("ROOT", "."),
		RPCEndpoint: getEnv("RPC_ENDPOINT", "https://lodestar-sepolia.chainsafe.io/"),
		InitPeriod:  0,
		Slot:        0,
	}

	for i := 0; i < len(args); i++ {
		if len(args) <= i+1 {
			panic(fmt.Errorf("missing argument for %s", args[i-1]))
		}

		switch args[i] {
		case "--slot":
			config.Slot, _ = strconv.ParseUint(args[i+1], 10, 64)
			i++
		case "--root":
			config.RootDir = args[i+1]
			i++
		case "--init-period":
			config.InitPeriod, _ = strconv.ParseUint(args[i+1], 10, 64)
			i++
		case "--rpc":
			config.RPCEndpoint = args[i+1]
			i++
		}
	}

	return &config
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
