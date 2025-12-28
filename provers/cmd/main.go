package main

import (
	"os"

	"github.com/kysee/zk-chains/provers"
	"github.com/kysee/zk-chains/provers/types"
)

func main() {
	//relayer.RelayerMain(types.NewConfig(os.Args...))

	relayer.ListenerMain(types.NewConfig(os.Args...))
}
