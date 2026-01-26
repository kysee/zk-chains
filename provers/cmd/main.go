package main

import (
	"os"

	"github.com/kysee/zk-chains/provers/bprn"
	"github.com/kysee/zk-chains/provers/eth2"
)

func main() {
	//relayer.RelayerMain(types.NewConfig(os.Args...))

	//eth2.ListenerMain(types.NewConfig(os.Args...))
	bprn.ListenerMain(eth2.NewConfig(os.Args...))
}
