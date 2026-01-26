package bprn

import (
	"fmt"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	provtypes "github.com/kysee/zk-chains/provers/eth2"
	"github.com/kysee/zk-chains/types"
)

func ListenerMain(config *provtypes.Config) {
	client := NewBPrNListener(config)
	client.Start(1)
}

type BPrNListener struct {
	cfg    *provtypes.Config
	client *FabricClient
	prover types.Prover
}

func NewBPrNListener(config *provtypes.Config) *BPrNListener {
	dir, _ := os.Getwd()
	os.Chdir("mychannel0")
	client, err := NewFabricClient("./connection-profile.json")
	os.Chdir(dir)
	if err != nil {
		panic(err)
	}
	return &BPrNListener{client: client, cfg: config, prover: NewTxProverGroth16()}
}

func (l *BPrNListener) Start(startHeight uint64) {
	go l.startRoutine(startHeight)
}

func (l *BPrNListener) startRoutine(startHeight uint64) {
	//for {
	block, err := l.client.GetBlockByNumber("mychannel0", "User1", "peerOrg1", startHeight)
	if err != nil {
		panic(err)
	}

	fmt.Println("\n====================================")
	fmt.Printf("Block Number: %d\n", block.Header.Number)

	actionPayloads, err := getChaincodeActionPayload(block)
	if err != nil {
		panic(err)
	}

	for _, payload := range actionPayloads {
		bzproofs, err := l.prover.Prove(payload.Action)
		if err != nil {
			panic(err)
		}
		for _, bzproof := range bzproofs {
			fmt.Printf("Proof: %x\n", bzproof)
		}
	}
	//}
}

func getChaincodeActionPayload(block *common.Block) ([]*peer.ChaincodeActionPayload, error) {
	var ret []*peer.ChaincodeActionPayload

	fmt.Printf("Number of transactions in block: %d\n", len(block.Data.Data))
	for i, txBytes := range block.Data.Data {
		fmt.Printf("\n=== block.Data.Data[%d] ===\n", i)

		// Step 1: All data in block.Data.Data is wrapped in an Envelope
		envelope := &common.Envelope{}
		if err := proto.Unmarshal(txBytes, envelope); err != nil {
			return nil, err
		}
		payload := &common.Payload{}
		if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
			return nil, err
		}

		transaction := &peer.Transaction{}
		if err := proto.Unmarshal(payload.Data, transaction); err != nil {
			return nil, err
		}

		action := transaction.Actions[0]
		actionPayload := &peer.ChaincodeActionPayload{}
		if err := proto.Unmarshal(action.Payload, actionPayload); err != nil {
			return nil, err
		}
		ret = append(ret, actionPayload)
	}
	return ret, nil
}
