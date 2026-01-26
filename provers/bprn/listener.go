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
		////printJson(fmt.Sprintf("block.data.data[%d](envelope)", i), envelope)
		//
		//// Step 2: Parse the Payload from Envelope
		//payload := &common.Payload{}
		//err = proto.Unmarshal(envelope.Payload, payload)
		//
		////printJson("envelope.payload", payload)
		//
		//// Step 3: Parse ChannelHeader to determine the type
		//channelHeader := &common.ChannelHeader{}
		//err = proto.Unmarshal(payload.Header.ChannelHeader, channelHeader)
		//require.NoError(t, err)
		////printJson("envelop.payload.header.channel_header", channelHeader)
		//
		//// signatureHeader == creator(e.g. client application)
		//signatureHeader := &common.SignatureHeader{}
		//err = proto.Unmarshal(payload.Header.SignatureHeader, signatureHeader)
		//require.NoError(t, err)
		////printJson("envelop.ayload.header.signature_header", signatureHeader)
		//
		//fmt.Println("txId", channelHeader.TxId)
		//fmt.Println("channelId", channelHeader.ChannelId)
		//fmt.Println("creator", getSubjectFromCert(signatureHeader.Creator))
		//
		//// Step 4: Parse payload.Data based on the type
		//switch common.HeaderType(channelHeader.Type) {
		//case common.HeaderType_CONFIG:
		//	parseConfigTransaction(t, payload)
		//
		//case common.HeaderType_CONFIG_UPDATE:
		//	parseConfigUpdateTransaction(t, payload)
		//
		//case common.HeaderType_ENDORSER_TRANSACTION:
		//	parseEndorserTransaction(t, payload)
		//
		//case common.HeaderType_ORDERER_TRANSACTION:
		//	fmt.Println("\t  [ORDERER_TRANSACTION - System transaction]")
		//
		//case common.HeaderType_MESSAGE:
		//	fmt.Println("\t  [MESSAGE]")
		//
		//default:
		//	fmt.Printf("\t  [Unknown/Unhandled type: %d]\n", channelHeader.Type)
		//}
		//
		//fmt.Println()
	}
	return ret, nil
}
