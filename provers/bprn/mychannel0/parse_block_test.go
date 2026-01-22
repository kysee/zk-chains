package mychannel0

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset/kvrwset"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/kysee/zk-chains/provers/bprn"
	"github.com/stretchr/testify/require"
)

func TestParseBlock(t *testing.T) {
	client, err := bprn.NewFabricClient("./connection-profile.json")
	require.NoError(t, err)

	block, err := client.GetBlockByNumber("mychannel0", "User1", "peerOrg1", 1619)
	require.NoError(t, err)

	fmt.Printf("Block Number: %d\n", block.Header.Number)
	fmt.Printf("Number of transactions in block: %d\n", len(block.Data.Data))

	// First, output the entire block as JSON
	//printJson("block.header", block)

	// Parse each data(transaction???, envelope???)
	for i, txBytes := range block.Data.Data {
		fmt.Printf("\n=== block.Data.Data[%d] ===\n", i)

		// Step 1: All data in block.Data.Data is wrapped in an Envelope
		envelope := &common.Envelope{}
		err := proto.Unmarshal(txBytes, envelope)
		require.NoError(t, err)
		//printJson(fmt.Sprintf("block.data.data[%d](envelope)", i), envelope)

		// Step 2: Parse the Payload from Envelope
		payload := &common.Payload{}
		err = proto.Unmarshal(envelope.Payload, payload)
		require.NoError(t, err)
		//printJson("envelope.payload", payload)

		// Step 3: Parse ChannelHeader to determine the type
		channelHeader := &common.ChannelHeader{}
		err = proto.Unmarshal(payload.Header.ChannelHeader, channelHeader)
		require.NoError(t, err)
		//printJson("envelop.payload.header.channel_header", channelHeader)

		// signatureHeader == creator(e.g. client application)
		signatureHeader := &common.SignatureHeader{}
		err = proto.Unmarshal(payload.Header.SignatureHeader, signatureHeader)
		require.NoError(t, err)
		//printJson("envelop.ayload.header.signature_header", signatureHeader)

		fmt.Println("txId", channelHeader.TxId)
		fmt.Println("channelId", channelHeader.ChannelId)
		fmt.Println("creator", getSubjectFromCert(signatureHeader.Creator))

		// Step 4: Parse payload.Data based on the type
		switch common.HeaderType(channelHeader.Type) {
		case common.HeaderType_CONFIG:
			parseConfigTransaction(t, payload)

		case common.HeaderType_CONFIG_UPDATE:
			parseConfigUpdateTransaction(t, payload)

		case common.HeaderType_ENDORSER_TRANSACTION:
			parseEndorserTransaction(t, payload)

		case common.HeaderType_ORDERER_TRANSACTION:
			fmt.Println("\t  [ORDERER_TRANSACTION - System transaction]")

		case common.HeaderType_MESSAGE:
			fmt.Println("\t  [MESSAGE]")

		default:
			fmt.Printf("\t  [Unknown/Unhandled type: %d]\n", channelHeader.Type)
		}

		fmt.Println()
	}
}

func parseConfigTransaction(t *testing.T, payload *common.Payload) {
	fmt.Println("  Type: CONFIG - Channel configuration")

	// Parse as ConfigEnvelope
	configEnvelope := &common.ConfigEnvelope{}
	err := proto.Unmarshal(payload.Data, configEnvelope)
	require.NoError(t, err)

	if configEnvelope.Config != nil {
		fmt.Printf("  Sequence: %d\n", configEnvelope.Config.Sequence)

		if configEnvelope.Config.ChannelGroup != nil {
			fmt.Printf("  Channel Groups: %v\n", getConfigGroupNames(configEnvelope.Config.ChannelGroup))
		}
	}

	// Output as JSON
	fmt.Println("\n  === JSON Output ===")
	jsonBytes, err := json.MarshalIndent(configEnvelope, "  ", "  ")
	require.NoError(t, err)
	fmt.Println(string(jsonBytes))
}

func parseConfigUpdateTransaction(t *testing.T, payload *common.Payload) {
	fmt.Println("  Type: CONFIG_UPDATE - Configuration update")

	configUpdateEnvelope := &common.ConfigUpdateEnvelope{}
	err := proto.Unmarshal(payload.Data, configUpdateEnvelope)
	require.NoError(t, err)

	configUpdate := &common.ConfigUpdate{}
	err = proto.Unmarshal(configUpdateEnvelope.ConfigUpdate, configUpdate)
	require.NoError(t, err)

	fmt.Printf("  Channel ID: %s\n", configUpdate.ChannelId)

	// Output as JSON
	fmt.Println("\n  === JSON Output ===")
	jsonBytes, err := json.MarshalIndent(configUpdateEnvelope, "  ", "  ")
	require.NoError(t, err)
	fmt.Println(string(jsonBytes))
}

func parseEndorserTransaction(t *testing.T, payload *common.Payload) {
	// Parse as peer.Transaction
	transaction := &peer.Transaction{}
	err := proto.Unmarshal(payload.Data, transaction)
	require.NoError(t, err)
	//printJson("envelop.payload.data(transaction)", transaction)

	// Parse each transaction action
	for _, action := range transaction.Actions {
		actionHeader := &common.SignatureHeader{}
		err = proto.Unmarshal(action.Header, actionHeader)
		require.NoError(t, err)

		fmt.Println("creator", getSubjectFromCert(actionHeader.Creator))

		// Parse ChaincodeActionPayload
		actionPayload := &peer.ChaincodeActionPayload{}
		err = proto.Unmarshal(action.Payload, actionPayload)
		require.NoError(t, err)
		//printJson(fmt.Sprintf("envelop.payload.data(transaction).actions[%d].payload", j), actionPayload)

		// Parse ChaincodeProposalPayload
		chaincodeProposalPayload := &peer.ChaincodeProposalPayload{}
		err = proto.Unmarshal(actionPayload.ChaincodeProposalPayload, chaincodeProposalPayload)
		require.NoError(t, err)
		//printJson(fmt.Sprintf("envelop.payload.data(transaction).actions[%d].payload.chaincode_proposal_payload", j), chaincodeProposalPayload)

		// Parse ChaincodeInvocationSpec
		chaincodeInvocationSpec := &peer.ChaincodeInvocationSpec{}
		err = proto.Unmarshal(chaincodeProposalPayload.Input, chaincodeInvocationSpec)
		require.NoError(t, err)
		//printJson(fmt.Sprintf("envelop.payload.data(transaction).actions[%d].payload.chaincode_proposal_payload.input", j), chaincodeInvocationSpec)

		if err == nil && chaincodeInvocationSpec.ChaincodeSpec != nil {
			fmt.Printf("\tChaincode Name: %s\n", chaincodeInvocationSpec.ChaincodeSpec.ChaincodeId.Name)
			if len(chaincodeInvocationSpec.ChaincodeSpec.Input.Args) > 0 {
				if len(chaincodeInvocationSpec.ChaincodeSpec.Input.Args) > 1 {
					fmt.Printf("\tArgs:\n")
					for k := 0; k < len(chaincodeInvocationSpec.ChaincodeSpec.Input.Args); k++ {
						fmt.Printf("\t\t[%d]: %s\n", k, string(chaincodeInvocationSpec.ChaincodeSpec.Input.Args[k]))
					}
				}
			}
		}

		// Parse ProposalResponsePayload
		proposalResponsePayload := &peer.ProposalResponsePayload{}
		err = proto.Unmarshal(actionPayload.Action.ProposalResponsePayload, proposalResponsePayload)
		require.NoError(t, err)
		//jz, err = json.MarshalIndent(proposalResponsePayload, "", "  ")
		//require.NoError(t, err)
		//fmt.Printf("envelop.payload.data(transaction).actions[%d].payload.action.proposal_response_payload: %v\n", j, string(jz))
		//printJson(fmt.Sprintf("envelop.payload.data(transaction).actions[%d].payload.action.proposal_response_payload", j), proposalResponsePayload)

		// Parse ChaincodeAction
		chaincodeAction := &peer.ChaincodeAction{}
		err = proto.Unmarshal(proposalResponsePayload.Extension, chaincodeAction)
		require.NoError(t, err)
		//printJson(fmt.Sprintf("envelop.payload.data(transaction).actions[%d].payload.action.proposal_response_payload.extention", j), chaincodeAction)

		// Parse and print read/write sets
		var txRwSet *rwset.TxReadWriteSet
		if len(chaincodeAction.Results) > 0 {
			// First, parse Results as TxReadWriteSet
			txRwSet = &rwset.TxReadWriteSet{}
			err = proto.Unmarshal(chaincodeAction.Results, txRwSet)
			require.NoError(t, err)
			//printJson(fmt.Sprintf("envelop.payload.data(transaction).actions[%d].payload.action.proposal_response_payload.extention.results", j), txRwSet)

			if err == nil && len(txRwSet.NsRwset) > 0 {
				fmt.Printf("\n---\nRead-Write Sets:\n")
				for _, nsRwSet := range txRwSet.NsRwset {
					fmt.Printf("\t\tNamespace: %s\n", nsRwSet.Namespace)

					// Parse KVRWSet
					kvRwSet := &kvrwset.KVRWSet{}
					err = proto.Unmarshal(nsRwSet.Rwset, kvRwSet)
					if err == nil {
						if len(kvRwSet.Reads) > 0 {
							fmt.Printf("\t\t\tReads: %d\n", len(kvRwSet.Reads))
							for _, read := range kvRwSet.Reads {
								if read.Version != nil {
									fmt.Printf("\t\t\t\tKey: %s, Version: [BlockNum:%d, TxNum:%d]\n",
										read.Key, read.Version.BlockNum, read.Version.TxNum)
								} else {
									fmt.Printf("\t\t\t\tKey: %s, Version: nil\n", read.Key)
								}
							}
						}

						if len(kvRwSet.Writes) > 0 {
							fmt.Printf("\t\t\tWrites: %d\n", len(kvRwSet.Writes))
							for _, write := range kvRwSet.Writes {
								valueStr := string(write.Value)
								if len(valueStr) > 100 {
									valueStr = valueStr[:100] + "..."
								}
								fmt.Printf("\t\t\t\tKey: %s, IsDelete: %v, Value: %s\n",
									write.Key, write.IsDelete, valueStr)
							}
						}
					}
				}
			}
		}

		for _, endorser := range actionPayload.Action.Endorsements {
			fmt.Println("endorser", getSubjectFromCert(endorser.Endorser))
		}

		//// Output detailed JSON for this action
		//fmt.Println("\n  === Action JSON Output ===")
		//actionData := map[string]interface{}{
		//	"chaincodeInvocationSpec": chaincodeInvocationSpec,
		//	"chaincodeAction":         chaincodeAction,
		//	"txReadWriteSet":          txRwSet,
		//}
		//jsonBytes, err := json.MarshalIndent(actionData, "  ", "  ")
		//require.NoError(t, err)
		//fmt.Println(string(jsonBytes))
	}
}

func getConfigGroupNames(group *common.ConfigGroup) []string {
	names := []string{}
	if group.Groups != nil {
		for name := range group.Groups {
			names = append(names, name)
		}
	}
	return names
}

func printJson(title string, v interface{}) {
	jsonBytes, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		panic(err)
	} else {
		fmt.Printf("%s: %s\n", title, string(jsonBytes))
	}
}
func getSubjectFromCert(idBytes []byte) string {
	// Creator is a SerializedIdentity protobuf, not raw PEM
	serializedIdentity := &msp.SerializedIdentity{}
	err := proto.Unmarshal(idBytes, serializedIdentity)
	if err != nil {
		return fmt.Sprintf("error: failed to unmarshal SerializedIdentity: %v", err)
	}

	// IdBytes contains the actual PEM certificate
	block, _ := pem.Decode(serializedIdentity.IdBytes)
	if block == nil {
		return "error: failed to decode PEM block"
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Sprintf("error: failed to parse certificate: %v", err)
	}

	return fmt.Sprintf("[%s] %s", serializedIdentity.Mspid, cert.Subject.String())
}
