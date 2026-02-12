package bprn

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset/kvrwset"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/kysee/zk-chains/provers/types"
	"github.com/stretchr/testify/require"
)

func TestGetTx(t *testing.T) {
	client, err := NewFabricClient("./connection-profile.json")
	require.NoError(t, err)
	defer client.Close()

	channelID := "mychannel0"
	userName := "User1"
	orgName := "peerOrg1"
	txID := "1d1611baa77ac2baa2779fc95f4d7a112abd629796e302f94a08a894d007e487"

	// Create ledger client
	ctxProvider := client.SDK().ChannelContext(channelID,
		fabsdk.WithUser(userName),
		fabsdk.WithOrg(orgName))

	ledgerClient, err := ledger.New(ctxProvider)
	require.NoError(t, err)

	// Query transaction by txID
	processedTx, err := ledgerClient.QueryTransaction(fab.TransactionID(txID))
	require.NoError(t, err)

	fmt.Printf("=== Transaction: %s ===\n", txID)
	fmt.Printf("Validation Code: %d\n", processedTx.ValidationCode)

	// Parse the transaction envelope
	envelope := processedTx.TransactionEnvelope
	payload := &common.Payload{}
	err = proto.Unmarshal(envelope.Payload, payload)
	require.NoError(t, err)

	// Parse channel header
	channelHeader := &common.ChannelHeader{}
	err = proto.Unmarshal(payload.Header.ChannelHeader, channelHeader)
	require.NoError(t, err)

	fmt.Printf("Channel ID: %s\n", channelHeader.ChannelId)
	fmt.Printf("TxID: %s\n", channelHeader.TxId)
	fmt.Printf("Timestamp: %v\n", channelHeader.Timestamp)
	fmt.Printf("Type: %s\n", common.HeaderType(channelHeader.Type).String())

	// Parse signature header (creator)
	signatureHeader := &common.SignatureHeader{}
	err = proto.Unmarshal(payload.Header.SignatureHeader, signatureHeader)
	require.NoError(t, err)
	fmt.Printf("Creator: %s\n", getSubjectFromCert(signatureHeader.Creator))

	// If it's an endorser transaction, parse the details
	if common.HeaderType(channelHeader.Type) == common.HeaderType_ENDORSER_TRANSACTION {
		transaction := &peer.Transaction{}
		err = proto.Unmarshal(payload.Data, transaction)
		require.NoError(t, err)

		for i, action := range transaction.Actions {
			fmt.Printf("\n--- Action[%d] ---\n", i)

			actionPayload := &peer.ChaincodeActionPayload{}
			err = proto.Unmarshal(action.Payload, actionPayload)
			require.NoError(t, err)

			// Parse chaincode proposal payload
			chaincodeProposalPayload := &peer.ChaincodeProposalPayload{}
			err = proto.Unmarshal(actionPayload.ChaincodeProposalPayload, chaincodeProposalPayload)
			require.NoError(t, err)

			// Parse chaincode invocation spec
			chaincodeInvocationSpec := &peer.ChaincodeInvocationSpec{}
			err = proto.Unmarshal(chaincodeProposalPayload.Input, chaincodeInvocationSpec)
			require.NoError(t, err)

			if chaincodeInvocationSpec.ChaincodeSpec != nil {
				fmt.Printf("Chaincode: %s\n", chaincodeInvocationSpec.ChaincodeSpec.ChaincodeId.Name)
				if len(chaincodeInvocationSpec.ChaincodeSpec.Input.Args) > 0 {
					fmt.Printf("Function: %s\n", string(chaincodeInvocationSpec.ChaincodeSpec.Input.Args[0]))
					fmt.Printf("Args:\n")
					for j, arg := range chaincodeInvocationSpec.ChaincodeSpec.Input.Args[1:] {
						fmt.Printf("  [%d]: %s\n", j+1, string(arg))
					}
				}
			}

			// Parse proposal response payload
			proposalResponsePayload := &peer.ProposalResponsePayload{}
			err = proto.Unmarshal(actionPayload.Action.ProposalResponsePayload, proposalResponsePayload)
			require.NoError(t, err)

			// Parse chaincode action
			chaincodeAction := &peer.ChaincodeAction{}
			err = proto.Unmarshal(proposalResponsePayload.Extension, chaincodeAction)
			require.NoError(t, err)

			fmt.Printf("Response Status: %d\n", chaincodeAction.Response.Status)
			if len(chaincodeAction.Response.Payload) > 0 {
				fmt.Printf("Response Payload: %s\n", string(chaincodeAction.Response.Payload))
			}

			fmt.Printf("Results: %d\n", len(chaincodeAction.Results))
			txRwSet := &rwset.TxReadWriteSet{}
			err = proto.Unmarshal(chaincodeAction.Results, txRwSet)
			for _, nsrwset := range txRwSet.NsRwset {
				fmt.Printf("\tNamespace: %s\n", nsrwset.Namespace)

				// Parse KVRWSet
				kvRwSet := &kvrwset.KVRWSet{}
				err = proto.Unmarshal(nsrwset.Rwset, kvRwSet)
				if err == nil {
					if len(kvRwSet.Reads) > 0 {
						fmt.Printf("\tReads: %d\n", len(kvRwSet.Reads))
						for _, read := range kvRwSet.Reads {
							if read.Version != nil {
								fmt.Printf("\t\tKey: %s, Version: [BlockNum:%d, TxNum:%d]\n",
									read.Key, read.Version.BlockNum, read.Version.TxNum)
							} else {
								fmt.Printf("\t\tKey: %s, Version: nil\n", read.Key)
							}
						}
					}

					if len(kvRwSet.Writes) > 0 {
						fmt.Printf("\tWrites: %d\n", len(kvRwSet.Writes))
						for _, write := range kvRwSet.Writes {
							valueStr := string(write.Value)
							//if len(valueStr) > 100 {
							//	valueStr = valueStr[:100] + "..."
							//}
							fmt.Printf("\t\tKey: %s, IsDelete: %v, Value: %s\n",
								write.Key, write.IsDelete, valueStr)
						}
					}
				}
			}

			// Parse chaincode events
			fmt.Printf("Event: %d\n", len(chaincodeAction.Events))
			if len(chaincodeAction.Events) > 0 {
				chaincodeEvent := &peer.ChaincodeEvent{}
				err = proto.Unmarshal(chaincodeAction.Events, chaincodeEvent)
				if err == nil {
					fmt.Printf("Event Chaincode: %s\n", chaincodeEvent.ChaincodeId)
					fmt.Printf("Event Type: %s\n", chaincodeEvent.EventName)
					fmt.Printf("Event TxId: %s\n", chaincodeEvent.TxId)
					fmt.Printf("Event Payload: %s\n", string(chaincodeEvent.Payload))
				}
			}

			// Print endorsers
			fmt.Printf("Endorsers: %d\n", len(actionPayload.Action.Endorsements))
			for j, endorsement := range actionPayload.Action.Endorsements {
				fmt.Printf("  [%d]: %s\n", j, getSubjectFromCert(endorsement.Endorser))
				fmt.Printf("      Signature: (%d bytes) %x\n", len(endorsement.Signature), endorsement.Signature)

				// Decode ECDSA signature (DER format) to get R, S values
				r, s, err := decodeECDSASignature(endorsement.Signature)
				require.NoError(t, err)
				fmt.Printf("      R: %s\n", r.Text(16))
				fmt.Printf("      S: %s\n", s.Text(16))

				pubKey, err := types.PubkeyFromCert(endorsement.Endorser)
				require.NoError(t, err)
				msgh := sha256.Sum256(append(actionPayload.Action.ProposalResponsePayload, endorsement.Endorser...))
				require.True(t, ecdsa.Verify(pubKey, msgh[:], r, s))
			}
		}
	}
}
