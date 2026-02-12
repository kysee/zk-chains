package bprn

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset/kvrwset"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/event"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/events/deliverclient/seek"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/kysee/zk-chains/provers/types"
	"github.com/stretchr/testify/require"
)

// ordererPubKeys stores orderer public keys parsed from config blocks.
var ordererPubKeys []*ecdsa.PublicKey

func TestTxType(t *testing.T) {
	client, err := NewFabricClient("./localchannel0/connection-profile.json")
	require.NoError(t, err)

	// Reset global orderer public keys
	ordererPubKeys = nil

	targetOpt := ledger.WithTargetEndpoints("peer0.org1.bc")

	height, err := client.GetBlockchainHeight("bpn", "User1", "peerOrg1", targetOpt)
	require.NoError(t, err)
	fmt.Printf("Blockchain height: %d (last block: %d)\n", height, height-1)

	for h := uint64(0); h < height; h++ {
		fmt.Println("======================================================================================================================")
		block, err := client.GetBlockByNumber("bpn", "User1", "peerOrg1", h, targetOpt)
		require.NoError(t, err)

		fmt.Printf("Block Number: %d\n", block.Header.Number)
		fmt.Printf("Number of transactions in block: %d\n", len(block.Data.Data))

		for _, txBytes := range block.Data.Data {
			// Step 1: All data in block.Data.Data is wrapped in an Envelope
			envelope := &common.Envelope{}
			err := proto.Unmarshal(txBytes, envelope)
			require.NoError(t, err)

			// Step 2: Parse the Payload from Envelope
			payload := &common.Payload{}
			err = proto.Unmarshal(envelope.Payload, payload)
			require.NoError(t, err)

			// Step 3: Parse ChannelHeader to determine the type
			channelHeader := &common.ChannelHeader{}
			err = proto.Unmarshal(payload.Header.ChannelHeader, channelHeader)
			require.NoError(t, err)

			headerType := common.HeaderType(channelHeader.Type)
			fmt.Println("---")
			fmt.Println("- txId", channelHeader.TxId)
			fmt.Println("- txType", headerType.String())
			fmt.Println("- channelId", channelHeader.ChannelId)

			switch headerType {
			case common.HeaderType_CONFIG:
				parseConfigTransaction(t, payload)

			//case common.HeaderType_CONFIG_UPDATE:
			//	parseConfigUpdateTransaction(t, payload)

			case common.HeaderType_ENDORSER_TRANSACTION:
				parseEndorserTransaction(t, payload)

			//case common.HeaderType_ORDERER_TRANSACTION:
			//	fmt.Println("\t  [ORDERER_TRANSACTION - System transaction]")

			case common.HeaderType_MESSAGE:
				fmt.Println("\t  [MESSAGE]")

			default:
				fmt.Printf("\t  [Unknown/Unhandled type: %d]\n", channelHeader.Type)
			}
		}

		// Verify block signature
		verifyBlockSignature(t, block)
	}
}

func TestParseBlock(t *testing.T) {
	client, err := NewFabricClient("./connection-profile.json")
	require.NoError(t, err)

	block, err := client.GetBlockByNumber("mychannel0", "User1", "peerOrg1", 1)
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

func TestEventClient(t *testing.T) {
	client, err := NewFabricClient("./connection-profile.json")
	require.NoError(t, err)
	defer client.Close()

	// Create channel context
	channelID := "mychannel0"
	userName := "User1"
	orgName := "peerOrg1"

	channelProvider := client.SDK().ChannelContext(channelID,
		fabsdk.WithUser(userName),
		fabsdk.WithOrg(orgName))

	// Create event client - WithSeekType(seek.FromBlock)으로 과거 블록부터 replay
	eventClient, err := event.New(channelProvider,
		event.WithBlockNum(1),
		event.WithSeekType(seek.FromBlock),
		event.WithBlockEvents(), // Full block events를 수신 (chaincode events 포함)
	)
	require.NoError(t, err)

	// Register chaincode event for "erc20" chaincode
	// The event name pattern can be a regex, ".*" matches all events
	chaincodeID := "endpoint-aws-a" //"erc20"
	eventFilter := ".*"             // Listen to all events from erc20 chaincode

	reg, notifier, err := eventClient.RegisterChaincodeEvent(chaincodeID, eventFilter)
	require.NoError(t, err)
	defer eventClient.Unregister(reg)

	// Listen for events
	secs := 60 * time.Second
	timeout := time.After(secs)
	eventCount := 0

	fmt.Printf("Listening for chaincode events from '%s' (filter: '%s')...\n", chaincodeID, eventFilter)
	fmt.Printf("Waiting for events (timeout: %v)...\n", secs.String())

	for {
		select {
		case ccEvent := <-notifier:
			eventCount++
			fmt.Printf("\n=== Chaincode Event #%d ===\n", eventCount)
			fmt.Printf("  Chaincode ID: %s\n", ccEvent.ChaincodeID)
			fmt.Printf("  Event Type:   %s\n", ccEvent.EventName)
			fmt.Printf("  TxID:         %s\n", ccEvent.TxID)
			fmt.Printf("  Block Number: %d\n", ccEvent.BlockNumber)
			fmt.Printf("  Payload:      %s\n", string(ccEvent.Payload))

			// Optionally parse the payload if it's JSON
			if len(ccEvent.Payload) > 0 {
				var payloadJSON map[string]interface{}
				if err := json.Unmarshal(ccEvent.Payload, &payloadJSON); err == nil {
					prettyPayload, _ := json.MarshalIndent(payloadJSON, "  ", "  ")
					fmt.Printf("  Payload (JSON):\n  %s\n", string(prettyPayload))
				}
			}

		case <-timeout:
			fmt.Printf("\nTimeout reached. Total events received: %d\n", eventCount)
			return
		}
	}
}

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

func parseConfigTransaction(t *testing.T, payload *common.Payload) {
	fmt.Println("  Type: CONFIG - Channel configuration")

	// Parse as ConfigEnvelope
	configEnvelope := &common.ConfigEnvelope{}
	err := proto.Unmarshal(payload.Data, configEnvelope)
	require.NoError(t, err)

	if configEnvelope.Config == nil {
		return
	}

	fmt.Printf("  Sequence: %d\n", configEnvelope.Config.Sequence)

	if configEnvelope.Config.ChannelGroup != nil {
		fmt.Printf("  Channel Groups: %v\n", getConfigGroupNames(configEnvelope.Config.ChannelGroup))
	}

	// Find Orderer group
	ordererGroup, ok := configEnvelope.Config.ChannelGroup.Groups["Orderer"]
	if !ok {
		fmt.Println("  No Orderer group found")
		return
	}

	// Parse ConsensusType to get individual orderer consenters
	consensusTypeValue, ok := ordererGroup.Values["ConsensusType"]
	if !ok {
		fmt.Println("  No ConsensusType value found in Orderer group")
		return
	}

	consensusType := &orderer.ConsensusType{}
	err = proto.Unmarshal(consensusTypeValue.Value, consensusType)
	require.NoError(t, err)

	fmt.Printf("  Consensus Type: %s\n", consensusType.Type)

	if consensusType.Type == "etcdraft" {
		configMetadata := &etcdraft.ConfigMetadata{}
		err = proto.Unmarshal(consensusType.Metadata, configMetadata)
		require.NoError(t, err)

		fmt.Printf("  Number of Consenters: %d\n", len(configMetadata.Consenters))

		for i, consenter := range configMetadata.Consenters {
			fmt.Printf("\n  === Orderer Consenter[%d] ===\n", i)
			fmt.Printf("    Host: %s\n", consenter.Host)
			fmt.Printf("    Port: %d\n", consenter.Port)

			// Parse ServerTlsCert
			if pk := parseCertWithLabel("Server TLS Cert", consenter.ServerTlsCert); pk != nil {
				ordererPubKeys = append(ordererPubKeys, pk)
			}

			// Parse ClientTlsCert
			if pk := parseCertWithLabel("Client TLS Cert", consenter.ClientTlsCert); pk != nil {
				ordererPubKeys = append(ordererPubKeys, pk)
			}
		}
	}

	// Parse orderer org MSP certificates
	for orgName, orgGroup := range ordererGroup.Groups {
		mspValue, ok := orgGroup.Values["MSP"]
		if !ok {
			continue
		}

		mspConfig := &msp.MSPConfig{}
		err = proto.Unmarshal(mspValue.Value, mspConfig)
		require.NoError(t, err)

		fabricMSPConfig := &msp.FabricMSPConfig{}
		err = proto.Unmarshal(mspConfig.Config, fabricMSPConfig)
		require.NoError(t, err)

		fmt.Printf("\n  === Orderer Org MSP: %s (%s) ===\n", orgName, fabricMSPConfig.Name)

		for j, certBytes := range fabricMSPConfig.RootCerts {
			if pk := parseCertWithLabel(fmt.Sprintf("Root Cert[%d]", j), certBytes); pk != nil {
				ordererPubKeys = append(ordererPubKeys, pk)
			}
		}
		for j, certBytes := range fabricMSPConfig.TlsRootCerts {
			if pk := parseCertWithLabel(fmt.Sprintf("TLS Root Cert[%d]", j), certBytes); pk != nil {
				ordererPubKeys = append(ordererPubKeys, pk)
			}
		}
		for j, certBytes := range fabricMSPConfig.Admins {
			if pk := parseCertWithLabel(fmt.Sprintf("Admin Cert[%d]", j), certBytes); pk != nil {
				ordererPubKeys = append(ordererPubKeys, pk)
			}
		}
	}

	fmt.Printf("\n  Total stored orderer public keys: %d\n", len(ordererPubKeys))
}

func parseCertWithLabel(label string, certPEM []byte) *ecdsa.PublicKey {
	if len(certPEM) == 0 {
		return nil
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		fmt.Printf("    %s: failed to decode PEM\n", label)
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("    %s: failed to parse certificate: %v\n", label, err)
		return nil
	}

	fmt.Printf("    %s:\n", label)
	fmt.Printf("      Subject: %s\n", cert.Subject.String())
	fmt.Printf("      Serial Number: %s\n", cert.SerialNumber.Text(16))
	if len(cert.Subject.OrganizationalUnit) > 0 {
		fmt.Printf("      OU: %v\n", cert.Subject.OrganizationalUnit)
	}
	if len(cert.DNSNames) > 0 {
		fmt.Printf("      DNS Names: %v\n", cert.DNSNames)
	}
	fmt.Printf("      IsCA: %v\n", cert.IsCA)
	fmt.Printf("      Key Usage: %s\n", keyUsageToString(cert.KeyUsage))
	if len(cert.ExtKeyUsage) > 0 {
		fmt.Printf("      Ext Key Usage: %s\n", extKeyUsageToString(cert.ExtKeyUsage))
	}
	if pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		fmt.Printf("      Public Key X: %s\n", hex.EncodeToString(pubKey.X.Bytes()))
		fmt.Printf("      Public Key Y: %s\n", hex.EncodeToString(pubKey.Y.Bytes()))
		return pubKey
	}
	fmt.Printf("      Public Key: (not ECDSA)\n")
	return nil
}

func keyUsageToString(usage x509.KeyUsage) string {
	var usages []string
	for u, name := range map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "DigitalSignature",
		x509.KeyUsageContentCommitment: "ContentCommitment",
		x509.KeyUsageKeyEncipherment:   "KeyEncipherment",
		x509.KeyUsageDataEncipherment:  "DataEncipherment",
		x509.KeyUsageKeyAgreement:      "KeyAgreement",
		x509.KeyUsageCertSign:          "CertSign",
		x509.KeyUsageCRLSign:           "CRLSign",
		x509.KeyUsageEncipherOnly:      "EncipherOnly",
		x509.KeyUsageDecipherOnly:      "DecipherOnly",
	} {
		if usage&u != 0 {
			usages = append(usages, name)
		}
	}
	if len(usages) == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%v", usages)
}

func extKeyUsageToString(usages []x509.ExtKeyUsage) string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                        "Any",
		x509.ExtKeyUsageServerAuth:                 "ServerAuth",
		x509.ExtKeyUsageClientAuth:                 "ClientAuth",
		x509.ExtKeyUsageCodeSigning:                "CodeSigning",
		x509.ExtKeyUsageEmailProtection:            "EmailProtection",
		x509.ExtKeyUsageIPSECEndSystem:             "IPSECEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                "IPSECTunnel",
		x509.ExtKeyUsageIPSECUser:                  "IPSECUser",
		x509.ExtKeyUsageTimeStamping:               "TimeStamping",
		x509.ExtKeyUsageOCSPSigning:                "OCSPSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto: "MicrosoftServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:  "NetscapeServerGatedCrypto",
	}
	var result []string
	for _, u := range usages {
		if name, ok := names[u]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("Unknown(%d)", u))
		}
	}
	return fmt.Sprintf("%v", result)
}

// blockHeaderASN1Bytes returns the ASN.1 DER encoded block header,
// matching Fabric's BlockHeaderBytes format used for block signing.
func blockHeaderASN1Bytes(h *common.BlockHeader) ([]byte, error) {
	return asn1.Marshal(struct {
		Number       *big.Int
		PreviousHash []byte
		DataHash     []byte
	}{
		Number:       new(big.Int).SetUint64(h.Number),
		PreviousHash: h.PreviousHash,
		DataHash:     h.DataHash,
	})
}

func verifyBlockSignature(t *testing.T, block *common.Block) {
	if block.Metadata == nil || len(block.Metadata.Metadata) == 0 {
		fmt.Println("  [No metadata in block]")
		return
	}

	metadata := &common.Metadata{}
	err := proto.Unmarshal(block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES], metadata)
	require.NoError(t, err)

	// Fabric uses ASN.1 DER encoding for block header bytes in signatures
	blockHeaderBytes, err := blockHeaderASN1Bytes(block.Header)
	require.NoError(t, err)

	fmt.Printf("  Block Signatures: %d\n", len(metadata.Signatures))

	for i, metadataSig := range metadata.Signatures {
		// Parse signature header to get signer identity
		sigHdr := &common.SignatureHeader{}
		err = proto.Unmarshal(metadataSig.SignatureHeader, sigHdr)
		require.NoError(t, err)

		// Parse signer's certificate from SerializedIdentity
		serializedIdentity := &msp.SerializedIdentity{}
		err = proto.Unmarshal(sigHdr.Creator, serializedIdentity)
		require.NoError(t, err)

		certBlock, _ := pem.Decode(serializedIdentity.IdBytes)
		require.NotNil(t, certBlock)

		signerCert, err := x509.ParseCertificate(certBlock.Bytes)
		require.NoError(t, err)

		pubKey, ok := signerCert.PublicKey.(*ecdsa.PublicKey)
		require.True(t, ok, "signer's public key is not ECDSA")

		// Construct the signed message: metadata.Value || signatureHeader || blockHeaderBytes(ASN.1)
		msg := make([]byte, 0, len(metadata.Value)+len(metadataSig.SignatureHeader)+len(blockHeaderBytes))
		msg = append(msg, metadata.Value...)
		msg = append(msg, metadataSig.SignatureHeader...)
		msg = append(msg, blockHeaderBytes...)
		msgHash := sha256.Sum256(msg)

		// Decode ECDSA signature (DER format)
		r, s, err := decodeECDSASignature(metadataSig.Signature)
		require.NoError(t, err)

		// Verify signature
		valid := ecdsa.Verify(pubKey, msgHash[:], r, s)

		// Check if signer's key matches any stored orderer public key
		isKnown := false
		for _, storedKey := range ordererPubKeys {
			if storedKey.X.Cmp(pubKey.X) == 0 && storedKey.Y.Cmp(pubKey.Y) == 0 {
				isKnown = true
				break
			}
		}

		fmt.Printf("  Signature[%d]: valid=%v, knownOrderer=%v\n", i, valid, isKnown)
		fmt.Printf("    MSP ID: %s\n", serializedIdentity.Mspid)
		fmt.Printf("    Subject: %s\n", signerCert.Subject.String())
		fmt.Printf("    Serial Number: %s\n", signerCert.SerialNumber.Text(16))
		if len(signerCert.Subject.OrganizationalUnit) > 0 {
			fmt.Printf("    OU: %v\n", signerCert.Subject.OrganizationalUnit)
		}
		if len(signerCert.DNSNames) > 0 {
			fmt.Printf("    DNS Names: %v\n", signerCert.DNSNames)
		}
		fmt.Printf("    IsCA: %v\n", signerCert.IsCA)
		fmt.Printf("    Key Usage: %s\n", keyUsageToString(signerCert.KeyUsage))
		if len(signerCert.ExtKeyUsage) > 0 {
			fmt.Printf("    Ext Key Usage: %s\n", extKeyUsageToString(signerCert.ExtKeyUsage))
		}
		fmt.Printf("    Public Key X: %s\n", hex.EncodeToString(pubKey.X.Bytes()))
		fmt.Printf("    Public Key Y: %s\n", hex.EncodeToString(pubKey.Y.Bytes()))

		// Also store orderer signing key if not already known
		if !isKnown {
			ordererPubKeys = append(ordererPubKeys, pubKey)
			fmt.Printf("    (added to ordererPubKeys, total: %d)\n", len(ordererPubKeys))
		}
	}
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
	// Actions length should be 1 for endorsement transaction
	for _, action := range transaction.Actions {
		actionHeader := &common.SignatureHeader{}
		err = proto.Unmarshal(action.Header, actionHeader)
		require.NoError(t, err)

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
			fmt.Printf("\tChaincode: %s\n", chaincodeInvocationSpec.ChaincodeSpec.ChaincodeId.Name)
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
		//printJson(fmt.Sprintf("envelop.payload.data(transaction).actions[%d].payload.action.proposal_response_payload", j), proposalResponsePayload)

		// Parse ChaincodeAction
		chaincodeAction := &peer.ChaincodeAction{}
		err = proto.Unmarshal(proposalResponsePayload.Extension, chaincodeAction)
		require.NoError(t, err)
		//printJson(fmt.Sprintf("envelop.payload.data(transaction).actions[%d].payload.action.proposal_response_payload.extention", j), chaincodeAction)

		//// Parse and print read/write sets
		//var txRwSet *rwset.TxReadWriteSet
		//if len(chaincodeAction.Results) > 0 {
		//	// First, parse Results as TxReadWriteSet
		//	txRwSet = &rwset.TxReadWriteSet{}
		//	err = proto.Unmarshal(chaincodeAction.Results, txRwSet)
		//	require.NoError(t, err)
		//	//printJson(fmt.Sprintf("envelop.payload.data(transaction).actions[%d].payload.action.proposal_response_payload.extention.results", j), txRwSet)
		//
		//	if err == nil && len(txRwSet.NsRwset) > 0 {
		//		fmt.Printf("\n---\nRead-Write Sets:\n")
		//		for _, nsRwSet := range txRwSet.NsRwset {
		//			fmt.Printf("\t\tNamespace: %s\n", nsRwSet.Namespace)
		//
		//			// Parse KVRWSet
		//			kvRwSet := &kvrwset.KVRWSet{}
		//			err = proto.Unmarshal(nsRwSet.Rwset, kvRwSet)
		//			if err == nil {
		//				if len(kvRwSet.Reads) > 0 {
		//					fmt.Printf("\t\t\tReads: %d\n", len(kvRwSet.Reads))
		//					for _, read := range kvRwSet.Reads {
		//						if read.Version != nil {
		//							fmt.Printf("\t\t\t\tKey: %s, Version: [BlockNum:%d, TxNum:%d]\n",
		//								read.Key, read.Version.BlockNum, read.Version.TxNum)
		//						} else {
		//							fmt.Printf("\t\t\t\tKey: %s, Version: nil\n", read.Key)
		//						}
		//					}
		//				}
		//
		//				if len(kvRwSet.Writes) > 0 {
		//					fmt.Printf("\t\t\tWrites: %d\n", len(kvRwSet.Writes))
		//					for _, write := range kvRwSet.Writes {
		//						valueStr := string(write.Value)
		//						//if len(valueStr) > 100 {
		//						//	valueStr = valueStr[:100] + "..."
		//						//}
		//						fmt.Printf("\t\t\t\tKey: %s, IsDelete: %v, Value: %s\n",
		//							write.Key, write.IsDelete, valueStr)
		//					}
		//				}
		//			}
		//		}
		//	}
		//}
		//
		//fmt.Printf("\tEvent: %s\n", string(chaincodeAction.Events))
		//
		//for _, endorser := range actionPayload.Action.Endorsements {
		//	fmt.Println("endorser", getSubjectFromCert(endorser.Endorser))
		//}
		//
		////// Output detailed JSON for this action
		////fmt.Println("\n  === Action JSON Output ===")
		////actionData := map[string]interface{}{
		////	"chaincodeInvocationSpec": chaincodeInvocationSpec,
		////	"chaincodeAction":         chaincodeAction,
		////	"txReadWriteSet":          txRwSet,
		////}
		////jsonBytes, err := json.MarshalIndent(actionData, "  ", "  ")
		////require.NoError(t, err)
		////fmt.Println(string(jsonBytes))
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

// ECDSASignature represents an ECDSA signature in ASN.1 DER format
type ECDSASignature struct {
	R, S *big.Int
}

// decodeECDSASignature decodes a DER-encoded ECDSA signature into R and S values
func decodeECDSASignature(derSig []byte) (*big.Int, *big.Int, error) {
	var sig ECDSASignature
	_, err := asn1.Unmarshal(derSig, &sig)
	if err != nil {
		return nil, nil, err
	}
	return sig.R, sig.S, nil
}
