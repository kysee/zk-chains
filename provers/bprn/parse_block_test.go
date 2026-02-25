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
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/event"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/events/deliverclient/seek"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/stretchr/testify/require"
)

// ordererPubKeys stores orderer public keys parsed from config blocks.
var ordererPubKeys []*ecdsa.PublicKey

// endorserPubKeys stores endorser public keys parsed from config blocks.
var endorserPubKeys []*ecdsa.PublicKey

func TestParseBlock0(t *testing.T) {
	client, err := NewFabricClient("./localchannel0/connection-profile.json")
	require.NoError(t, err)

	// Reset global public keys
	ordererPubKeys = nil
	endorserPubKeys = nil

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

func parseConfigTransaction(t *testing.T, payload *common.Payload) {
	fmt.Println("  Type: CONFIG - Channel configuration")

	// Parse as ConfigEnvelope
	configEnvelope := &common.ConfigEnvelope{}
	err := proto.Unmarshal(payload.Data, configEnvelope)
	require.NoError(t, err)

	if configEnvelope.Config == nil {
		return
	}

	//fmt.Printf("  Sequence: %d\n", configEnvelope.Config.Sequence)
	//
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
			if _, pk := parseCertWithLabel("Server TLS Cert", consenter.ServerTlsCert); pk != nil {
				ordererPubKeys = append(ordererPubKeys, pk)
			}
			//
			//// Parse ClientTlsCert
			//if pk := parseCertWithLabel("Client TLS Cert", consenter.ClientTlsCert); pk != nil {
			//	ordererPubKeys = append(ordererPubKeys, pk)
			//}
		}
	}

	// Extract endorser public keys from Application group Policies["Endorsement"]
	appGroup, ok := configEnvelope.Config.ChannelGroup.Groups["Application"]
	if !ok {
		fmt.Println("  No Application group found")
		return
	}

	// Reset endorserPubKeys - rebuild from current config
	endorserPubKeys = nil

	for orgName, orgGroup := range appGroup.Groups {
		endorsementPolicy, ok := orgGroup.Policies["Endorsement"]
		if !ok {
			fmt.Printf("\n  === Endorser Org: %s - No Endorsement policy ===\n", orgName)
			continue
		}

		fmt.Printf("\n  === Endorser Org: %s (Policy Type: %d) ===\n", orgName, endorsementPolicy.Policy.Type)

		// Type 1 = SIGNATURE policy
		if endorsementPolicy.Policy.Type == 1 {
			sigPolicyEnv := &common.SignaturePolicyEnvelope{}
			err = proto.Unmarshal(endorsementPolicy.Policy.Value, sigPolicyEnv)
			require.NoError(t, err)

			fmt.Printf("    Identities: %d\n", len(sigPolicyEnv.Identities))

			for i, identity := range sigPolicyEnv.Identities {
				fmt.Printf("    Identity[%d]: Classification=%s\n", i, identity.PrincipalClassification.String())

				switch identity.PrincipalClassification {
				case msp.MSPPrincipal_IDENTITY:
					// Principal contains SerializedIdentity with actual certificate
					serializedIdentity := &msp.SerializedIdentity{}
					err = proto.Unmarshal(identity.Principal, serializedIdentity)
					require.NoError(t, err)

					fmt.Printf("      MSP ID: %s\n", serializedIdentity.Mspid)
					if _, pk := parseCertWithLabel(fmt.Sprintf("Endorser Identity[%d]", i), serializedIdentity.IdBytes); pk != nil {
						endorserPubKeys = append(endorserPubKeys, pk)
					}

				case msp.MSPPrincipal_ROLE:
					mspRole := &msp.MSPRole{}
					err = proto.Unmarshal(identity.Principal, mspRole)
					require.NoError(t, err)
					fmt.Printf("      MSP ID: %s, Role: %s\n", mspRole.MspIdentifier, mspRole.Role.String())
				}
			}
		}
	}

	fmt.Printf("\n  Total stored endorser public keys: %d\n", len(endorserPubKeys))
}

func parseCertWithLabel(label string, certPEM []byte) (*x509.Certificate, *ecdsa.PublicKey) {
	if len(certPEM) == 0 {
		return nil, nil
	}

	fmt.Printf("\n%v\n", string(certPEM))

	block, _ := pem.Decode(certPEM)
	if block == nil {
		fmt.Printf("    %s: failed to decode PEM\n", label)
		return nil, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("    %s: failed to parse certificate: %v\n", label, err)
		return nil, nil
	}

	fmt.Printf("    %s:\n", label)
	fmt.Printf("      Issuer: %s\n", cert.Issuer.String())
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
		return cert, pubKey
	} else {
		fmt.Printf("      Public Key: (not ECDSA)\n")
		return nil, nil
	}
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

		_, pubKey := parseCertWithLabel("orderer MSP certificate", serializedIdentity.IdBytes)

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

		//if err == nil && chaincodeInvocationSpec.ChaincodeSpec != nil {
		//	fmt.Printf("\tChaincode: %s\n", chaincodeInvocationSpec.ChaincodeSpec.ChaincodeId.Name)
		//	if len(chaincodeInvocationSpec.ChaincodeSpec.Input.Args) > 0 {
		//		if len(chaincodeInvocationSpec.ChaincodeSpec.Input.Args) > 1 {
		//			fmt.Printf("\tArgs:\n")
		//			for k := 0; k < len(chaincodeInvocationSpec.ChaincodeSpec.Input.Args); k++ {
		//				fmt.Printf("\t\t[%d]: %s\n", k, string(chaincodeInvocationSpec.ChaincodeSpec.Input.Args[k]))
		//			}
		//		}
		//	}
		//}

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

		// Verify endorsement signatures
		fmt.Printf("  Endorsements: %d\n", len(actionPayload.Action.Endorsements))
		for i, endorsement := range actionPayload.Action.Endorsements {
			// Parse endorser's identity
			serializedIdentity := &msp.SerializedIdentity{}
			err = proto.Unmarshal(endorsement.Endorser, serializedIdentity)
			require.NoError(t, err)

			_, pubKey := parseCertWithLabel(fmt.Sprintf("Endorser[%d] certificate", i), serializedIdentity.IdBytes)
			if pubKey == nil {
				fmt.Printf("  Endorsement[%d]: failed to parse endorser certificate\n", i)
				continue
			}

			// Signed message = ProposalResponsePayload bytes || Endorser bytes
			msg := append(actionPayload.Action.ProposalResponsePayload, endorsement.Endorser...)
			msgHash := sha256.Sum256(msg)

			// Decode and verify ECDSA signature
			r, s, err := decodeECDSASignature(endorsement.Signature)
			require.NoError(t, err)

			valid := ecdsa.Verify(pubKey, msgHash[:], r, s)

			// Check if endorser's key matches any stored endorser public key
			isKnown := false
			for _, storedKey := range endorserPubKeys {
				if storedKey.X.Cmp(pubKey.X) == 0 && storedKey.Y.Cmp(pubKey.Y) == 0 {
					isKnown = true
					break
				}
			}
			fmt.Printf("  Endorsement[%d]: valid=%v, knownEndorser=%v, MSP=%s\n", i, valid, isKnown, serializedIdentity.Mspid)
			require.True(t, valid)
			//require.True(t, isKnown)
		}
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
