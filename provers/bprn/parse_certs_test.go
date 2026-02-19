package bprn

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	fabricmsp "github.com/hyperledger/fabric/msp"
	"github.com/stretchr/testify/require"
)

func TestParseCerts(t *testing.T) {
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
				parseConfigCerts(t, payload)

			case common.HeaderType_ENDORSER_TRANSACTION:
				parseEndorserCerts(t, payload)

			//case common.HeaderType_ORDERER_TRANSACTION:
			//	fmt.Println("\t  [ORDERER_TRANSACTION - System transaction]")

			//case common.HeaderType_MESSAGE:
			//	fmt.Println("\t  [MESSAGE]")

			default:
				fmt.Printf("\t  [Unknown/Unhandled type: %d]\n", channelHeader.Type)
			}
		}
	}
}

var (
	fabricNodeOus             = map[string]*x509.Certificate{}
	endorsementRoleIdentifier = "peer"
)

func parseConfigCerts(t *testing.T, payload *common.Payload) {
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

	appGroup, ok := configEnvelope.Config.ChannelGroup.Groups["Application"]
	if !ok {
		fmt.Println("  No Application group found")
		return
	}

	for orgName, orgGroup := range appGroup.Groups {
		endorsementPolicy, ok := orgGroup.Policies["Endorsement"]
		require.True(t, ok)

		// Type 1 = SIGNATURE policy
		if endorsementPolicy.Policy.Type == 1 {
			sigPolicyEnv := &common.SignaturePolicyEnvelope{}
			err = proto.Unmarshal(endorsementPolicy.Policy.Value, sigPolicyEnv)
			require.NoError(t, err)

			for _, id := range sigPolicyEnv.Identities {
				if id.PrincipalClassification == msp.MSPPrincipal_ROLE {
					mspRole := &msp.MSPRole{}
					err = proto.Unmarshal(id.Principal, mspRole)
					require.NoError(t, err)

					endorsementRoleIdentifier = strings.ToLower(mspRole.Role.String())
				}
			}
		}

		val0, ok := orgGroup.Values["MSP"]
		require.True(t, ok)

		mspConfig := &msp.MSPConfig{}
		err := proto.Unmarshal(val0.Value, mspConfig)
		require.NoError(t, err)
		fmt.Printf("  Org: %s - msgConfig.Type: %d\n", orgName, mspConfig.Type)

		if mspConfig.Type == int32(fabricmsp.FABRIC) {
			fabricMSPConfig := &msp.FabricMSPConfig{}
			err = proto.Unmarshal(mspConfig.Config, fabricMSPConfig)
			require.NoError(t, err)

			fmt.Println("fabricMSPConfig.FabricNodeOus.Enable:", fabricMSPConfig.FabricNodeOus.Enable)
			identifier := fabricMSPConfig.FabricNodeOus.AdminOuIdentifier.OrganizationalUnitIdentifier
			fabricNodeOus[identifier], _ = parseCertWithLabel(identifier, fabricMSPConfig.FabricNodeOus.AdminOuIdentifier.Certificate)
			identifier = fabricMSPConfig.FabricNodeOus.ClientOuIdentifier.OrganizationalUnitIdentifier
			fabricNodeOus[identifier], _ = parseCertWithLabel(identifier, fabricMSPConfig.FabricNodeOus.ClientOuIdentifier.Certificate)
			identifier = fabricMSPConfig.FabricNodeOus.PeerOuIdentifier.OrganizationalUnitIdentifier
			fabricNodeOus[identifier], _ = parseCertWithLabel(identifier, fabricMSPConfig.FabricNodeOus.PeerOuIdentifier.Certificate)
			identifier = fabricMSPConfig.FabricNodeOus.OrdererOuIdentifier.OrganizationalUnitIdentifier
			fabricNodeOus[identifier], _ = parseCertWithLabel(identifier, fabricMSPConfig.FabricNodeOus.OrdererOuIdentifier.Certificate)
			for i, pem := range fabricMSPConfig.RootCerts {
				identifier = fabricMSPConfig.FabricNodeOus.AdminOuIdentifier.OrganizationalUnitIdentifier
				fabricNodeOus["root"], _ = parseCertWithLabel(fmt.Sprintf("Root Cert[%d]", i), pem)
			}
		}

		err = proto.Unmarshal(mspConfig.Config, mspConfig)
	}

	//// Find Orderer group
	//ordererGroup, ok := configEnvelope.Config.ChannelGroup.Groups["Orderer"]
	//if !ok {
	//	fmt.Println("  No Orderer group found")
	//	return
	//}
}

func parseEndorserCerts(t *testing.T, payload *common.Payload) {
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

		// Verify endorsement signatures
		fmt.Printf("  Endorsements: %d\n", len(actionPayload.Action.Endorsements))
		for i, endorsement := range actionPayload.Action.Endorsements {
			// Parse endorser's identity
			serializedIdentity := &msp.SerializedIdentity{}
			err = proto.Unmarshal(endorsement.Endorser, serializedIdentity)
			require.NoError(t, err)

			cert, pubKey := parseCertWithLabel(fmt.Sprintf("Endorser[%d] certificate", i), serializedIdentity.IdBytes)
			require.NotNil(t, cert)
			require.NotNil(t, pubKey)

			issuer, ok := fabricNodeOus[endorsementRoleIdentifier]
			require.NotNil(t, issuer)
			require.True(t, ok)
			require.NoError(t, cert.CheckSignatureFrom(issuer))

			// Signed message = ProposalResponsePayload bytes || Endorser bytes
			msg := append(actionPayload.Action.ProposalResponsePayload, endorsement.Endorser...)
			msgHash := sha256.Sum256(msg)

			// Decode and verify ECDSA signature
			r, s, err := decodeECDSASignature(endorsement.Signature)
			require.NoError(t, err)

			valid := ecdsa.Verify(pubKey, msgHash[:], r, s)
			require.True(t, valid)
		}
	}
}
