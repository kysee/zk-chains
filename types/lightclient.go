package types

import (
	"crypto/sha256"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	zrntaltair "github.com/protolambda/zrnt/eth2/beacon/altair"
	zrntcommon "github.com/protolambda/zrnt/eth2/beacon/common"
)

type SyncCommittee struct {
	Period  string                 `json:"period"`
	Pubkeys []zrntcommon.BLSPubkey `json:"pubkeys"`
}

type SyncAggregate struct {
	SyncCommitteeBits      string `json:"sync_committee_bits"`
	SyncCommitteeSignature string `json:"sync_committee_signature"`
}

type LightClientUpdate struct {
	Data struct {
		AttestedHeader struct {
			Beacon          zrntcommon.BeaconBlockHeader `json:"beacon"`
			Execution       ExecutionPayloadHeader       `json:"execution"`
			ExecutionBranch []string                     `json:"execution_branch"`
		} `json:"attested_header"`
		NextSyncCommittee       zrntcommon.SyncCommittee `json:"next_sync_committee"`
		NextSyncCommitteeBranch [6]zrntcommon.Root       `json:"next_sync_committee_branch"`
		SyncAggregate           zrntaltair.SyncAggregate `json:"sync_aggregate"`
		SignatureSlot           string                   `json:"signature_slot"`
	} `json:"data"`
	Version string `json:"version"`
}

type ExecutionPayloadHeader struct {
	ParentHash       string `json:"parent_hash"`
	FeeRecipient     string `json:"fee_recipient"`
	StateRoot        string `json:"state_root"`
	ReceiptsRoot     string `json:"receipts_root"`
	LogsBloom        string `json:"logs_bloom"`
	PrevRandao       string `json:"prev_randao"`
	BlockNumber      string `json:"block_number"`
	GasLimit         string `json:"gas_limit"`
	GasUsed          string `json:"gas_used"`
	Timestamp        string `json:"timestamp"`
	ExtraData        string `json:"extra_data"`
	BaseFeePerGas    string `json:"base_fee_per_gas"`
	BlockHash        string `json:"block_hash"`
	TransactionsRoot string `json:"transactions_root"`
	WithdrawalsRoot  string `json:"withdrawals_root"`
	BlobGasUsed      string `json:"blob_gas_used"`
	ExcessBlobGas    string `json:"excess_blob_gas"`
}

func ParseSyncCommitteeBits(bitsBytes []byte) []bool {
	bits := make([]bool, 512)
	for i := 0; i < 512; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		if byteIndex < len(bitsBytes) {
			bits[i] = (bitsBytes[byteIndex] & (1 << bitIndex)) != 0
		}
	}
	return bits
}

// Aggregate public keys using gnark-crypto (native BLS12-381)
func AggregatePublicKeys(pubkeys []zrntcommon.BLSPubkey, bits []bool) (bls12381.G1Affine, int, error) {
	var aggPubkey bls12381.G1Affine
	aggPubkey.SetInfinity() // Start with identity element

	count := 0
	for i, participate := range bits {
		if !participate || i >= len(pubkeys) {
			continue
		}
		var pubkey bls12381.G1Affine
		_, err := pubkey.SetBytes(pubkeys[i][:])
		if err != nil {
			return aggPubkey, 0, fmt.Errorf("failed to deserialize pubkey %d: %v", i, err)
		}

		// Add to aggregate
		aggPubkey.Add(&aggPubkey, &pubkey)
		count++
	}

	if count == 0 {
		return aggPubkey, 0, fmt.Errorf("no public keys to aggregate")
	}

	return aggPubkey, count, nil
}

// ComputeScPubKeysHash computes a SHA256 commitment to the sync committee public keys
// This matches the commitment computation in the circuit
//
//	func ComputeScPubKeysHash(pubkeys []bls12381.G1Affine) [32]byte {
//		hasher := sha256.New()
//
//		// Hash each public key's X coordinate (48 bytes in compressed form)
//		for i := 0; i < 512; i++ {
//			// Serialize the G1 point to compressed form (48 bytes)
//			// For the circuit, we only hash X coordinates
//			pubkeyBytes := pubkeys[i].X.Bytes()
//			hasher.Write(pubkeyBytes[:])
//		}
//
//		var commitment [32]byte
//		copy(commitment[:], hasher.Sum(nil))
//		return commitment
//	}
func ComputeScPubKeysHash(pubkeys []bls12381.G1Affine) [32]byte {
	hasher := sha256.New()

	// Hash only the first two limbs (Limbs[0], Limbs[1]) of each X coordinate for efficiency
	// This matches the circuit which hashes Limbs[0] and Limbs[1] in big-endian format
	for i := 0; i < len(pubkeys); i++ {
		// Get the X coordinate as bytes (big-endian, 48 bytes = 384 bits)
		xBytes := pubkeys[i].X.Bytes()
		bytesToHash := xBytes[32:] // [32..48] = 128bits. it's for X.Limbs[1] || X.Limbs[0] in the circuit
		hasher.Write(bytesToHash)
		//if i < 10 {
		//	fmt.Printf("pubkey[%d] to hash: 0x%x\n", i, bytesToHash)
		//}
	}

	var commitment [32]byte
	copy(commitment[:], hasher.Sum(nil))
	return commitment
}

// ComputeDomain computes the BLS domain for sync committee signatures
// domain = domain_type || fork_data_root[:28]
// where fork_data_root = hash_tree_root(ForkData(fork_version, genesis_validators_root))
func ComputeDomain(domainType []byte, forkVersion []byte, genesisValidatorsRoot []byte) ([32]byte, error) {
	var domain [32]byte

	// Validate input lengths
	if len(domainType) != 4 {
		return domain, fmt.Errorf("domainType must be 4 bytes, got %d", len(domainType))
	}
	if len(forkVersion) != 4 {
		return domain, fmt.Errorf("forkVersion must be 4 bytes, got %d", len(forkVersion))
	}
	if len(genesisValidatorsRoot) != 32 {
		return domain, fmt.Errorf("genesisValidatorsRoot must be 32 bytes, got %d", len(genesisValidatorsRoot))
	}

	// Step 1: Compute fork_data_root
	// Serialize fork_version as 32-byte chunk (little-endian + zero padding)
	var forkVersionChunk [32]byte
	copy(forkVersionChunk[:4], forkVersion[:4])
	// Remaining 28 bytes are already zero

	// Hash fork_version chunk with genesis_validators_root
	hasher := sha256.New()
	hasher.Write(forkVersionChunk[:])
	hasher.Write(genesisValidatorsRoot[:32])
	forkDataRoot := hasher.Sum(nil)

	// Step 2: Compute domain = domain_type (4 bytes) || fork_data_root[:28]
	copy(domain[:4], domainType[:4])
	copy(domain[4:], forkDataRoot[:28])

	return domain, nil
}

type ProofData struct {
	Proof         []HexBytes `json:"proof"`
	Commitments   []HexBytes `json:"commitments"`
	CommitmentPok []HexBytes `json:"commitmentPok"`
}

func CreateProofData(proofSolidity []byte) *ProofData {
	// A, B, C
	proof := make([]HexBytes, 8)
	for i := 0; i < len(proof); i++ {
		proof[i] = proofSolidity[i*bn254_fr.Bytes : (i+1)*bn254_fr.Bytes]
	}

	startIdx0 := 8*bn254_fr.Bytes + 4
	commitments := make([]HexBytes, 4)
	for i := 0; i < len(commitments); i++ {
		startIdx := startIdx0 + (i * bn254_fr.Bytes)
		commitments[i] = proofSolidity[startIdx : startIdx+bn254_fr.Bytes]
	}

	return &ProofData{
		Proof:         proof,
		Commitments:   commitments[0:2],
		CommitmentPok: commitments[2:4],
	}
}
