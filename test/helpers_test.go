package test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/stretchr/testify/require"
)

/*
{
	"blockHash": "0xb60f2a3121caf74169a726560d3cd026b0761d9929da0dae516cfdd9d064b651",
	"blockNumber": "0x16faea6",
	"contractAddress": null,
	"cumulativeGasUsed": "0x5208",
	"effectiveGasPrice": "0x1b18aa5",
	"from": "0x5d9f6433771c734130fea4bc814f7be3eb454331",
	"gasUsed": "0x5208",
	"logs": [],
	"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"status": "0x1",
	"to": "0x5d9f6433771c734130fea4bc814f7be3eb454331",
	"transactionHash": "0x7eb2dc8a1631c7644c27b9d6f289953aef9267e228fe289aab416c111c04cd78",
	"transactionIndex": "0x0",
	"type": "0x2"
},
*/

func TestBlockReceipts(t *testing.T) {
	blockReceiptsBytes, err := os.ReadFile("./blockReceipts.json")
	require.NoError(t, err)

	var blockReceipts types.Receipts
	err = json.Unmarshal(blockReceiptsBytes, &blockReceipts)
	require.NoError(t, err)

	expectedRoot, _ := hex.DecodeString("c08151d34b457e471dd711167ffd3cb716c56a770ced7c00a79dda28e9426113")
	t.Log("blockReceipts length:", len(blockReceipts))
	t.Logf("expected receiptsRoot: %x", expectedRoot)

	receiptsRoot := types.DeriveSha(blockReceipts, trie.NewStackTrie(nil))
	require.Equal(t, expectedRoot, receiptsRoot[:])
	t.Logf("computed receiptsRoot: %x", receiptsRoot)

	// Generate merkle proof for blockReceipts[10]
	targetIndex := 200
	proofDb, _, err := GenerateReceiptProof(blockReceipts, targetIndex)
	require.NoError(t, err)
	t.Logf("Generated merkle proof for receipt[%d]", targetIndex)

	// Network transmission example
	proofNodes := ExtractProofNodes(proofDb)
	nodeBytesSize := 0
	for _, node := range proofNodes {
		nodeBytesSize += len(node)
	}
	t.Logf("Extracted %d proof nodes (%d B)for transmission", len(proofNodes), nodeBytesSize)

	// Simulate network transmission (would normally be JSON/RLP encoded)
	// On receiving side, reconstruct the proofDb
	// This should be on-chain operations
	reconstructedProofDb := ProofNodesToDatabase(proofNodes)

	// Verify with reconstructed proof
	value, err := VerifyReceiptProof(receiptsRoot, targetIndex, reconstructedProofDb)
	require.NoError(t, err)
	t.Logf("Verification successful with reconstructed proof from network")

	// Decode the value to Receipt
	// Must use UnmarshalBinary because blockReceipts.EncodeIndex uses typed encoding
	// Note: The proof only contains consensus fields (Status, CumulativeGasUsed, Bloom, Logs)
	// Derived fields (TxHash, GasUsed, BlockHash, etc.) are not included in the trie
	var decodedReceipt types.Receipt
	err = decodedReceipt.UnmarshalBinary(value)
	require.NoError(t, err)

	t.Logf("Decoded receipt (consensus fields only):")
	t.Logf("  Type: %d", decodedReceipt.Type)
	t.Logf("  Status: %d", decodedReceipt.Status)
	t.Logf("  CumulativeGasUsed: %d", decodedReceipt.CumulativeGasUsed)
	t.Logf("  Bloom: %x", decodedReceipt.Bloom[:8]) // First 8 bytes
	t.Logf("  Logs: %d", len(decodedReceipt.Logs))

	// Verify consensus fields match the original
	require.Equal(t, blockReceipts[targetIndex].Type, decodedReceipt.Type)
	require.Equal(t, blockReceipts[targetIndex].Status, decodedReceipt.Status)
	require.Equal(t, blockReceipts[targetIndex].CumulativeGasUsed, decodedReceipt.CumulativeGasUsed)
	require.Equal(t, blockReceipts[targetIndex].Bloom, decodedReceipt.Bloom)
	require.Equal(t, len(blockReceipts[targetIndex].Logs), len(decodedReceipt.Logs))

	// Note: Derived fields like TxHash, GasUsed, BlockHash are not in the proof
	// They need to be computed using DeriveFields() if needed
	t.Logf("Decoded receipt consensus fields match original!")

}

// GenerateReceiptProof generates a merkle proof for a specific receipt at the given index.
// Uses go-ethereum's trie.Prove function. Returns a proof database that can be used with trie.VerifyProof.
func GenerateReceiptProof(receipts types.Receipts, index int) (*memorydb.Database, []byte, error) {
	// Build the trie from all receipts using the same encoding as DeriveSha
	db := rawdb.NewMemoryDatabase()
	trieDB := triedb.NewDatabase(db, nil)
	tr := trie.NewEmpty(trieDB)

	// Insert all receipts into the trie using EncodeIndex (same as DeriveSha)
	for i := range receipts {
		key := rlp.AppendUint64(nil, uint64(i))
		var buf bytes.Buffer
		receipts.EncodeIndex(i, &buf)
		tr.MustUpdate(key, buf.Bytes())
	}

	// Generate proof for the target index using trie.Prove
	proofDb := memorydb.New()
	targetKey := rlp.AppendUint64(nil, uint64(index))
	if err := tr.Prove(targetKey, proofDb); err != nil {
		return nil, nil, err
	}

	return proofDb, targetKey, nil
}

// VerifyReceiptProof verifies a merkle proof for a receipt.
// Uses go-ethereum's trie.VerifyProof function.
func VerifyReceiptProof(root common.Hash, targetIndex int, proofDb *memorydb.Database) ([]byte, error) {
	// Calculate the key from the target index
	targetKey := rlp.AppendUint64(nil, uint64(targetIndex))

	// trie.VerifyProof checks if the proof is valid for the given root and key
	// If it succeeds, the proof is valid - no need to check the value
	return trie.VerifyProof(root, targetKey, proofDb)
}

// ExtractProofNodes extracts proof nodes from proofDb for network transmission
func ExtractProofNodes(proofDb *memorydb.Database) [][]byte {
	var proofNodes [][]byte
	iter := proofDb.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		proofNodes = append(proofNodes, common.CopyBytes(iter.Value()))
	}

	return proofNodes
}

// ProofNodesToDatabase converts proof nodes back to memorydb.Database
func ProofNodesToDatabase(proofNodes [][]byte) *memorydb.Database {
	proofDb := memorydb.New()

	for _, node := range proofNodes {
		hash := crypto.Keccak256(node)
		_ = proofDb.Put(hash, node)
	}

	return proofDb
}
