package relayer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	cfgtypes "github.com/kysee/zk-chains/provers/types"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/tree"
)

func ListenerMain(config *cfgtypes.Config) {
	// Create and run relayer
	relayer := NewListener(config, NewAPIFetcher(config.RPCEndpoint))

	_, err := relayer.GetTransaction(config.Slot, 0)
	if err != nil {
		log.Fatalf("failed to get transaction: %w", err)
	}

}

type Listener struct {
	config  *cfgtypes.Config
	fetcher cfgtypes.Fetcher
}

// NewListener creates a new Listener with the given APIFetcher
func NewListener(config *cfgtypes.Config, fetcher cfgtypes.Fetcher) *Listener {
	return &Listener{
		config:  config,
		fetcher: fetcher,
	}
}

// GetTransaction retrieves a block by slot and prints the transaction at the given index
func (listener *Listener) GetTransaction(slot uint64, txIdx int) ([]byte, error) {
	// Fetch block by slot
	blockResponse, err := listener.fetcher.Block(slot)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch block at slot %d: %w", slot, err)
	}

	// Get the beacon block from the response
	block := &blockResponse.Data.Message

	// Get transactions from the execution payload
	transactions := block.Body.ExecutionPayload.Transactions

	// Check if txIdx is valid
	if txIdx < 0 || txIdx >= len(transactions) {
		return nil, fmt.Errorf("transaction index %d out of range (block has %d transactions)", txIdx, len(transactions))
	}

	spec := configs.Mainnet
	hFn := tree.GetHashFn()

	// Get the tx and leaf at the specified index
	tx := transactions[txIdx]
	txLeaf := tx.HashTreeRoot(spec, hFn)
	log.Printf("Transaction[%d] Leaf: %v", txIdx, txLeaf)

	// Get ExecutionPayloadHeader from the block
	executionPayloadHeader := block.Body.ExecutionPayload.Header(spec)
	executionPayloadHeaderRoot := executionPayloadHeader.HashTreeRoot(hFn)
	log.Printf("ExecutionPayloadHeaderRoot: %v", executionPayloadHeaderRoot)

	// Generate merkle proof (branch) for the transaction
	branch, err := generateTransactionMerkleProof(transactions, txIdx, spec, hFn)
	if err != nil {
		return nil, fmt.Errorf("failed to generate merkle proof: %w", err)
	}

	log.Printf("Merkle proof (branch) for transaction[%d]:", txIdx)
	for i, sibling := range branch {
		log.Printf("  Branch[%d]: %v", i, sibling)
	}

	// Verify the proof using our implementation
	// Note: SSZ List uses Mixin, so TransactionsRoot = hash(Merkleize(leaves), length)
	verified := verifyTransactionMerkleProof(txLeaf, branch, txIdx, uint64(len(transactions)), executionPayloadHeader.TransactionsRoot, hFn)
	log.Printf("Custom merkle proof verification: %v", verified)

	// Double-check using zrnt's HashTreeRoot (the authoritative implementation)
	calculatedTxRoot := transactions.HashTreeRoot(spec, hFn)
	zrntVerified := bytes.Equal(calculatedTxRoot[:], executionPayloadHeader.TransactionsRoot[:])
	log.Printf("zrnt HashTreeRoot verification: %v (calculated: %v, expected: %v)",
		zrntVerified, calculatedTxRoot, executionPayloadHeader.TransactionsRoot)

	if !zrntVerified {
		return nil, fmt.Errorf("TransactionsRoot mismatch - this should never happen")
	}

	return tx[:], nil
}

// generateTransactionMerkleProof generates a merkle proof (branch) for a transaction at the given index
func generateTransactionMerkleProof(transactions common.PayloadTransactions, txIdx int, spec *common.Spec, hFn tree.HashFn) ([]common.Root, error) {
	count := uint64(len(transactions))
	limit := uint64(spec.MAX_TRANSACTIONS_PER_PAYLOAD)

	if txIdx < 0 || uint64(txIdx) >= count {
		return nil, fmt.Errorf("invalid transaction index: %d", txIdx)
	}

	// Calculate tree depth
	depth := tree.CoverDepth(count)
	limitDepth := tree.CoverDepth(limit)

	// Build all leaves
	leaves := make([]common.Root, count)
	for i := uint64(0); i < count; i++ {
		leaves[i] = transactions[i].HashTreeRoot(spec, hFn)
	}

	// Generate the merkle tree and collect siblings
	branch := make([]common.Root, limitDepth)
	index := uint64(txIdx)

	// Build the tree level by level and collect siblings
	currentLevel := leaves
	for level := uint8(0); level < limitDepth; level++ {
		// Determine sibling index
		siblingIdx := index ^ 1 // XOR with 1 to get sibling

		// Get the sibling at this level
		if siblingIdx < uint64(len(currentLevel)) {
			branch[level] = currentLevel[siblingIdx]
		} else {
			// Use zero hash if sibling doesn't exist
			if level < depth {
				branch[level] = tree.ZeroHashes[level]
			} else {
				branch[level] = tree.ZeroHashes[level]
			}
		}

		// Move to next level (parent level)
		nextLevelSize := (uint64(len(currentLevel)) + 1) / 2
		nextLevel := make([]common.Root, nextLevelSize)
		for i := uint64(0); i < nextLevelSize; i++ {
			leftIdx := i * 2
			rightIdx := leftIdx + 1

			var left, right common.Root
			if leftIdx < uint64(len(currentLevel)) {
				left = currentLevel[leftIdx]
			} else {
				left = tree.ZeroHashes[level]
			}

			if rightIdx < uint64(len(currentLevel)) {
				right = currentLevel[rightIdx]
			} else {
				right = tree.ZeroHashes[level]
			}

			nextLevel[i] = hFn(left, right)
		}

		currentLevel = nextLevel
		index = index / 2

		// Pad to next power of 2 if needed
		if level >= depth-1 && level < limitDepth-1 {
			currentLevel = append(currentLevel, tree.ZeroHashes[level+1])
		}
	}

	return branch, nil
}

// verifyTransactionMerkleProof verifies a merkle proof for SSZ List
// SSZ Lists use: root = hash(Merkleize(leaves), length)
func verifyTransactionMerkleProof(leaf common.Root, branch []common.Root, index int, length uint64, expectedRoot common.Root, hFn tree.HashFn) bool {
	// Step 1: Compute the merkleized root from leaf and branch
	merkleizedRoot := leaf
	idx := uint64(index)

	for _, sibling := range branch {
		if idx%2 == 0 {
			// Current node is left child
			merkleizedRoot = hFn(merkleizedRoot, sibling)
		} else {
			// Current node is right child
			merkleizedRoot = hFn(sibling, merkleizedRoot)
		}
		idx = idx / 2
	}

	log.Printf("Computed MerkleizedRoot: %v", merkleizedRoot)

	// Step 2: Apply Mixin with length (SSZ List specific)
	// Mixin(root, length) = hash(root, length_as_32bytes)
	var lengthRoot common.Root
	binary.LittleEndian.PutUint64(lengthRoot[:], length)

	finalRoot := hFn(merkleizedRoot, lengthRoot)
	log.Printf("After Mixin with length %d: %v", length, finalRoot)
	log.Printf("Expected TransactionsRoot: %v", expectedRoot)

	return bytes.Equal(finalRoot[:], expectedRoot[:])
}
