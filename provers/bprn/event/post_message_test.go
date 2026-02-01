package event

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecode(t *testing.T) {
	evtValue := NewPostMessageEventLogValueWith(
		"srcChainId",
		"srcDappId",
		"srcAcctId",
		"dstChainId",
		"dstDappId",
		"dstAcctId",
		uint64(100),
		[]byte("hello world"),
	)
	root, err := evtValue.Root()
	require.NoError(t, err)

	fmt.Printf("root: %x\n", root)

	fmt.Println("---")
	leaves, err := evtValue.Leaves()
	require.NoError(t, err)
	for i, leaf := range leaves {
		fmt.Printf("leaf[%d]: %s, %x\n", i, leaf, sha256.Sum256(leaf))
	}

	depth := bits.Len(uint(len(leaves) - 1))
	for d := 0; d <= depth; d++ {
		fmt.Println("--- d:", d)
		pollard := evtValue.tree.Pollard(d)
		for i, sibling := range pollard {
			fmt.Printf("pollard_%d [%d]: %x\n", d, i, sibling)
		}
	}

	branches, err := evtValue.Proof(2)
	require.NoError(t, err)
	require.Equal(t, depth, len(branches))

	fmt.Println("--- depth:", depth)
	fmt.Printf("--- leaf[%d]: %s, %x\n", 2, leaves[2], sha256.Sum256(leaves[2]))
	fmt.Println("--- branches:")
	for i, branch := range branches {
		fmt.Printf("branch[%d]: %x\n", i, branch)
	}
}
