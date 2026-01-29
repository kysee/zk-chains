package event

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecode(t *testing.T) {
	evtValue := NewPostMessageEventLogValueWith(
		fmt.Sprintf("srcChainId"),
		fmt.Sprintf("srcDappId"),
		fmt.Sprintf("srcAcctId"),
		fmt.Sprintf("dstChainId"),
		fmt.Sprintf("dstDappId"),
		fmt.Sprintf("dstAcctId"),
		uint64(100),
		[]byte(fmt.Sprintf("hello world")),
	)
	root, err := evtValue.Root()
	require.NoError(t, err)

	fmt.Printf("root: %x\n", root)
}
