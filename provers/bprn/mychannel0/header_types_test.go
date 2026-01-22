package mychannel0

import (
	"fmt"
	"testing"

	"github.com/hyperledger/fabric-protos-go/common"
)

func TestHeaderTypes(t *testing.T) {
	fmt.Println("Fabric Transaction Types:")
	fmt.Println("=========================")

	for i := 0; i <= 10; i++ {
		name := common.HeaderType_name[int32(i)]
		if name != "" {
			fmt.Printf("%d: %s\n", i, name)
		}
	}
}
