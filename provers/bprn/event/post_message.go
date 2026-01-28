package event

import (
	"encoding/binary"

	"github.com/wealdtech/go-merkletree/v2"
)

type PostMessageEventLogValue struct {
	SrcChainId string `json:"srcChainId"`
	SrcDappId  string `json:"srcDappId"`
	SrcAcctId  string `json:"srcAcctId"`
	DstChainId string `json:"dstChainId"`
	DstDappId  string `json:"dstDappId"`
	DstAcctId  string `json:"dstAcctId"`
	MsgIdx     uint64 `json:"msgIdx"`
	MsgPayload []byte `json:"msgPayload"`

	tree *merkletree.MerkleTree
}

func (p *PostMessageEventLogValue) Root() ([]byte, error) {
	tree, err := merkletree.NewTree(
		merkletree.WithData(p.leaves()),
		merkletree.WithHashType(&SHA256Hasher{}),
	)
	if err != nil {
		return nil, err
	}

	p.tree = tree

	size := len(tree.Root())
	result := make([]byte, size)
	copy(result, tree.Root())
	return result, nil
}

func (p *PostMessageEventLogValue) Proof(idx int) ([][]byte, error) {
	if p.tree == nil {
		_, _ = p.Root()
	}

	proof, err := p.tree.GenerateProofWithIndex(uint64(idx), 0)
	if err != nil {
		return nil, err
	}

	return proof.Hashes, nil
}

func (p *PostMessageEventLogValue) leaves() [][]byte {
	msgIdxBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(msgIdxBytes, p.MsgIdx)

	return [][]byte{
		[]byte(p.SrcChainId),
		[]byte(p.SrcDappId),
		[]byte(p.SrcAcctId),
		[]byte(p.DstChainId),
		[]byte(p.DstDappId),
		[]byte(p.DstAcctId),
		msgIdxBytes,
		p.MsgPayload,
	}
}
