package event

import "encoding/binary"

var _ IMerkleable = (*PostMessageEventLogValue)(nil)

type PostMessageEventLogValue struct {
	*merkleableType
	SrcChainId string `json:"srcChainId"`
	SrcDappId  string `json:"srcDappId"`
	SrcAcctId  string `json:"srcAcctId"`
	DstChainId string `json:"dstChainId"`
	DstDappId  string `json:"dstDappId"`
	DstAcctId  string `json:"dstAcctId"`
	MsgIdx     uint64 `json:"msgIdx"`
	MsgPayload []byte `json:"msgPayload"`
}

func NewPostMessageEventLogValue() *PostMessageEventLogValue {
	ret := &PostMessageEventLogValue{}
	ret.merkleableType = newMerkleableType(ret.Leaves)
	return ret
}
func NewPostMessageEventLogValueWith(srcChainId, srcDappId, srcAcctId, dstChainId, dstDappId, dstAcctId string, msgIdx uint64, msgPayload []byte) *PostMessageEventLogValue {
	ret := &PostMessageEventLogValue{
		SrcChainId: srcChainId,
		SrcDappId:  srcDappId,
		SrcAcctId:  srcAcctId,
		DstChainId: dstChainId,
		DstDappId:  dstDappId,
		DstAcctId:  dstAcctId,
		MsgIdx:     msgIdx,
		MsgPayload: msgPayload,
	}
	ret.merkleableType = newMerkleableType(ret.Leaves)
	return ret
}

func (p *PostMessageEventLogValue) Leaves() [][]byte {
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
