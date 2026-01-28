package event

import (
	"encoding/json"
	"errors"

	"github.com/wealdtech/go-merkletree/v2"
)

type EventLog struct {
	Type  string `json:"type"`
	Value []byte `json:"value"` // e.g. PostMessageEventLog.Marshal()
}

func (evtlog *EventLog) Root() ([]byte, error) {
	switch evtlog.Type {
	case "PostMessageEventLogValue":
		var logVal PostMessageEventLogValue
		if err := json.Unmarshal(evtlog.Value, &logVal); err != nil {
			return nil, err
		}
		return logVal.Root()
	}
	return nil, errors.New("unsupported event log")
}

type EventPayload struct {
	Logs []*EventLog

	tree *merkletree.MerkleTree
}

func (ep *EventPayload) Root() ([]byte, error) {
	data := make([][]byte, len(ep.Logs))
	for i, l := range ep.Logs {
		root, err := l.Root()
		if err != nil {
			return nil, err
		}
		data[i] = root
	}
	tree, err := merkletree.NewTree(
		merkletree.WithData(data),
		merkletree.WithHashType(&SHA256Hasher{}),
	)
	if err != nil {
		return nil, err
	}

	ep.tree = tree

	size := len(tree.Root())
	result := make([]byte, size)
	copy(result, tree.Root())
	return result, nil
}

func (ep *EventPayload) Proof(idx int) ([][]byte, error) {
	if ep.tree == nil {
		_, _ = ep.Root()
	}

	proof, err := ep.tree.GenerateProofWithIndex(uint64(idx), 0)
	if err != nil {
		return nil, err
	}

	return proof.Hashes, nil
}
