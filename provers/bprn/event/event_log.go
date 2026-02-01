package event

type EventLog struct {
	Type  string      `json:"type"`
	Value IMerkleable `json:"value"` // e.g. PostMessageEventLog.Marshal()
}

func (evtlog *EventLog) Root() ([]byte, error) {
	return evtlog.Value.Root()
}

func (evtlog *EventLog) Proof(idx int) ([][]byte, error) {
	return evtlog.Value.Proof(idx)
}

func (evtlog *EventLog) Leaves() ([][]byte, error) {
	return evtlog.Value.Leaves()
}

type EventPayload struct {
	*merkleableType
	Logs []*EventLog
}

func NewEventPayload(evtLogs ...*EventLog) *EventPayload {
	ret := &EventPayload{
		Logs: evtLogs,
	}
	ret.merkleableType = newMerkleableType(ret.Leaves)
	return ret
}

func (ep *EventPayload) Leaves() ([][]byte, error) {
	leaves := make([][]byte, len(ep.Logs))
	for i, l := range ep.Logs {
		leaf, err := l.Root()
		if err != nil {
			return nil, err
		}
		leaves[i] = leaf
	}
	return leaves, nil
}
