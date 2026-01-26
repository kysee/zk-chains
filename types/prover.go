package types

type Prover interface {
	Prove(interface{}) ([][]byte, error)
}
