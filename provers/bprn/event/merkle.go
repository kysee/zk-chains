package event

import (
	"crypto/sha256"

	"github.com/wealdtech/go-merkletree/v2"
)

type Merkleable interface {
	Root() ([]byte, error)
	Proof(int) ([][]byte, error)
}

func Verify(idx int, data []byte, proofHashes [][]byte, root []byte) (bool, error) {

	proof := &merkletree.Proof{
		Hashes: proofHashes,
		Index:  uint64(idx),
	}

	return merkletree.VerifyProofUsing(data, false, proof, [][]byte{root}, &SHA256Hasher{})
}

// SHA256Hasher implements merkletree.HashType using crypto/sha256 (SHA-2-256).
type SHA256Hasher struct{}

func (s *SHA256Hasher) Hash(data ...[]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func (s *SHA256Hasher) HashName() string { return "sha256" }
func (s *SHA256Hasher) HashLength() int  { return sha256.Size }

type IMerkleable interface {
	Root() ([32]byte, error)
}
