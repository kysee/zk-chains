package event

import (
	"crypto/sha256"

	"github.com/wealdtech/go-merkletree/v2"
)

type IMerkleable interface {
	Root() ([]byte, error)
	Proof(int) ([][]byte, error)
	Leaves() [][]byte
}

type merkleableType struct {
	leaves func() [][]byte
	tree   *merkletree.MerkleTree
}

func newMerkleableType(leaves func() [][]byte) *merkleableType {
	return &merkleableType{leaves: leaves}
}

func (p *merkleableType) Root() ([]byte, error) {
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

func (p *merkleableType) Proof(idx int) ([][]byte, error) {
	if p.tree == nil {
		_, _ = p.Root()
	}

	proof, err := p.tree.GenerateProofWithIndex(uint64(idx), 0)
	if err != nil {
		return nil, err
	}

	return proof.Hashes, nil
}

func (p *merkleableType) Leaves() [][]byte {
	panic("not implemented")
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
