package examples

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/stretchr/testify/require"
)

// BenchmarkSHA256 measures native SHA256 performance
func BenchmarkSHA256(b *testing.B) {
	data := make([]byte, 64) // 64 bytes input
	rand.Read(data)

	hasher := sha256.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Reset()
		for i := 0; i < 300; i++ {
			_, _ = hasher.Write(data)
		}
		_ = hasher.Sum(nil)
	}
}

// BenchmarkPoseidon2 measures native Poseidon2 performance
func BenchmarkPoseidon2(b *testing.B) {
	// Poseidon works on Field Elements (Fr), not raw bytes.
	// We simulate converting 64 bytes into 2 Fr elements.

	//var e1, e2 fr.Element
	//e1.SetRandom()
	//e2.SetRandom()
	//d1 := e1.Marshal()
	//d2 := e2.Marshal()
	//d := append(d1, d2...)

	hasher := poseidon2.NewMerkleDamgardHasher()

	d20000 := make([]byte, 20000)
	rand.Read(d20000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Reset()
		//for i := 0; i < 300; i++ {
		//	_, err := hasher.Write(d)
		//	require.NoError(b, err)
		//}
		_, err := hasher.Write(d20000)
		require.NoError(b, err)
		_ = hasher.Sum(nil)
	}
}

/*
실행 방법:
go test -bench=. -benchmem ./circuits/poseidon_bench_test.go

예상 결과 (M1 Pro 기준 대략적 수치):
BenchmarkSHA256-10       20000000        80 ns/op
BenchmarkPoseidon2-10     1000000      1200 ns/op

해석:
SHA-256이 약 15배 빠릅니다. (80ns vs 1.2µs)
하지만 Poseidon2도 1회 해싱에 1.2 마이크로초(0.0000012초)밖에 걸리지 않습니다.

Merkle Tree가 100만 개의 리프를 가진다 해도:
1,000,000 * 1.2µs = 1.2초

Witness 생성에서 1초 늦어지는 대신,
ZK 증명 생성 시간은 수십 초~수 분 단축됩니다.
*/
