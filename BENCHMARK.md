## Commit: 39fe78f8

### Features

- Use `[32]uints.U8` instead of `frontend.Variable` for `ScPubKeysHash`

### Benchmark

- goos: darwin
- goarch: amd64
- cpu: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz

| Name              | Value |
|-------------------| ----- |
| Constraints       | 6285865 |
| Public Inputs     | 65 |
| ProofGeneration   | 20618443368 ns/op |
| ProofVerification | 1078106 ns/op |

## Commit: 84347f9b

### Features

- Use sha256 to hash `ScPubKeysHash`
- Verify BlS signature
- Verify SSZ merkle proof of `NextScRoot`

### Benchmark
- goos: darwin  
- goarch: amd64  
- cpu: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz  

| Name              | Value |
|-------------------| ----- |
| Constraints       | 6285865 |
| Public Inputs     | 34 |
| ProofGeneration   | 20899166401 ns/op |
| ProofVerification | 1076800 ns/op |
