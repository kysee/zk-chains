package main

import (
	"bytes"
	"crypto/sha256"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
)

func main() {
	// Read the verifying key from file (to ensure consistency with proving key)
	vkFile, err := os.Open("../.build/Eth2ScUpdateCircuit.vk")
	if err != nil {
		panic(err)
	}
	defer vkFile.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		panic(err)
	}

	if err := os.MkdirAll("contracts", 0755); err != nil {
		panic(err)
	}
	// Solidity verifier 생성
	var buf bytes.Buffer
	err = vk.ExportSolidity(&buf, solidity.WithHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("contracts/Eth2ScUpdateVerifier.sol", buf.Bytes(), 0644)
	if err != nil {
		panic(err)
	}

	println("✅ Solidity verifier generated: contracts/Eth2ScUpdateVerifier.sol")
}
