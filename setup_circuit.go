package main

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/kysee/zk-chains/circuits"
)

const rootDir = "."

func main() {
	_, _, vk, err := SetupCircuit()
	if err != nil {
		println("error", err)
		return
	}

	if err := CreateSolidity(vk); err != nil {
		println("error", err)
	}
}

func SetupCircuit() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	logger.Disable()

	ccsPath := filepath.Join(rootDir, ".build/ScUpdateVerifierCircuit.ccs")
	pkPath := filepath.Join(rootDir, ".build/ScUpdateVerifierCircuit.pk")
	vkPath := filepath.Join(rootDir, ".build/ScUpdateVerifierCircuit.vk")

	//
	// Step 1: Compile circuit and save to file
	println("🕧 Compile ScUpdateVerifierCircuit circuit...")
	// Compile with BN254 scalar field (for emulated BLS12-381)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.ScUpdateVerifierCircuit{})
	if err != nil {
		return nil, nil, nil, err
	}

	println("Constraint system saving to", ccsPath, "...")
	fccs, _ := os.Create(ccsPath)
	defer fccs.Close()
	_, err = ccs.WriteTo(fccs)
	if err != nil {
		return nil, nil, nil, err
	}
	println("constraints:", ccs.GetNbConstraints(), "public inputs:", ccs.GetNbPublicVariables())
	println("✅ Compile complete")

	//
	// Step 2: Setup (generate proving and verifying keys)
	println("🕧 Generating proving and verifying keys...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, err
	}

	println("Proving key saving to", pkPath, "...")
	fpk, _ := os.Create(pkPath)
	defer fpk.Close()
	_, err = pk.WriteTo(fpk)
	if err != nil {
		return nil, nil, nil, err
	}

	println("Verifying key saving to", vkPath, "...")
	fvk, _ := os.Create(vkPath)
	defer fvk.Close()
	_, err = vk.WriteTo(fvk)
	if err != nil {
		return nil, nil, nil, err
	}
	println("✅ Setup complete")

	return ccs, pk, vk, nil
}

func CreateSolidity(vk groth16.VerifyingKey) error {
	path := "verifiers/eth2/contracts/ScUpdateVerifier.sol"

	// Solidity verifier 생성
	var buf bytes.Buffer
	err := vk.ExportSolidity(&buf, solidity.WithHashToFieldFunction(sha256.New()))
	if err != nil {
		return err
	}

	err = os.WriteFile(path, buf.Bytes(), 0644)
	if err != nil {
		return err
	}

	println("✅ Solidity verifier generate to", path)
	return nil
}
