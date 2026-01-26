package circuits

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

func LoadOrSetupCircuit_Groth16(outDir string, c frontend.Circuit) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var err error

	t := reflect.TypeOf(c)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	circuitName := t.Name()

	ccsPath := filepath.Join(outDir, fmt.Sprintf("%s_groth16.ccs", circuitName))
	pkPath := filepath.Join(outDir, fmt.Sprintf("%s_groth16.pk", circuitName))
	vkPath := filepath.Join(outDir, fmt.Sprintf("%s_groth16.vk", circuitName))

	// Step 1: Circuit compile
	fCcs, err := os.Open(ccsPath)
	defer fCcs.Close()

	if err != nil {
		fmt.Println("[groth16] Compiling", circuitName, "...")
		// Compile with BN254 scalar field (for emulated BLS12-381)
		ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
		if err != nil {
			panic(err)
		}
		fCcs, err = os.Create(ccsPath)
		_, _ = ccs.WriteTo(fCcs)
	} else {
		fmt.Println("[groth16] Loading", circuitName, "...")

		ccs = groth16.NewCS(ecc.BN254)
		_, err = ccs.ReadFrom(fCcs)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("[groth16] Number of constraints: %d\n", ccs.GetNbConstraints())
	fmt.Printf("[groth16] Number of public inputs: %d\n", ccs.GetNbPublicVariables())
	fmt.Printf("[groth16] Number of secret inputs: %d\n", ccs.GetNbSecretVariables())

	// Step 2: Setup (generate proving and verifying keys)
	fpk, err0 := os.Open(pkPath)
	defer fpk.Close()
	fvk, err1 := os.Open(vkPath)
	defer fvk.Close()

	if err0 != nil || err1 != nil {
		fmt.Println("[groth16] Generating proving and verifying keys...")
		pk, vk, err = groth16.Setup(ccs)
		if err != nil {
			panic(err)
		}
		fpk, _ = os.Create(pkPath)
		_, _ = pk.WriteTo(fpk)

		fvk, _ = os.Create(vkPath)
		_, _ = vk.WriteTo(fvk)
	} else {
		fmt.Println("[groth16] Loading proving and verifying keys...")
		pk = groth16.NewProvingKey(ecc.BN254)
		vk = groth16.NewVerifyingKey(ecc.BN254)
		if _, err := pk.ReadFrom(fpk); err != nil {
			panic(err)
		}
		if _, err := vk.ReadFrom(fvk); err != nil {
			panic(err)
		}
	}
	fmt.Println("[groth16] ✓ Setup complete")
	return ccs, pk, vk
}

func LoadOrSetupCircuit_Plonk(outDir string, c frontend.Circuit) (constraint.ConstraintSystem, plonk.ProvingKey, plonk.VerifyingKey) {
	var ccs constraint.ConstraintSystem
	var pk plonk.ProvingKey
	var vk plonk.VerifyingKey
	var err error

	t := reflect.TypeOf(c)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	circuitName := t.Name()

	ccsPath := filepath.Join(outDir, fmt.Sprintf("%s_plonk.ccs", circuitName))
	pkPath := filepath.Join(outDir, fmt.Sprintf("%s_plonk.pk", circuitName))
	vkPath := filepath.Join(outDir, fmt.Sprintf("%s_plonk.vk", circuitName))

	// Step 1: Circuit compile
	fCcs, err := os.Open(ccsPath)
	defer fCcs.Close()

	if err != nil {
		fmt.Println("[plonk] Compiling", circuitName, "...")
		// Compile with BN254 scalar field (for emulated BLS12-381)
		ccs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, c)
		if err != nil {
			panic(err)
		}
		fCcs, err = os.Create(ccsPath)
		_, _ = ccs.WriteTo(fCcs)
	} else {
		fmt.Println("[plonk] Loading", circuitName, "...")

		ccs = groth16.NewCS(ecc.BN254)
		_, err = ccs.ReadFrom(fCcs)
		if err != nil {
			panic(err)
		}
	}

	fmt.Printf("[plonk] Number of constraints: %d\n", ccs.GetNbConstraints())
	fmt.Printf("[plonk] Number of public inputs: %d\n", ccs.GetNbPublicVariables())
	fmt.Printf("[plonk] Number of secret inputs: %d\n", ccs.GetNbSecretVariables())

	// Step 2: Setup (generate proving and verifying keys)
	fpk, err0 := os.Open(pkPath)
	defer fpk.Close()
	fvk, err1 := os.Open(vkPath)
	defer fvk.Close()

	if err0 != nil || err1 != nil {

		fmt.Println("[plonk] Generating SRS (this may take a while)...")
		srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
		if err != nil {
			panic(err)
		}
		fmt.Println("[plonk] Generating proving and verifying keys...")
		pk, vk, err = plonk.Setup(ccs, srs, srsLagrange)
		if err != nil {
			panic(err)
		}
		fpk, _ = os.Create(pkPath)
		_, _ = pk.WriteTo(fpk)

		fvk, _ = os.Create(vkPath)
		_, _ = vk.WriteTo(fvk)
	} else {
		fmt.Println("[plonk] Loading proving and verifying keys...")
		pk = plonk.NewProvingKey(ecc.BN254)
		vk = plonk.NewVerifyingKey(ecc.BN254)
		if _, err := pk.ReadFrom(fpk); err != nil {
			panic(err)
		}
		if _, err := vk.ReadFrom(fvk); err != nil {
			panic(err)
		}
	}
	fmt.Println("[plonk] ✓ Setup complete")
	return ccs, pk, vk
}
