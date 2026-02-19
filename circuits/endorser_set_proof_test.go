package circuits

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	ecdsaCircuit "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/kysee/zk-chains/provers/types"
	zkTypes "github.com/kysee/zk-chains/types"
	"github.com/stretchr/testify/require"
)

// generateEndorserProofData creates a valid EndorserProofCircuit assignment for testing.
func generateEndorserProofData(t *testing.T) EndorserProofCircuit {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ouData := []byte("test-org-unit")
	pubkData := make([]byte, 32)
	_, err = rand.Read(pubkData)
	require.NoError(t, err)

	ouOffset := 50
	pubkOffset := 200
	certLen := 400

	cert := buildCertData(ouOffset, ouData, pubkOffset, pubkData, certLen)

	// SHA256 pad
	paddedCert := sha256PadMessage(cert)
	var certU8 [MaxMsgSize]uints.U8
	for i := 0; i < MaxMsgSize; i++ {
		if i < len(paddedCert) {
			certU8[i] = uints.NewU8(paddedCert[i])
		} else {
			certU8[i] = uints.NewU8(0)
		}
	}

	// Sign
	certHash := sha256.Sum256(cert)
	sigDER, err := privKey.Sign(rand.Reader, certHash[:], nil)
	require.NoError(t, err)
	r, s, err := types.ParseDERSignature(sigDER)
	require.NoError(t, err)

	var ouBytes [32]uints.U8
	for i := 0; i < 32; i++ {
		if i < len(ouData) {
			ouBytes[i] = uints.NewU8(ouData[i])
		} else {
			ouBytes[i] = uints.NewU8(0)
		}
	}
	var pubkBytes [32]uints.U8
	for i := 0; i < 32; i++ {
		if i < len(pubkData) {
			pubkBytes[i] = uints.NewU8(pubkData[i])
		} else {
			pubkBytes[i] = uints.NewU8(0)
		}
	}

	return EndorserProofCircuit{
		CertBytes: certU8,
		CertLen:   certLen,
		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		RootPubK: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
		},
		OUIdx:      ouOffset,
		OULen:      len(ouData),
		PubKOffset: pubkOffset,
		OUBytes:    ouBytes,
		PubKBytes:  pubkBytes,
	}
}

// buildOuterCircuitWithPlaceholders creates an EndorserSetProofCircuit with placeholders from innerCcs.
func buildOuterCircuitWithPlaceholders(innerCcs constraint.ConstraintSystem) *EndorserSetProofCircuit {
	var placeholderProofs [MaxEndorserProof]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	var placeholderWitnesses [MaxEndorserProof]stdgroth16.Witness[sw_bn254.ScalarField]
	for i := 0; i < MaxEndorserProof; i++ {
		placeholderProofs[i] = stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs)
		placeholderWitnesses[i] = stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs)
	}
	return &EndorserSetProofCircuit{
		Proofs:    placeholderProofs,
		Witnesses: placeholderWitnesses,
		VK:        stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
	}
}

// generateInnerProofs generates MaxEndorserProof inner proofs and returns circuit-compatible values.
func generateInnerProofs(t *testing.T, innerCcs constraint.ConstraintSystem, innerPk groth16.ProvingKey, innerVk groth16.VerifyingKey) (
	[MaxEndorserProof]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine],
	[MaxEndorserProof]stdgroth16.Witness[sw_bn254.ScalarField],
	stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl],
) {
	t.Helper()

	var circuitProofs [MaxEndorserProof]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	var circuitWitnesses [MaxEndorserProof]stdgroth16.Witness[sw_bn254.ScalarField]

	for i := 0; i < MaxEndorserProof; i++ {
		t.Logf("Generating inner proof %d/%d...", i+1, MaxEndorserProof)

		assignment := generateEndorserProofData(t)

		wit, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		require.NoError(t, err)

		proof, err := groth16.Prove(innerCcs, innerPk, wit,
			stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
		require.NoError(t, err)

		pubWit, err := wit.Public()
		require.NoError(t, err)
		err = groth16.Verify(proof, innerVk, pubWit,
			stdgroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
		require.NoError(t, err)
		t.Logf("Inner proof %d verified natively", i+1)

		circuitProofs[i], err = stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](proof)
		require.NoError(t, err)

		circuitWitnesses[i], err = stdgroth16.ValueOfWitness[sw_bn254.ScalarField](pubWit)
		require.NoError(t, err)
	}

	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	require.NoError(t, err)

	return circuitProofs, circuitWitnesses, circuitVk
}

func TestEndorserSetProofCircuit(t *testing.T) {
	rootDir, _ := zkTypes.ProjectRoot()
	buildDir := filepath.Join(rootDir, ".build")

	// 1. Compile + Setup inner circuit
	innerCcs, innerPk, innerVk := LoadOrSetupCircuit_Groth16(buildDir, &EndorserProofCircuit{})
	t.Logf("Inner circuit constraints: %d", innerCcs.GetNbConstraints())

	// 2. Generate inner proofs
	circuitProofs, circuitWitnesses, circuitVk := generateInnerProofs(t, innerCcs, innerPk, innerVk)

	// 3. Build outer circuit and test IsSolved
	outerCircuit := buildOuterCircuitWithPlaceholders(innerCcs)
	outerAssignment := &EndorserSetProofCircuit{
		Proofs:    circuitProofs,
		Witnesses: circuitWitnesses,
		VK:        circuitVk,
	}

	t.Log("Testing IsSolved for EndorserSetProofCircuit...")
	err := test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err, "EndorserSetProofCircuit should be solved")
	t.Log("EndorserSetProofCircuit IsSolved passed!")
}

func TestEndorserSetProofCircuit_ProveAndVerify(t *testing.T) {
	rootDir, _ := zkTypes.ProjectRoot()
	buildDir := filepath.Join(rootDir, ".build")

	// 1. Compile + Setup inner circuit
	innerCcs, innerPk, innerVk := LoadOrSetupCircuit_Groth16(buildDir, &EndorserProofCircuit{})
	t.Logf("Inner circuit constraints: %d", innerCcs.GetNbConstraints())

	// 2. Generate inner proofs
	circuitProofs, circuitWitnesses, circuitVk := generateInnerProofs(t, innerCcs, innerPk, innerVk)

	// 3. Compile + Setup outer circuit
	outerCcs, outerPk, outerVk := LoadOrSetupCircuit_Groth16(buildDir, buildOuterCircuitWithPlaceholders(innerCcs))
	t.Logf("Outer circuit constraints: %d", outerCcs.GetNbConstraints())

	// 4. Create outer witness and prove
	outerAssignment := &EndorserSetProofCircuit{
		Proofs:    circuitProofs,
		Witnesses: circuitWitnesses,
		VK:        circuitVk,
	}

	outerWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	fmt.Println("Generating outer proof...")
	start := time.Now()
	outerProof, err := groth16.Prove(outerCcs, outerPk, outerWitness)
	require.NoError(t, err, "Outer proof generation failed")
	fmt.Println("Outer proof generation time:", time.Since(start))

	// 5. Verify outer proof
	outerPubWitness, err := outerWitness.Public()
	require.NoError(t, err)

	fmt.Println("Verifying outer proof...")
	start = time.Now()
	err = groth16.Verify(outerProof, outerVk, outerPubWitness)
	require.NoError(t, err, "Outer proof verification failed")
	fmt.Println("Outer verify time:", time.Since(start))

	t.Log("EndorserSetProofCircuit ProveAndVerify passed!")
}

func TestEndorserSetProofCircuit_Compile(t *testing.T) {
	rootDir, _ := zkTypes.ProjectRoot()
	buildDir := filepath.Join(rootDir, ".build")

	// Compile + Setup inner circuit
	innerCcs, _, _ := LoadOrSetupCircuit_Groth16(buildDir, &EndorserProofCircuit{})

	// Compile + Setup outer circuit
	outerCcs, _, _ := LoadOrSetupCircuit_Groth16(buildDir, buildOuterCircuitWithPlaceholders(innerCcs))

	t.Logf("Outer circuit constraints: %d", outerCcs.GetNbConstraints())
	t.Logf("Outer circuit public inputs: %d", outerCcs.GetNbPublicVariables())
	t.Logf("Outer circuit commitments: %v", outerCcs.GetCommitments().CommitmentIndexes())
}
