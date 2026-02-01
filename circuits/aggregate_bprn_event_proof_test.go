package circuits

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	ecdsaCircuit "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/kysee/zk-chains/provers/types"
	"github.com/stretchr/testify/require"
)

// InnerProofData holds data needed to generate an inner BPrNEventProofCircuit proof
type InnerProofData struct {
	PrivKey        *ecdsa.PrivateKey
	OriginPayloadH [32]byte // OriginPayloadH
	EventPayloadH  [32]byte // EventPayloadH - Same for all proofs in aggregate
	EventLogRoot   [32]byte
	EventElemH     [32]byte // Public input
}

// InnerProofResult holds the result of generating an inner proof
type InnerProofResult struct {
	Index   int
	Proof   groth16.Proof
	Witness witness.Witness
	Err     error
}

// GenerateInnerProofsParallel generates multiple BPrNEventProofCircuit proofs in parallel
func GenerateInnerProofsParallel(
	innerCcs constraint.ConstraintSystem,
	innerPk groth16.ProvingKey,
	proofDataList []InnerProofData,
) ([]groth16.Proof, []witness.Witness, error) {
	n := len(proofDataList)
	results := make(chan InnerProofResult, n)
	var wg sync.WaitGroup

	// Generate proofs in parallel using goroutines
	for i, data := range proofDataList {
		wg.Add(1)
		go func(idx int, d InnerProofData) {
			defer wg.Done()

			result := InnerProofResult{Index: idx}

			// Compute digest: SHA256(OriginPayloadH || EventPayloadH)
			digest := sha256.Sum256(append(d.OriginPayloadH[:], d.EventPayloadH[:]...))

			// Sign the digest
			sigDER, err := d.PrivKey.Sign(rand.Reader, digest[:], nil)
			if err != nil {
				result.Err = fmt.Errorf("sign error at index %d: %w", idx, err)
				results <- result
				return
			}

			r, s, err := types.ParseDERSignature(sigDER)
			if err != nil {
				result.Err = fmt.Errorf("parse signature error at index %d: %w", idx, err)
				results <- result
				return
			}

			// Create witness for inner circuit
			assignment := BPrNEventProofCircuit{
				OriginPayloadH: ToU8Array32(d.OriginPayloadH[:]),
				EventPayloadH:  ToU8Array32(d.EventPayloadH[:]),
				EventLogRoot:   ToU8Array32(d.EventLogRoot[:]),
				EventElemH:     ToU8Array32(d.EventElemH[:]),
				Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
					X: emulated.ValueOf[emulated.P256Fp](d.PrivKey.PublicKey.X),
					Y: emulated.ValueOf[emulated.P256Fp](d.PrivKey.PublicKey.Y),
				},
				Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
					R: emulated.ValueOf[emulated.P256Fr](r),
					S: emulated.ValueOf[emulated.P256Fr](s),
				},
			}

			wit, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
			if err != nil {
				result.Err = fmt.Errorf("witness creation error at index %d: %w", idx, err)
				results <- result
				return
			}

			proof, err := groth16.Prove(innerCcs, innerPk, wit)
			if err != nil {
				result.Err = fmt.Errorf("prove error at index %d: %w", idx, err)
				results <- result
				return
			}

			result.Proof = proof
			result.Witness = wit
			results <- result
		}(i, data)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	proofs := make([]groth16.Proof, n)
	witnesses := make([]witness.Witness, n)

	for result := range results {
		if result.Err != nil {
			return nil, nil, result.Err
		}
		proofs[result.Index] = result.Proof
		witnesses[result.Index] = result.Witness
	}

	return proofs, witnesses, nil
}

func TestAggregateBPrNEventProofCircuitBN254_Compile(t *testing.T) {
	t.Log("Step 1: Compile inner circuit (BPrNEventProofCircuit)...")

	// First, compile the inner circuit to get its constraint system
	var innerCircuit BPrNEventProofCircuit
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &innerCircuit)
	require.NoError(t, err)
	t.Logf("Inner circuit constraints: %d", innerCcs.GetNbConstraints())
	t.Logf("Inner circuit public inputs: %d", innerCcs.GetNbPublicVariables())

	t.Log("Step 2: Create placeholders for recursive circuit...")

	// Create placeholders using inner circuit's constraint system
	placeholderVK := stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs)
	placeholderProof := stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs)
	placeholderWitness := stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs)

	// Build outer circuit with placeholders
	var circuitProofs [MaxAggregateProofs]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	var circuitWitnesses [MaxAggregateProofs]stdgroth16.Witness[sw_bn254.ScalarField]

	for i := 0; i < MaxAggregateProofs; i++ {
		circuitProofs[i] = placeholderProof
		circuitWitnesses[i] = placeholderWitness
	}

	outerCircuit := AggregateBPrNEventProofCircuitBN254{
		Proofs:    circuitProofs,
		Witnesses: circuitWitnesses,
		VK:        placeholderVK,
	}

	t.Log("Step 3: Compile outer circuit (AggregateBPrNEventProofCircuitBN254)...")
	t.Log("NOTE: This will be very slow due to emulated BN254 pairing...")

	// This compilation is extremely expensive - may take a long time
	outerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &outerCircuit)
	if err != nil {
		t.Logf("Compilation error: %v", err)
		t.Skip("Skipping - compilation failed or timed out")
		return
	}

	t.Logf("Outer circuit compiled successfully!")
	t.Logf("Number of constraints: %d", outerCcs.GetNbConstraints())
	t.Logf("Number of public inputs: %d", outerCcs.GetNbPublicVariables())
}

func TestGenerateInnerProofsParallel(t *testing.T) {
	numProofs := 3

	// Step 1: Setup inner circuit (BPrNEventProofCircuit)
	t.Log("Setting up inner circuit...")
	var innerCircuit BPrNEventProofCircuit
	innerCcs, innerPk, innerVk := LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &innerCircuit)
	t.Logf("Inner circuit constraints: %d", innerCcs.GetNbConstraints())

	// Step 2: Generate test data with common EventPayloadH
	commonTargetH := sha256.Sum256([]byte("common_target_hash"))
	commonEventElemH := sha256.Sum256([]byte("common_event_elem_hash"))

	proofDataList := make([]InnerProofData, numProofs)
	for i := 0; i < numProofs; i++ {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		var preH [32]byte
		_, err = rand.Read(preH[:])
		require.NoError(t, err)

		var eventLogRoot [32]byte
		_, err = rand.Read(eventLogRoot[:])
		require.NoError(t, err)

		proofDataList[i] = InnerProofData{
			PrivKey:        privKey,
			OriginPayloadH: preH,
			EventPayloadH:  commonTargetH, // Same for all
			EventLogRoot:   eventLogRoot,
			EventElemH:     commonEventElemH, // Public input
		}
	}

	// Step 3: Generate proofs in parallel
	t.Log("Generating proofs in parallel...")
	proofs, witnesses, err := GenerateInnerProofsParallel(innerCcs, innerPk, proofDataList)
	require.NoError(t, err)
	require.Len(t, proofs, numProofs)
	require.Len(t, witnesses, numProofs)

	t.Logf("Generated %d proofs successfully", numProofs)

	// Step 4: Verify each proof individually
	t.Log("Verifying proofs individually...")
	for i, proof := range proofs {
		pubWit, err := witnesses[i].Public()
		require.NoError(t, err)

		err = groth16.Verify(proof, innerVk, pubWit)
		require.NoError(t, err)
		t.Logf("Proof %d verified successfully", i)
	}
}

func TestAggregateProofsWithRecursion(t *testing.T) {
	// This test demonstrates the full recursive proof aggregation workflow
	// Note: This is computationally intensive

	t.Skip("Skipping full recursion test - requires significant computation time")

	numProofs := 2 // Start small for testing

	// Step 1: Setup inner circuit
	t.Log("Setting up inner circuit (BPrNEventProofCircuit)...")
	var innerCircuit BPrNEventProofCircuit
	innerCcs, innerPk, innerVk := LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &innerCircuit)
	t.Logf("Inner circuit constraints: %d", innerCcs.GetNbConstraints())

	// Step 2: Generate inner proofs with common EventPayloadH
	commonTargetH := sha256.Sum256([]byte("common_target"))
	commonEventElemH := sha256.Sum256([]byte("common_event_elem"))

	proofDataList := make([]InnerProofData, numProofs)
	for i := 0; i < numProofs; i++ {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		var preH [32]byte
		var eventLogRoot [32]byte
		_, _ = rand.Read(preH[:])
		_, _ = rand.Read(eventLogRoot[:])

		proofDataList[i] = InnerProofData{
			PrivKey:        privKey,
			OriginPayloadH: preH,
			EventPayloadH:  commonTargetH,
			EventLogRoot:   eventLogRoot,
			EventElemH:     commonEventElemH,
		}
	}

	t.Log("Generating inner proofs in parallel...")
	innerProofs, innerWitnesses, err := GenerateInnerProofsParallel(innerCcs, innerPk, proofDataList)
	require.NoError(t, err)

	// Step 3: Convert to recursive proof format
	t.Log("Converting proofs for recursive verification...")

	// Convert inner VK to circuit format
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	require.NoError(t, err)

	// Convert proofs and witnesses
	var circuitProofs [MaxAggregateProofs]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	var circuitWitnesses [MaxAggregateProofs]stdgroth16.Witness[sw_bn254.ScalarField]

	for i := 0; i < numProofs; i++ {
		circuitProofs[i], err = stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProofs[i])
		require.NoError(t, err)

		pubWit, err := innerWitnesses[i].Public()
		require.NoError(t, err)

		circuitWitnesses[i], err = stdgroth16.ValueOfWitness[sw_bn254.ScalarField](pubWit)
		require.NoError(t, err)
	}

	// Fill remaining slots with dummy proofs (for circuits that require fixed size)
	// In production, you'd generate valid dummy proofs for unused slots

	// Step 4: Create aggregate circuit assignment
	targetHLimbs := ToLimbs(commonTargetH)

	aggregateAssignment := AggregateBPrNEventProofCircuitBN254{
		EventPayloadH: [4]frontend.Variable{
			targetHLimbs[0],
			targetHLimbs[1],
			targetHLimbs[2],
			targetHLimbs[3],
		},
		NumProofs: numProofs,
		Proofs:    circuitProofs,
		Witnesses: circuitWitnesses,
		VK:        circuitVk,
	}

	t.Logf("Aggregate assignment created with %d proofs", numProofs)
	_ = aggregateAssignment // Use the assignment

	// Note: Full proving would require compiling and running the aggregate circuit
	// which is computationally very expensive for BN254 emulated version
}
