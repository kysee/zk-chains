package bprn

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/kysee/zk-chains/circuits"
	"github.com/kysee/zk-chains/provers/types"
	types2 "github.com/kysee/zk-chains/types"
)

// MsgHProofInput holds input data for generating a BPrNMsgHCircuit proof
type MsgHProofInput struct {
	PrivKey *ecdsa.PrivateKey
	PreH    [32]byte
	TargetH [32]byte
}

// MsgHProofOutput holds the result of generating a proof
type MsgHProofOutput struct {
	Index   int
	Proof   groth16.Proof
	Witness witness.Witness
	PubWit  witness.Witness
	Err     error
}

// AggregateMsgHProver manages parallel proof generation for BPrNMsgHCircuit
type AggregateMsgHProver struct {
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey

	mu sync.Mutex
}

// NewAggregateMsgHProver creates a new prover for aggregate proofs
func NewAggregateMsgHProver() *AggregateMsgHProver {
	fmt.Println("Creating AggregateMsgHProver...")

	var circuit circuits.BPrNEventProofCircuit

	rootDir, _ := types2.ProjectRoot()
	ccs, pk, vk := circuits.LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &circuit)

	fmt.Printf("Inner circuit constraints: %d\n", ccs.GetNbConstraints())
	fmt.Printf("Inner circuit public inputs: %d\n", ccs.GetNbPublicVariables())

	return &AggregateMsgHProver{
		ccs: ccs,
		pk:  pk,
		vk:  vk,
	}
}

// GetVerifyingKey returns the verifying key for the inner circuit
func (p *AggregateMsgHProver) GetVerifyingKey() groth16.VerifyingKey {
	return p.vk
}

// GenerateProofsParallel generates multiple BPrNMsgHCircuit proofs in parallel
// All inputs must share the same EventPayloadH
func (p *AggregateMsgHProver) GenerateProofsParallel(inputs []MsgHProofInput) ([]MsgHProofOutput, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no inputs provided")
	}

	// Verify all inputs have the same EventPayloadH
	commonTargetH := inputs[0].TargetH
	for i, input := range inputs[1:] {
		if input.TargetH != commonTargetH {
			return nil, fmt.Errorf("input %d has different EventPayloadH", i+1)
		}
	}

	n := len(inputs)
	results := make(chan MsgHProofOutput, n)
	var wg sync.WaitGroup

	fmt.Printf("Generating %d proofs in parallel...\n", n)
	startTime := time.Now()

	// Launch goroutines for parallel proof generation
	for i, input := range inputs {
		wg.Add(1)
		go func(idx int, inp MsgHProofInput) {
			defer wg.Done()

			output := MsgHProofOutput{Index: idx}
			proofStart := time.Now()

			// Generate proof
			proof, wit, err := p.generateSingleProof(inp)
			if err != nil {
				output.Err = fmt.Errorf("proof %d failed: %w", idx, err)
				results <- output
				return
			}

			// Get public witness
			pubWit, err := wit.Public()
			if err != nil {
				output.Err = fmt.Errorf("proof %d public witness failed: %w", idx, err)
				results <- output
				return
			}

			output.Proof = proof
			output.Witness = wit
			output.PubWit = pubWit

			fmt.Printf("Proof %d generated in %v\n", idx, time.Since(proofStart))
			results <- output
		}(i, input)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	outputs := make([]MsgHProofOutput, n)
	for result := range results {
		if result.Err != nil {
			return nil, result.Err
		}
		outputs[result.Index] = result
	}

	fmt.Printf("All %d proofs generated in %v\n", n, time.Since(startTime))
	return outputs, nil
}

// generateSingleProof generates a single BPrNMsgHCircuit proof
func (p *AggregateMsgHProver) generateSingleProof(input MsgHProofInput) (groth16.Proof, witness.Witness, error) {
	// Compute digest: SHA256(PreH || EventPayloadH)
	digest := sha256.Sum256(append(input.PreH[:], input.TargetH[:]...))

	// Sign the digest
	sigDER, err := input.PrivKey.Sign(nil, digest[:], nil)
	if err != nil {
		return nil, nil, fmt.Errorf("signing failed: %w", err)
	}

	_, _, _ = types.ParseDERSignature(sigDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse signature failed: %w", err)
	}

	// Create circuit assignment
	assignment := circuits.BPrNEventProofCircuit{
		//OriginPayloadH: circuits.ToU8Array32(input.PreH[:]),
		//EventPayloadH:  circuits.ToU8Array32(input.TargetH[:]),
		//Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		//	X: emulated.ValueOf[emulated.P256Fp](input.PrivKey.PublicKey.X),
		//	Y: emulated.ValueOf[emulated.P256Fp](input.PrivKey.PublicKey.Y),
		//},
		//Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
		//	R: emulated.ValueOf[emulated.P256Fr](r),
		//	S: emulated.ValueOf[emulated.P256Fr](s),
		//},
	}

	// Create witness
	wit, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, fmt.Errorf("witness creation failed: %w", err)
	}

	// Generate proof
	proof, err := groth16.Prove(p.ccs, p.pk, wit)
	if err != nil {
		return nil, nil, fmt.Errorf("proof generation failed: %w", err)
	}

	return proof, wit, nil
}

// VerifyProofs verifies all proofs individually
func (p *AggregateMsgHProver) VerifyProofs(outputs []MsgHProofOutput) error {
	for _, output := range outputs {
		err := groth16.Verify(output.Proof, p.vk, output.PubWit)
		if err != nil {
			return fmt.Errorf("verification failed for proof %d: %w", output.Index, err)
		}
	}
	return nil
}

// AggregateResult holds the aggregated proof result
type AggregateResult struct {
	// Inner proofs and witnesses (for recursive verification)
	Proofs    []groth16.Proof
	PubWits   []witness.Witness
	InnerVK   groth16.VerifyingKey
	TargetH   [32]byte
	NumProofs int
}

// PrepareForAggregation prepares the proof outputs for aggregation
func (p *AggregateMsgHProver) PrepareForAggregation(outputs []MsgHProofOutput, targetH [32]byte) *AggregateResult {
	proofs := make([]groth16.Proof, len(outputs))
	pubWits := make([]witness.Witness, len(outputs))

	for i, output := range outputs {
		proofs[i] = output.Proof
		pubWits[i] = output.PubWit
	}

	return &AggregateResult{
		Proofs:    proofs,
		PubWits:   pubWits,
		InnerVK:   p.vk,
		TargetH:   targetH,
		NumProofs: len(outputs),
	}
}
