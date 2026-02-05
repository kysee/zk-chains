package circuits

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	ecdsaCircuit "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

// SimpleInnerCircuit - 간단한 P*Q=N 회로
type SimpleInnerCircuit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *SimpleInnerCircuit) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	api.AssertIsDifferent(c.P, 1)
	api.AssertIsDifferent(c.Q, 1)
	return nil
}

// SimpleOuterCircuit - inner proof를 검증하는 outer circuit
type SimpleOuterCircuit struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	InnerWitness stdgroth16.Witness[sw_bn254.ScalarField]
}

func (c *SimpleOuterCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness, stdgroth16.WithCompleteArithmetic())
}

func TestP256CircuitCommitments(t *testing.T) {
	// P256ProofCircuit의 commitment 수 확인
	var circuit P256ProofCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	require.NoError(t, err)

	t.Logf("P256ProofCircuit constraints: %d", ccs.GetNbConstraints())
	t.Logf("P256ProofCircuit public inputs: %d", ccs.GetNbPublicVariables())
	t.Logf("P256ProofCircuit commitments: %v", ccs.GetCommitments().CommitmentIndexes())
}

func TestP256RecursionWithCommitment(t *testing.T) {
	// This test verifies a single P256ProofCircuit proof recursively
	// P256ProofCircuit has commitments (from emulated field operations)

	// 1. Generate test data
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	h0 := sha256.Sum256([]byte("test_h0"))
	msgH := sha256.Sum256([]byte("test_msgH"))
	data := append(h0[:], msgH[:]...)
	hash := sha256.Sum256(data)

	sigDER, err := privKey.Sign(rand.Reader, hash[:], nil)
	require.NoError(t, err)

	rVal, sVal := parseP256Signature(sigDER)

	// 2. Compile and setup inner circuit
	t.Log("Compiling P256ProofCircuit...")
	var innerCircuit P256ProofCircuit
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &innerCircuit)
	require.NoError(t, err)
	t.Logf("Inner circuit constraints: %d", innerCcs.GetNbConstraints())
	t.Logf("Inner circuit commitments: %v", innerCcs.GetCommitments().CommitmentIndexes())

	t.Log("Setting up inner circuit...")
	innerPk, innerVk, err := groth16.Setup(innerCcs)
	require.NoError(t, err)

	// 3. Create inner assignment and generate proof
	innerAssignment := &P256ProofCircuit{
		Pub: ecdsaCircuitP256{
			X: emulatedP256Fp(privKey.PublicKey.X),
			Y: emulatedP256Fp(privKey.PublicKey.Y),
		},
		Sig: signatureP256{
			R: emulatedP256Fr(rVal),
			S: emulatedP256Fr(sVal),
		},
		H0:   ToU8Array32(h0[:]),
		MsgH: ToU8Array32(msgH[:]),
	}

	innerWitness, err := frontend.NewWitness(innerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	t.Log("Generating inner proof...")
	innerProof, err := groth16.Prove(innerCcs, innerPk, innerWitness,
		stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	require.NoError(t, err)
	t.Log("Inner proof generated")

	// 4. Verify inner proof (sanity check)
	innerPubWitness, err := innerWitness.Public()
	require.NoError(t, err)
	err = groth16.Verify(innerProof, innerVk, innerPubWitness,
		stdgroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	require.NoError(t, err)
	t.Log("Inner proof verified natively")

	// 5. Convert to circuit values
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	require.NoError(t, err)
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	require.NoError(t, err)
	circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerPubWitness)
	require.NoError(t, err)

	// 6. Test outer circuit with IsSolved
	outerCircuit := &SimpleOuterCircuit{
		InnerWitness: stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
		Proof:        stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
	}
	outerAssignment := &SimpleOuterCircuit{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}

	t.Log("Testing IsSolved...")
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err, "Outer circuit should be solved with P256 inner proof")
	t.Log("IsSolved passed!")
}

// Helper functions for P256 signature
func parseP256Signature(sigDER []byte) (*big.Int, *big.Int) {
	// Simple ASN.1 DER parsing for ECDSA signature
	// Format: 0x30 len 0x02 rLen r 0x02 sLen s
	if len(sigDER) < 8 || sigDER[0] != 0x30 {
		panic("invalid DER signature")
	}
	idx := 2
	if sigDER[idx] != 0x02 {
		panic("expected 0x02 for R")
	}
	idx++
	rLen := int(sigDER[idx])
	idx++
	rBytes := sigDER[idx : idx+rLen]
	idx += rLen
	if sigDER[idx] != 0x02 {
		panic("expected 0x02 for S")
	}
	idx++
	sLen := int(sigDER[idx])
	idx++
	sBytes := sigDER[idx : idx+sLen]

	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	return r, s
}

type ecdsaCircuitP256 = ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]
type signatureP256 = ecdsaCircuit.Signature[emulated.P256Fr]

func emulatedP256Fp(v *big.Int) emulated.Element[emulated.P256Fp] {
	return emulated.ValueOf[emulated.P256Fp](v)
}

func emulatedP256Fr(v *big.Int) emulated.Element[emulated.P256Fr] {
	return emulated.ValueOf[emulated.P256Fr](v)
}

// MultiProofOuterCircuit verifies multiple inner proofs
type MultiProofOuterCircuit struct {
	Proofs    [2]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VK        stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	Witnesses [2]stdgroth16.Witness[sw_bn254.ScalarField]
}

func (c *MultiProofOuterCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	// Verify all proofs
	for i := 0; i < 2; i++ {
		err = verifier.AssertProof(c.VK, c.Proofs[i], c.Witnesses[i], stdgroth16.WithCompleteArithmetic())
		if err != nil {
			return err
		}
	}
	return nil
}

func TestMultiProofSimple(t *testing.T) {
	// Test verifying multiple proofs from a simple inner circuit (no commitments)

	// 1. Compile inner circuit
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &SimpleInnerCircuit{})
	require.NoError(t, err)
	t.Logf("Inner circuit constraints: %d", innerCcs.GetNbConstraints())
	t.Logf("Inner circuit commitments: %v", innerCcs.GetCommitments().CommitmentIndexes())

	// 2. Setup inner circuit
	innerPk, innerVk, err := groth16.Setup(innerCcs)
	require.NoError(t, err)

	// 3. Generate two different inner proofs
	assignments := []*SimpleInnerCircuit{
		{P: 3, Q: 5, N: 15},
		{P: 7, Q: 11, N: 77},
	}

	var circuitProofs [2]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	var circuitWitnesses [2]stdgroth16.Witness[sw_bn254.ScalarField]

	for i, assignment := range assignments {
		wit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		require.NoError(t, err)

		proof, err := groth16.Prove(innerCcs, innerPk, wit,
			stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
		require.NoError(t, err)

		pubWit, err := wit.Public()
		require.NoError(t, err)

		circuitProofs[i], err = stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](proof)
		require.NoError(t, err)

		circuitWitnesses[i], err = stdgroth16.ValueOfWitness[sw_bn254.ScalarField](pubWit)
		require.NoError(t, err)
	}

	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	require.NoError(t, err)

	// 4. Test outer circuit
	outerCircuit := &MultiProofOuterCircuit{
		Proofs: [2]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{
			stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
			stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		},
		VK: stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
		Witnesses: [2]stdgroth16.Witness[sw_bn254.ScalarField]{
			stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
			stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		},
	}
	outerAssignment := &MultiProofOuterCircuit{
		Proofs:    circuitProofs,
		VK:        circuitVk,
		Witnesses: circuitWitnesses,
	}

	t.Log("Testing IsSolved with multiple simple proofs...")
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err, "Multi-proof outer circuit should be solved")
	t.Log("Multi-proof IsSolved passed!")
}

func TestMultiProofP256(t *testing.T) {
	// Test verifying multiple proofs from P256ProofCircuit (with commitments)

	// 1. Compile inner circuit
	var innerCircuit P256ProofCircuit
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &innerCircuit)
	require.NoError(t, err)
	t.Logf("Inner circuit constraints: %d", innerCcs.GetNbConstraints())
	t.Logf("Inner circuit commitments: %v", innerCcs.GetCommitments().CommitmentIndexes())

	// 2. Setup inner circuit
	t.Log("Setting up inner circuit...")
	innerPk, innerVk, err := groth16.Setup(innerCcs)
	require.NoError(t, err)

	// 3. Generate two different P256 proofs
	var circuitProofs [2]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	var circuitWitnesses [2]stdgroth16.Witness[sw_bn254.ScalarField]

	for i := 0; i < 2; i++ {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		h0 := sha256.Sum256([]byte("test_h0"))
		msgH := sha256.Sum256([]byte("test_msgH"))
		data := append(h0[:], msgH[:]...)
		hash := sha256.Sum256(data)

		sigDER, err := privKey.Sign(rand.Reader, hash[:], nil)
		require.NoError(t, err)

		rVal, sVal := parseP256Signature(sigDER)

		assignment := &P256ProofCircuit{
			Pub: ecdsaCircuitP256{
				X: emulatedP256Fp(privKey.PublicKey.X),
				Y: emulatedP256Fp(privKey.PublicKey.Y),
			},
			Sig: signatureP256{
				R: emulatedP256Fr(rVal),
				S: emulatedP256Fr(sVal),
			},
			H0:   ToU8Array32(h0[:]),
			MsgH: ToU8Array32(msgH[:]),
		}

		wit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		require.NoError(t, err)

		t.Logf("Generating inner proof %d...", i)
		proof, err := groth16.Prove(innerCcs, innerPk, wit,
			stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
		require.NoError(t, err)

		pubWit, err := wit.Public()
		require.NoError(t, err)

		circuitProofs[i], err = stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](proof)
		require.NoError(t, err)

		circuitWitnesses[i], err = stdgroth16.ValueOfWitness[sw_bn254.ScalarField](pubWit)
		require.NoError(t, err)
	}

	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	require.NoError(t, err)

	// 4. Test outer circuit
	outerCircuit := &MultiProofOuterCircuit{
		Proofs: [2]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{
			stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
			stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		},
		VK: stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
		Witnesses: [2]stdgroth16.Witness[sw_bn254.ScalarField]{
			stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
			stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		},
	}
	outerAssignment := &MultiProofOuterCircuit{
		Proofs:    circuitProofs,
		VK:        circuitVk,
		Witnesses: circuitWitnesses,
	}

	t.Log("Testing IsSolved with multiple P256 proofs...")
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err, "Multi-proof P256 outer circuit should be solved")
	t.Log("Multi-proof P256 IsSolved passed!")
}

func TestBPrNEventProofCircuitWithEventPayloadH(t *testing.T) {
	// Test version with EventPayloadH field added but not used

	// 1. Compile inner circuit
	var innerCircuit P256ProofCircuit
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &innerCircuit)
	require.NoError(t, err)

	// 2. Setup inner circuit
	t.Log("Setting up inner circuit...")
	innerPk, innerVk, err := groth16.Setup(innerCcs)
	require.NoError(t, err)

	// 3. Generate P256 proofs
	var circuitProofs [MaxP256Proofs]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	var circuitWitnesses [MaxP256Proofs]stdgroth16.Witness[sw_bn254.ScalarField]

	h0 := sha256.Sum256([]byte("test_h0"))
	msgH := sha256.Sum256([]byte("test_msgH"))
	data := append(h0[:], msgH[:]...)
	hash := sha256.Sum256(data)

	for i := 0; i < MaxP256Proofs; i++ {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		sigDER, err := privKey.Sign(rand.Reader, hash[:], nil)
		require.NoError(t, err)

		rVal, sVal := parseP256Signature(sigDER)

		assignment := &P256ProofCircuit{
			Pub: ecdsaCircuitP256{
				X: emulatedP256Fp(privKey.PublicKey.X),
				Y: emulatedP256Fp(privKey.PublicKey.Y),
			},
			Sig: signatureP256{
				R: emulatedP256Fr(rVal),
				S: emulatedP256Fr(sVal),
			},
			H0:   ToU8Array32(h0[:]),
			MsgH: ToU8Array32(msgH[:]),
		}

		wit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		require.NoError(t, err)

		t.Logf("Generating inner proof %d...", i)
		proof, err := groth16.Prove(innerCcs, innerPk, wit,
			stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
		require.NoError(t, err)

		pubWit, err := wit.Public()
		require.NoError(t, err)

		circuitProofs[i], err = stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](proof)
		require.NoError(t, err)

		circuitWitnesses[i], err = stdgroth16.ValueOfWitness[sw_bn254.ScalarField](pubWit)
		require.NoError(t, err)
	}

	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	require.NoError(t, err)

	// 4. Test circuit with EventPayloadH field
	outerCircuit := &BPrNEventProofCircuitWithEventPayloadH{
		Proofs: [MaxP256Proofs]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{
			stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
			stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		},
		VK: stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
		Witnesses: [MaxP256Proofs]stdgroth16.Witness[sw_bn254.ScalarField]{
			stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
			stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		},
	}
	outerAssignment := &BPrNEventProofCircuitWithEventPayloadH{
		Proofs:        circuitProofs,
		VK:            circuitVk,
		Witnesses:     circuitWitnesses,
		EventPayloadH: ToU8Array32(msgH[:]),
	}

	t.Log("Testing IsSolved with EventPayloadH field...")
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err, "Circuit with EventPayloadH should be solved")
	t.Log("Test passed!")
}

func TestBPrNEventProofCircuitMinimal(t *testing.T) {
	// Test the minimal version of BPrNEventProofCircuit

	// 1. Compile inner circuit
	var innerCircuit P256ProofCircuit
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &innerCircuit)
	require.NoError(t, err)
	t.Logf("Inner circuit constraints: %d", innerCcs.GetNbConstraints())
	t.Logf("Inner circuit commitments: %v", innerCcs.GetCommitments().CommitmentIndexes())

	// 2. Setup inner circuit
	t.Log("Setting up inner circuit...")
	innerPk, innerVk, err := groth16.Setup(innerCcs)
	require.NoError(t, err)

	// 3. Generate P256 proofs
	var circuitProofs [MaxP256Proofs]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	var circuitWitnesses [MaxP256Proofs]stdgroth16.Witness[sw_bn254.ScalarField]

	for i := 0; i < MaxP256Proofs; i++ {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		h0 := sha256.Sum256([]byte("test_h0"))
		msgH := sha256.Sum256([]byte("test_msgH"))
		data := append(h0[:], msgH[:]...)
		hash := sha256.Sum256(data)

		sigDER, err := privKey.Sign(rand.Reader, hash[:], nil)
		require.NoError(t, err)

		rVal, sVal := parseP256Signature(sigDER)

		assignment := &P256ProofCircuit{
			Pub: ecdsaCircuitP256{
				X: emulatedP256Fp(privKey.PublicKey.X),
				Y: emulatedP256Fp(privKey.PublicKey.Y),
			},
			Sig: signatureP256{
				R: emulatedP256Fr(rVal),
				S: emulatedP256Fr(sVal),
			},
			H0:   ToU8Array32(h0[:]),
			MsgH: ToU8Array32(msgH[:]),
		}

		wit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		require.NoError(t, err)

		t.Logf("Generating inner proof %d...", i)
		proof, err := groth16.Prove(innerCcs, innerPk, wit,
			stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
		require.NoError(t, err)

		pubWit, err := wit.Public()
		require.NoError(t, err)

		circuitProofs[i], err = stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](proof)
		require.NoError(t, err)

		circuitWitnesses[i], err = stdgroth16.ValueOfWitness[sw_bn254.ScalarField](pubWit)
		require.NoError(t, err)
	}

	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	require.NoError(t, err)

	// 4. Test minimal outer circuit
	outerCircuit := &BPrNEventProofCircuitMinimal{
		Proofs: [MaxP256Proofs]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{
			stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
			stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		},
		VK: stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
		Witnesses: [MaxP256Proofs]stdgroth16.Witness[sw_bn254.ScalarField]{
			stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
			stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		},
	}
	outerAssignment := &BPrNEventProofCircuitMinimal{
		Proofs:    circuitProofs,
		VK:        circuitVk,
		Witnesses: circuitWitnesses,
	}

	t.Log("Testing IsSolved with BPrNEventProofCircuitMinimal...")
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err, "BPrNEventProofCircuitMinimal should be solved")
	t.Log("BPrNEventProofCircuitMinimal IsSolved passed!")
}

func TestSimpleRecursion(t *testing.T) {
	// 1. Inner circuit 컴파일
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &SimpleInnerCircuit{})
	require.NoError(t, err)
	t.Logf("Inner circuit constraints: %d", innerCcs.GetNbConstraints())
	t.Logf("Inner circuit commitments: %v", innerCcs.GetCommitments().CommitmentIndexes())

	// 2. Inner circuit setup
	innerPk, innerVk, err := groth16.Setup(innerCcs)
	require.NoError(t, err)

	// 3. Inner proof 생성
	innerAssignment := &SimpleInnerCircuit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	// GetNativeProverOptions 사용
	innerProof, err := groth16.Prove(innerCcs, innerPk, innerWitness,
		stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	require.NoError(t, err)

	// 4. Inner proof 검증 (sanity check)
	innerPubWitness, err := innerWitness.Public()
	require.NoError(t, err)
	err = groth16.Verify(innerProof, innerVk, innerPubWitness,
		stdgroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	require.NoError(t, err)
	t.Log("Inner proof verified successfully")

	// 5. Outer circuit을 위한 값 변환
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	require.NoError(t, err)
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	require.NoError(t, err)
	circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerPubWitness)
	require.NoError(t, err)

	// 6. Outer circuit 컴파일
	outerCircuit := &SimpleOuterCircuit{
		InnerWitness: stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
	}
	outerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	require.NoError(t, err)
	t.Logf("Outer circuit constraints: %d", outerCcs.GetNbConstraints())

	// 7. Outer circuit setup
	outerPk, outerVk, err := groth16.Setup(outerCcs)
	require.NoError(t, err)

	// 8. Outer assignment
	outerAssignment := &SimpleOuterCircuit{
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
		InnerWitness: circuitWitness,
	}

	// 9. Outer proof 생성
	outerWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	t.Log("Generating outer proof...")
	outerProof, err := groth16.Prove(outerCcs, outerPk, outerWitness)
	require.NoError(t, err, "Outer proof generation failed")
	t.Log("Outer proof generated successfully")

	// 10. Outer proof 검증
	outerPubWitness, err := outerWitness.Public()
	require.NoError(t, err)
	err = groth16.Verify(outerProof, outerVk, outerPubWitness)
	require.NoError(t, err, "Outer proof verification failed")
	t.Log("Outer proof verified successfully!")
}
