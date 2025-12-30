package circuit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/uints"
	gnark_test "github.com/consensys/gnark/test"
	"github.com/kysee/zk-chains/types"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/tree"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

var rootDir = mustGetRootDir()

// Global variables for circuit compilation and setup (initialized once in init())
var (
	blsVerifierCCS constraint.ConstraintSystem
	blsVerifierPK  groth16.ProvingKey
	blsVerifierVK  groth16.VerifyingKey

	// Prepare domain parameters
	domainType                    = []byte{0x07, 0x00, 0x00, 0x00} // DOMAIN_SYNC_COMMITTEE
	forkVersion                   = []byte{0x90, 0x00, 0x00, 0x75} // Fulu fork
	genesisValidatorsRootBytes, _ = types.HexToBytes("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")

	gnarkLogger = zerolog.New(os.Stdout).Level(zerolog.DebugLevel).With().Timestamp().Logger()
)

func TestEth2ScUpdateCircuit_IsSolved(t *testing.T) {
	// Load sync committee
	update1104File, err := os.ReadFile(filepath.Join(rootDir, "data/sc-update-1104.json"))
	require.NoError(t, err, "Failed to read file")
	var update1104 types.LightClientUpdate
	err = json.Unmarshal(update1104File, &update1104)
	require.NoError(t, err, "Failed to parse sc-update-1104.json")

	// At slot 1105, current sync committee
	syncCommittee := update1104.Data.NextSyncCommittee
	period := uint64(update1104.Data.AttestedHeader.Beacon.Slot / 8192)

	t.Logf("Loaded light client update (period %d, curr_sync_committee at period %d)",
		period, period+1)

	// Load light client update
	updateFile, err := os.ReadFile(filepath.Join(rootDir, "data/sc-update-1105.json"))
	require.NoError(t, err, "Failed to read light client update file")

	var update types.LightClientUpdate
	err = json.Unmarshal(updateFile, &update)
	require.NoError(t, err, "Failed to parse light client update JSON")

	t.Logf("Loaded light client update for slot %s", update.Data.AttestedHeader.Beacon.Slot)

	// Parse sync committee bits
	bits := types.ParseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)

	// Parse signature (G2 point)
	sigBytes := update.Data.SyncAggregate.SyncCommitteeSignature[:]
	var signature bls12381.G2Affine
	_, err = signature.SetBytes(sigBytes)
	require.NoError(t, err, "Failed to deserialize signature")

	// Parse all 512 public keys
	require.Equal(t, 512, len(syncCommittee.Pubkeys), "Expected 512 pubkeys")
	var pubkeys [512]bls12381.G1Affine
	for i := 0; i < 512; i++ {
		pubkeyBytes := syncCommittee.Pubkeys[i][:]
		_, err = pubkeys[i].SetBytes(pubkeyBytes)
		require.NoError(t, err, "Failed to deserialize pubkey %d", i)
	}

	// Create witness
	witness := &Eth2ScUpdateCircuit{}

	// Assign BeaconBlockHeader fields
	witness.Slot = uint64(update.Data.AttestedHeader.Beacon.Slot)
	witness.ProposerIndex = uint64(update.Data.AttestedHeader.Beacon.ProposerIndex)

	for i := 0; i < 32; i++ {
		witness.ParentRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.ParentRoot[i])
		witness.StateRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.StateRoot[i])
		witness.BodyRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.BodyRoot[i])
	}

	// Assign sync committee public keys (PRIVATE INPUT)
	for i := 0; i < 512; i++ {
		witness.ScPubKeys[i] = sw_bls12381.NewG1Affine(pubkeys[i])
	}

	// Compute commitment to sync committee public keys (PUBLIC INPUT)
	commitment := types.ComputeScPubKeysHash(pubkeys[:])
	fmt.Printf("curr_sync_committee hash: 0x%x\n", commitment)
	for i := 0; i < 32; i++ {
		witness.ScPubKeysHash[i] = uints.NewU8(commitment[i])
	}

	// Assign sync committee bits (PUBLIC INPUT)
	for i := 0; i < 512; i++ {
		if bits[i] {
			witness.ScBits[i] = 1
		} else {
			witness.ScBits[i] = 0
		}
	}

	// Assign BLS signature using gnark's conversion function
	witness.AggregatedSig = sw_bls12381.NewG2Affine(signature)

	// Assign next_sync_committee root and branch to witness
	assignNextSyncCommitteeToWitness(&update, witness)

	// Test the circuit using gnark test framework
	assert := gnark_test.NewAssert(t)
	err = gnark_test.IsSolved(&Eth2ScUpdateCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err, "Circuit constraints should be satisfied")
	t.Logf("✓ Proof solving SUCCEEDED!")

	//assert.CheckCircuit(&circuit.Eth2ScUpdateCircuit{}, gnark_test.WithCurves(ecc.BN254), gnark_test.WithValidAssignment(witness), gnark_test.WithBackends(backend.GROTH16))
}

func TestEth2ScUpdateCircuit(t *testing.T) {
	onceSetupCircuit()

	// Load sync committee
	update1104File, err := os.ReadFile(filepath.Join(rootDir, "data/sc-update-1104.json"))
	require.NoError(t, err, "Failed to read file")
	var update1104 types.LightClientUpdate
	err = json.Unmarshal(update1104File, &update1104)
	require.NoError(t, err, "Failed to parse sc-update-1104.json")

	// At slot 1105, current sync committee
	syncCommittee := update1104.Data.NextSyncCommittee
	period := uint64(update1104.Data.AttestedHeader.Beacon.Slot / 8192)

	t.Logf("Loaded light client update (period %d, curr_sync_committee at period %d)",
		period, period+1)

	// Load light client update
	updateFile, err := os.ReadFile(filepath.Join(rootDir, "data/sc-update-1105.json"))
	require.NoError(t, err, "Failed to read light client update file")

	var update types.LightClientUpdate
	err = json.Unmarshal(updateFile, &update)
	require.NoError(t, err, "Failed to parse light client update JSON")

	t.Logf("Loaded light client update for slot %s", update.Data.AttestedHeader.Beacon.Slot)

	// Parse sync committee bits
	bits := types.ParseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)

	// Parse signature (G2 point)
	sigBytes := update.Data.SyncAggregate.SyncCommitteeSignature[:]
	var signature bls12381.G2Affine
	_, err = signature.SetBytes(sigBytes)
	require.NoError(t, err, "Failed to deserialize signature")

	// Parse all 512 public keys
	require.Equal(t, 512, len(syncCommittee.Pubkeys), "Expected 512 pubkeys")
	var pubkeys [512]bls12381.G1Affine
	for i := 0; i < 512; i++ {
		pubkeyBytes := syncCommittee.Pubkeys[i][:]
		_, err = pubkeys[i].SetBytes(pubkeyBytes)
		require.NoError(t, err, "Failed to deserialize pubkey %d", i)
	}

	// Create witness
	witness := &Eth2ScUpdateCircuit{}

	// Assign BeaconBlockHeader fields
	witness.Slot = uint64(update.Data.AttestedHeader.Beacon.Slot)
	witness.ProposerIndex = uint64(update.Data.AttestedHeader.Beacon.ProposerIndex)
	for i := 0; i < 32; i++ {
		witness.ParentRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.ParentRoot[i])
		witness.StateRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.StateRoot[i])
		witness.BodyRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.BodyRoot[i])
	}

	// Assign sync committee public keys (PRIVATE INPUT)
	for i := 0; i < 512; i++ {
		witness.ScPubKeys[i] = sw_bls12381.NewG1Affine(pubkeys[i])
	}

	// Compute commitment to sync committee public keys (PUBLIC INPUT)
	commitment := types.ComputeScPubKeysHash(pubkeys[:])
	fmt.Printf("curr_sync_committee hash: 0x%x\n", commitment)
	for i := 0; i < 32; i++ {
		witness.ScPubKeysHash[i] = uints.NewU8(commitment[i])
	}

	// Assign sync committee bits (PUBLIC INPUT)
	for i := 0; i < 512; i++ {
		if bits[i] {
			witness.ScBits[i] = 1
		} else {
			witness.ScBits[i] = 0
		}
	}

	// Assign BLS signature using gnark's conversion function
	witness.AggregatedSig = sw_bls12381.NewG2Affine(signature)

	// Assign next_sync_committee root and branch to witness
	assignNextSyncCommitteeToWitness(&update, witness)

	// Test proof generation and verification
	// Create full witness
	fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	require.NoError(t, err, "Failed to create witness")

	// Create proof using pre-compiled circuit and keys
	proof, err := groth16.Prove(blsVerifierCCS, blsVerifierPK, fullWitness,
		backend.WithProverHashToFieldFunction(sha256.New()),
		backend.WithSolverOptions(
			solver.WithLogger(gnarkLogger),
		))
	require.NoError(t, err, "Proof generation failed")

	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	require.True(t, ok, "proof does not implement MarshalSolidity()")

	proofSolidity := _proof.MarshalSolidity()
	proofData := types.CreateProofData(proofSolidity)
	jsonBlob, _ := json.MarshalIndent(proofData, "", "  ")

	err = os.WriteFile(filepath.Join(rootDir, "data/proof-data.json"), jsonBlob, 0644)
	require.NoError(t, err, "Failed to write proof-data.json")

	fmt.Printf("Proof (solidity, %d bytes): 0x%x\n", len(proofSolidity), proofSolidity)

	t.Logf("Proof generated successfully")

	// Extract public inputs for verification
	publicWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	require.NoError(t, err, "Failed to create public witness")

	// Verify proof using pre-compiled verifying key
	err = groth16.Verify(proof, blsVerifierVK, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	require.NoError(t, err, "Proof verification failed")

	t.Logf("✓ Proof verification SUCCEEDED!")
}

func TestEth2ScUpdateCircuitInvalidSignature(t *testing.T) {
	onceSetupCircuit()

	// Load sync committee
	update1104File, err := os.ReadFile(filepath.Join(rootDir, "data/sc-update-1104.json"))
	require.NoError(t, err, "Failed to read file")
	var update1104 types.LightClientUpdate
	err = json.Unmarshal(update1104File, &update1104)
	require.NoError(t, err, "Failed to parse sc-update-1104.json")

	// At slot 1105, current sync committee
	syncCommittee := update1104.Data.NextSyncCommittee
	period := uint64(update1104.Data.AttestedHeader.Beacon.Slot / 8192)

	t.Logf("Loaded light client update (period %d, curr_sync_committee at period %d)",
		period, period+1)

	// Load light client update
	updateFile, err := os.ReadFile(filepath.Join(rootDir, "data/sc-update-1105.json"))
	require.NoError(t, err, "Failed to read light client update file")

	var update types.LightClientUpdate
	err = json.Unmarshal(updateFile, &update)
	require.NoError(t, err, "Failed to parse light client update JSON")

	// Parse sync committee bits
	bits := types.ParseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)

	// Parse all 512 public keys
	require.Equal(t, 512, len(syncCommittee.Pubkeys), "Expected 512 pubkeys")
	var pubkeys [512]bls12381.G1Affine
	for i := 0; i < 512; i++ {
		pubkeyBytes := syncCommittee.Pubkeys[i][:]
		_, err = pubkeys[i].SetBytes(pubkeyBytes)
		require.NoError(t, err, "Failed to deserialize pubkey %d", i)
	}

	// Use INVALID signature (random G2 point)
	var invalidSignature bls12381.G2Affine
	_, err = invalidSignature.X.SetRandom()
	require.NoError(t, err, "Failed to set random X")
	_, err = invalidSignature.Y.SetRandom()
	require.NoError(t, err, "Failed to set random Y")

	// Create witness with invalid signature
	witness := &Eth2ScUpdateCircuit{}

	witness.Slot = uint64(update.Data.AttestedHeader.Beacon.Slot)
	witness.ProposerIndex = uint64(update.Data.AttestedHeader.Beacon.ProposerIndex)
	for i := 0; i < 32; i++ {
		witness.ParentRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.ParentRoot[i])
		witness.StateRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.StateRoot[i])
		witness.BodyRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.BodyRoot[i])
	}

	// Assign sync committee public keys (PRIVATE INPUT)
	for i := 0; i < 512; i++ {
		witness.ScPubKeys[i] = sw_bls12381.NewG1Affine(pubkeys[i])
	}

	// Compute commitment to sync committee public keys (PUBLIC INPUT)
	commitment := types.ComputeScPubKeysHash(pubkeys[:])
	fmt.Printf("curr_sync_committee hash: 0x%x\n", commitment)
	for i := 0; i < 32; i++ {
		witness.ScPubKeysHash[i] = uints.NewU8(commitment[i])
	}

	// Assign sync committee bits (PUBLIC INPUT)
	for i := 0; i < 512; i++ {
		if bits[i] {
			witness.ScBits[i] = 1
		} else {
			witness.ScBits[i] = 0
		}
	}

	// Assign INVALID signature
	witness.AggregatedSig = sw_bls12381.NewG2Affine(invalidSignature)

	// Assign next_sync_committee root and branch to witness
	assignNextSyncCommitteeToWitness(&update, witness)

	// Create witness
	fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	require.NoError(t, err, "Failed to create witness")

	// Try to create proof with invalid signature - this should fail
	proof, err := groth16.Prove(blsVerifierCCS, blsVerifierPK, fullWitness)
	if err != nil {
		t.Logf("✓ Proof generation correctly failed with invalid signature: %v", err)
		return
	}

	// If proof was generated, verification should fail
	publicWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	require.NoError(t, err, "Failed to create public witness")

	err = groth16.Verify(proof, blsVerifierVK, publicWitness)
	if err != nil {
		t.Logf("✓ Proof verification correctly failed with invalid signature")
	} else {
		t.Fatal("Expected verification to fail with invalid signature, but it succeeded!")
	}
}

func TestEth2ScUpdateCircuitInvalidBlockRoot(t *testing.T) {
	onceSetupCircuit()

	// Load sync committee
	update1104File, err := os.ReadFile(filepath.Join(rootDir, "data/sc-update-1104.json"))
	require.NoError(t, err, "Failed to read file")
	var update1104 types.LightClientUpdate
	err = json.Unmarshal(update1104File, &update1104)
	require.NoError(t, err, "Failed to parse sc-update-1104.json")

	// At slot 1105, current sync committee
	syncCommittee := update1104.Data.NextSyncCommittee
	period := uint64(update1104.Data.AttestedHeader.Beacon.Slot / 8192)

	t.Logf("Loaded light client update (period %d, curr_sync_committee at period %d)",
		period, period+1)

	// Load light client update
	updateFile, err := os.ReadFile(filepath.Join(rootDir, "data/sc-update-1105.json"))
	require.NoError(t, err, "Failed to read light client update file")

	var update types.LightClientUpdate
	err = json.Unmarshal(updateFile, &update)
	require.NoError(t, err, "Failed to parse light client update JSON")

	// Parse sync committee bits
	bits := types.ParseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)

	// Parse all 512 public keys
	require.Equal(t, 512, len(syncCommittee.Pubkeys), "Expected 512 pubkeys")
	var pubkeys [512]bls12381.G1Affine
	for i := 0; i < 512; i++ {
		pubkeyBytes := syncCommittee.Pubkeys[i][:]
		_, err = pubkeys[i].SetBytes(pubkeyBytes)
		require.NoError(t, err, "Failed to deserialize pubkey %d", i)
	}

	// Parse signature
	sigBytes := update.Data.SyncAggregate.SyncCommitteeSignature[:]
	var signature bls12381.G2Affine
	_, err = signature.SetBytes(sigBytes)
	require.NoError(t, err, "Failed to deserialize signature")

	// Use INVALID block root
	var invalidBlockRoot [32]byte
	for i := 0; i < 32; i++ {
		invalidBlockRoot[i] = 0xFF
	}

	// Create witness with invalid block root
	witness := &Eth2ScUpdateCircuit{}

	witness.Slot = uint64(update.Data.AttestedHeader.Beacon.Slot)
	witness.ProposerIndex = uint64(update.Data.AttestedHeader.Beacon.ProposerIndex)
	for i := 0; i < 32; i++ {
		witness.ParentRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.ParentRoot[i])
		witness.StateRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.StateRoot[i])
		witness.BodyRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.BodyRoot[i])
	}

	// Assign sync committee public keys (PRIVATE INPUT)
	for i := 0; i < 512; i++ {
		witness.ScPubKeys[i] = sw_bls12381.NewG1Affine(pubkeys[i])
	}

	// Compute commitment to sync committee public keys (PUBLIC INPUT)
	commitment := types.ComputeScPubKeysHash(pubkeys[:])
	fmt.Printf("curr_sync_committee hash: 0x%x\n", commitment)
	for i := 0; i < 32; i++ {
		witness.ScPubKeysHash[i] = uints.NewU8(commitment[i])
	}

	// Assign sync committee bits (PUBLIC INPUT)
	for i := 0; i < 512; i++ {
		if bits[i] {
			witness.ScBits[i] = 1
		} else {
			witness.ScBits[i] = 0
		}
	}

	witness.AggregatedSig = sw_bls12381.NewG2Affine(signature)

	// Assign next_sync_committee root and branch to witness
	assignNextSyncCommitteeToWitness(&update, witness)

	// Create witness
	fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	require.NoError(t, err, "Failed to create witness")

	// Try to create proof with invalid block root - this should fail
	_, err = groth16.Prove(blsVerifierCCS, blsVerifierPK, fullWitness)
	require.Error(t, err, "Expected proof generation to fail with invalid block root")

	t.Logf("✓ Proof generation correctly failed with invalid block root: %v", err)
}

// Benchmark the circuit
func BenchmarkEth2ScUpdateCircuit(b *testing.B) {
	onceSetupCircuit()

	// Load test data
	update1104File, err := os.ReadFile(filepath.Join(rootDir, "data/sc-update-1104.json"))
	require.NoError(b, err, "Failed to read file")
	var update1104 types.LightClientUpdate
	err = json.Unmarshal(update1104File, &update1104)
	require.NoError(b, err, "Failed to parse sc-update-1104.json")
	// At slot 1105, current sync committee
	syncCommittee := update1104.Data.NextSyncCommittee

	updateFile, _ := os.ReadFile(filepath.Join(rootDir, "data/sc-update-1105.json"))
	var update types.LightClientUpdate
	json.Unmarshal(updateFile, &update)

	bits := types.ParseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)

	// Parse all 512 public keys
	var pubkeys [512]bls12381.G1Affine
	for i := 0; i < 512; i++ {
		pubkeyBytes := syncCommittee.Pubkeys[i][:]
		_, _ = pubkeys[i].SetBytes(pubkeyBytes)
	}

	sigBytes := update.Data.SyncAggregate.SyncCommitteeSignature[:]
	var signature bls12381.G2Affine
	_, _ = signature.SetBytes(sigBytes)

	witness := &Eth2ScUpdateCircuit{}
	witness.Slot = uint64(update.Data.AttestedHeader.Beacon.Slot)
	witness.ProposerIndex = uint64(update.Data.AttestedHeader.Beacon.ProposerIndex)
	for i := 0; i < 32; i++ {
		witness.ParentRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.ParentRoot[i])
		witness.StateRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.StateRoot[i])
		witness.BodyRoot[i] = uints.NewU8(update.Data.AttestedHeader.Beacon.BodyRoot[i])
	}

	// Assign sync committee public keys (PRIVATE INPUT)
	for i := 0; i < 512; i++ {
		witness.ScPubKeys[i] = sw_bls12381.NewG1Affine(pubkeys[i])
	}

	// Compute commitment to sync committee public keys (PUBLIC INPUT)
	commitment := types.ComputeScPubKeysHash(pubkeys[:])
	fmt.Printf("curr_sync_committee hash: 0x%x\n", commitment)
	for i := 0; i < 32; i++ {
		witness.ScPubKeysHash[i] = uints.NewU8(commitment[i])
	}

	// Assign sync committee bits (PUBLIC INPUT)
	for i := 0; i < 512; i++ {
		if bits[i] {
			witness.ScBits[i] = 1
		} else {
			witness.ScBits[i] = 0
		}
	}

	witness.AggregatedSig = sw_bls12381.NewG2Affine(signature)

	// Assign next_sync_committee root and branch to witness
	assignNextSyncCommitteeToWitness(&update, witness)

	// Create witness once
	fullWitness, _ := frontend.NewWitness(witness, ecc.BN254.ScalarField())

	b.Run("ProofGeneration", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := groth16.Prove(blsVerifierCCS, blsVerifierPK, fullWitness)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Generate proof once for verification benchmark
	proof, _ := groth16.Prove(blsVerifierCCS, blsVerifierPK, fullWitness)
	publicWitness, _ := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())

	b.Run("ProofVerification", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := groth16.Verify(proof, blsVerifierVK, publicWitness)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Compile the circuit and performs setup once for all tests
func onceSetupCircuit() {
	if blsVerifierCCS != nil {
		fmt.Println("Circuit already compiled and setup")
		return
	}
	//
	// Compile circuit
	var err error

	ccsPath := filepath.Join(rootDir, ".build/Eth2ScUpdateCircuit.ccs")
	pkPath := filepath.Join(rootDir, ".build/Eth2ScUpdateCircuit.pk")
	vkPath := filepath.Join(rootDir, ".build/Eth2ScUpdateCircuit.vk")

	// Step 1: Circuit compile
	fCcs, err := os.Open(ccsPath)
	defer fCcs.Close()

	if err != nil {
		fmt.Println("Compiling Eth2ScUpdateCircuit circuit...")
		// Compile with BN254 scalar field (for emulated BLS12-381)
		blsVerifierCCS, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Eth2ScUpdateCircuit{})
		if err != nil {
			panic(err)
		}
		fCcs, _ = os.Create(ccsPath)
		_, _ = blsVerifierCCS.WriteTo(fCcs)
	} else {
		fmt.Println("Loading Eth2ScUpdateCircuit circuit...")

		blsVerifierCCS = groth16.NewCS(ecc.BN254)
		_, err = blsVerifierCCS.ReadFrom(fCcs)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("✓ Circuit has %d constraints, %d public inputs\n", blsVerifierCCS.GetNbConstraints(), blsVerifierCCS.GetNbPublicVariables())

	// Step 2: Setup (generate proving and verifying keys)
	fpk, err0 := os.Open(pkPath)
	defer fpk.Close()
	fvk, err1 := os.Open(vkPath)
	defer fvk.Close()

	if err0 != nil || err1 != nil {
		fmt.Println("Generating proving and verifying keys...")
		blsVerifierPK, blsVerifierVK, err = groth16.Setup(blsVerifierCCS)
		if err != nil {
			panic(err)
		}
		fpk, _ = os.Create(pkPath)
		_, _ = blsVerifierPK.WriteTo(fpk)

		fvk, _ = os.Create(vkPath)
		_, _ = blsVerifierVK.WriteTo(fvk)
	} else {
		fmt.Println("Loading proving and verifying keys...")
		blsVerifierPK = groth16.NewProvingKey(ecc.BN254)
		blsVerifierVK = groth16.NewVerifyingKey(ecc.BN254)
		if _, err := blsVerifierPK.ReadFrom(fpk); err != nil {
			panic(err)
		}
		if _, err := blsVerifierVK.ReadFrom(fvk); err != nil {
			panic(err)
		}
	}
	fmt.Println("✓ Setup complete")
}

// assignNextSyncCommitteeToWitness computes next_sync_committee root and assigns it along with
// next_sync_committee_branch to the witness
func assignNextSyncCommitteeToWitness(
	update *types.LightClientUpdate,
	witness *Eth2ScUpdateCircuit,
) {
	// Compute next_sync_committee root
	nextSCRoot := update.Data.NextSyncCommittee.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
	fmt.Printf("next_sync_committee root: %v\n", nextSCRoot.String())

	// Assign next_sync_committee root (public input)
	for i := 0; i < 32; i++ {
		witness.NextScRoot[i] = uints.NewU8(nextSCRoot[i])
	}

	// Assign next_sync_committee_branch (private input)
	for i := 0; i < 6; i++ {
		for j := 0; j < 32; j++ {
			witness.NextScBranch[i][j] = uints.NewU8(update.Data.NextSyncCommitteeBranch[i][j])
		}
	}
}

func mustGetRootDir() string {
	root, err := projectRoot(".")
	if err != nil {
		panic(err)
	}
	return root
}

// projectRoot finds the project root directory by searching for go.mod file
// starting from the given startPath (default: current directory)
func projectRoot(startPath ...string) (string, error) {
	start := "."
	if len(startPath) > 0 {
		start = startPath[0]
	}

	// Convert to absolute path
	currentPath, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Walk up directory tree until we find go.mod
	for {
		// Check if go.mod exists in current directory
		goModPath := filepath.Join(currentPath, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			fmt.Println("found project root dir:", currentPath)
			return currentPath, nil
		}

		// Get parent directory
		parentPath := filepath.Dir(currentPath)

		// Check if we've reached the root
		if parentPath == currentPath {
			return "", fmt.Errorf("not found project root dir")
		}

		currentPath = parentPath
		fmt.Println("next dir:", currentPath)
	}
}
