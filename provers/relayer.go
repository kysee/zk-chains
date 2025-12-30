package relayer

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/kysee/zk-chains/circuits"
	cfgtypes "github.com/kysee/zk-chains/provers/types"
	"github.com/kysee/zk-chains/types"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/tree"
)

// Main entry point for the relayer
func RelayerMain(config *cfgtypes.Config) {
	// Create and run relayer
	relayer, err := NewRelayer(config, NewAPIFetcher(config.RPCEndpoint))
	if err != nil {
		log.Fatalf("Failed to create relayer: %v", err)
	}

	// Setup circuit first
	if err := relayer.setupCircuit(); err != nil {
		log.Fatalf("failed to setup circuit: %w", err)
	}

	if err := relayer.Run(); err != nil {
		log.Fatalf("Failed to run relayer: %v", err)
	}
}

// Relayer is the main relayer struct
type Relayer struct {
	config           *cfgtypes.Config
	fetcher          cfgtypes.Fetcher
	ccs              constraint.ConstraintSystem
	pk               groth16.ProvingKey
	scPubKeysHash    []byte
	currentScPubkeys [512]bls12381.G1Affine
}

// NewRelayer creates a new Relayer with the given configuration
func NewRelayer(config *cfgtypes.Config, fetcher cfgtypes.Fetcher) (*Relayer, error) {
	_ = os.MkdirAll(config.RootDir, 0755)

	return &Relayer{
		fetcher: fetcher,
		config:  config,
	}, nil
}

// Run executes the relayer to fetch and display attested header information
func (r *Relayer) Run() error {
	period := r.config.InitPeriod
	log.Printf("Starting from period %d\n", period)

	// Fetch first update to initialize currentScPubkeys
	log.Printf("\n### Fetching initial update for period %d ###\n", period)
	var err error
	initialUpdate, err := r.fetcher.ScUpdate(period)
	if err != nil {
		return fmt.Errorf("failed to fetch initial update: %w", err)
	}

	// Parse and store current sync committee pubkeys
	for i := 0; i < 512; i++ {
		pubkeyBytes := initialUpdate.Data.NextSyncCommittee.Pubkeys[i][:]
		_, err = r.currentScPubkeys[i].SetBytes(pubkeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse pubkey %d: %w", i, err)
		}
	}

	// Compute and store scPubKeysHash
	hashArray := types.ComputeScPubKeysHash(r.currentScPubkeys[:])
	r.scPubKeysHash = hashArray[:]
	log.Printf("Initial scPubKeysHash: 0x%x\n", r.scPubKeysHash)

	period++

	// Main loop
	for {
		// Fetch update
		log.Printf("\n### Fetching update for period %d ###\n", period)
		update, err := r.fetcher.ScUpdate(period)
		if err != nil {
			log.Println("error", err)
			time.Sleep(1000 * time.Millisecond)
			continue //return fmt.Errorf("failed to fetch update for period %d: %w", period, err)
		}

		//// Display attested header information
		//attestedHeader := update.Data.AttestedHeader
		//log.Printf("=== Attested Header ===\n")
		//log.Printf("Beacon Block Header:\n")
		//log.Printf("  Slot: %s\n", attestedHeader.Beacon.Slot)
		//log.Printf("  Proposer Index: %s\n", attestedHeader.Beacon.ProposerIndex)
		//log.Printf("Execution Payload Header:\n")
		//log.Printf("  Block Number: %s\n", attestedHeader.Execution.BlockNumber)
		//log.Printf("  Block Hash: %s\n", attestedHeader.Execution.BlockHash)
		//log.Printf("  Timestamp: %s\n", attestedHeader.Execution.Timestamp)

		// Generate proof
		log.Printf("\n=== Generating proof ===\n")
		log.Printf("Current scPubKeysHash: 0x%x\n", r.scPubKeysHash)

		proofSolidity, err := r.generateProof(update)
		if err != nil {
			return fmt.Errorf("failed to generate proof: %w", err)
		}

		// Save proof to file
		outputPath := fmt.Sprintf("output/proof-period-%d.json", period)
		proofData := types.CreateProofData(proofSolidity)
		jsonBlob, err := json.MarshalIndent(proofData, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal proof data: %w", err)
		}
		err = os.WriteFile(outputPath, jsonBlob, 0644)
		if err != nil {
			return fmt.Errorf("failed to write proof file: %w", err)
		}
		log.Printf("✓ Proof saved to %s\n", outputPath)

		// Update pubkeys and scPubKeysHash for next iteration
		for i := 0; i < 512; i++ {
			pubkeyBytes := update.Data.NextSyncCommittee.Pubkeys[i][:]
			_, err = r.currentScPubkeys[i].SetBytes(pubkeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse pubkey %d: %w", i, err)
			}
		}
		hashArray := types.ComputeScPubKeysHash(r.currentScPubkeys[:])
		r.scPubKeysHash = hashArray[:]
		log.Printf("Updated scPubKeysHash: 0x%x\n", r.scPubKeysHash)

		// Move to next period
		period++

		time.Sleep(1000 * time.Millisecond)
	}
}

// setupCircuit loads the compiled circuit and proving key from output directory
func (r *Relayer) setupCircuit() error {
	if r.ccs != nil {
		log.Println("Circuit already loaded")
		return nil
	}

	ccsPath := filepath.Join(r.config.RootDir, "../.build/Eth2ScUpdateCircuit.ccs")
	pkPath := filepath.Join(r.config.RootDir, "../.build/Eth2ScUpdateCircuit.pk")

	// Load compiled circuit
	log.Println("Loading Eth2ScUpdateCircuit...")
	fCcs, err := os.Open(ccsPath)
	if err != nil {
		return fmt.Errorf("failed to open CCS file: %w", err)
	}

	r.ccs = groth16.NewCS(ecc.BN254)
	_, err = r.ccs.ReadFrom(fCcs)
	_ = fCcs.Close()
	if err != nil {
		return fmt.Errorf("failed to read CCS: %w", err)
	}

	log.Printf("✓ Circuit loaded: %d constraints\n", r.ccs.GetNbConstraints())

	// Load proving key
	log.Println("Loading proving key...")
	fpk, err := os.Open(pkPath)
	if err != nil {
		return fmt.Errorf("failed to open PK file: %w", err)
	}

	r.pk = groth16.NewProvingKey(ecc.BN254)
	_, err = r.pk.ReadFrom(fpk)
	_ = fpk.Close()
	if err != nil {
		return fmt.Errorf("failed to read PK: %w", err)
	}

	log.Println("✓ Proving key loaded")
	return nil
}

// generateProof generates a ZK proof for the given light client update
// update contains the update to prove
// Uses r.currentScPubkeys and r.scPubKeysHash
func (r *Relayer) generateProof(update *types.LightClientUpdate) ([]byte, error) {
	// Parse sync committee bits from update
	bits := types.ParseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)

	// Parse signature (G2 point)
	sigBytes := update.Data.SyncAggregate.SyncCommitteeSignature[:]
	var signature bls12381.G2Affine
	_, err := signature.SetBytes(sigBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize signature: %w", err)
	}

	// Create witness
	witness := &circuit.Eth2ScUpdateCircuit{}

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
		witness.ScPubKeys[i] = sw_bls12381.NewG1Affine(r.currentScPubkeys[i])
	}

	// Use r.scPubKeysHash directly (PUBLIC INPUT)
	for i := 0; i < 32; i++ {
		witness.ScPubKeysHash[i] = uints.NewU8(r.scPubKeysHash[i])
	}

	// Assign sync committee bits (PUBLIC INPUT)
	for i := 0; i < 512; i++ {
		if bits[i] {
			witness.ScBits[i] = 1
		} else {
			witness.ScBits[i] = 0
		}
	}

	// Assign BLS signature
	witness.AggregatedSig = sw_bls12381.NewG2Affine(signature)

	// Assign next_sync_committee root and branch to witness
	assignNextSyncCommitteeToWitness(update, witness)

	// Create full witness
	fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	// Generate proof
	log.Println("Generating proof...")
	proof, err := groth16.Prove(r.ccs, r.pk, fullWitness,
		backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		return nil, fmt.Errorf("proof generation failed: %w", err)
	}

	// Convert to Solidity format
	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		return nil, fmt.Errorf("proof does not implement MarshalSolidity()")
	}

	proofSolidity := _proof.MarshalSolidity()
	log.Printf("✓ Proof generated successfully (%d bytes)\n", len(proofSolidity))

	return proofSolidity, nil
}

// assignNextSyncCommitteeToWitness computes next_sync_committee root and assigns it along with
// next_sync_committee_branch to the witness
func assignNextSyncCommitteeToWitness(
	update *types.LightClientUpdate,
	witness *circuit.Eth2ScUpdateCircuit,
) {
	// Compute next_sync_committee root
	nextSCRoot := update.Data.NextSyncCommittee.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
	//log.Printf("next_sync_committee root: %v\n", nextSCRoot.String())

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
