package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	gnark_ecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// MaxNestedProofs is the maximum number of signatures to verify in a single circuit
const MaxNestedProofs = 8

// NestedBPrNMsgHCircuit verifies multiple P256 ECDSA signatures on PreH + TargetH
// All signatures must use the same TargetH (public input)
//
// This is a "nested circuit" approach where inner circuit logic is directly
// embedded in the outer circuit. Unlike recursive proofs, this creates a single
// proof that verifies all signatures at once.
//
// Pros:
//   - Simple implementation, no curve cycles needed
//   - Single proof generation
//   - No recursive verification overhead
//
// Cons:
//   - Cannot generate proofs in parallel (single proof for all)
//   - Constraints scale linearly with number of signatures
//   - Proving time increases with more signatures
type NestedBPrNMsgHCircuit struct {
	// Public input - shared TargetH across all signatures
	TargetH [32]uints.U8 `gnark:",public"`

	// Number of actual signatures to verify (must be <= MaxNestedProofs)
	NumSigs frontend.Variable `gnark:",public"`

	// Secret inputs for each signature
	Pubs  [MaxNestedProofs]gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	Sigs  [MaxNestedProofs]gnark_ecdsa.Signature[emulated.P256Fr]
	PreHs [MaxNestedProofs][32]uints.U8
}

func (c *NestedBPrNMsgHCircuit) Define(api frontend.API) error {
	// Verify each signature
	for i := 0; i < MaxNestedProofs; i++ {
		// Determine if this slot is active (i < NumSigs)
		iConst := frontend.Variable(i)
		cmpResult := api.Cmp(c.NumSigs, iConst) // 1 if NumSigs > i
		isActive := api.IsZero(api.Sub(cmpResult, 1))

		// Call inner circuit logic for this signature
		err := c.verifySignature(api, i, isActive)
		if err != nil {
			return err
		}
	}

	return nil
}

// verifySignature implements the BPrNMsgHCircuit logic for a single signature
// This is essentially calling the inner circuit's Define logic
func (c *NestedBPrNMsgHCircuit) verifySignature(api frontend.API, idx int, isActive frontend.Variable) error {
	// Create a new SHA256 hasher
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}

	// Write 64 bytes total (PreH || TargetH)
	hasher.Write(c.PreHs[idx][:])
	hasher.Write(c.TargetH[:])

	// Compute SHA256 hash
	computedHash := hasher.Sum()

	// Convert computed hash to emulated.Element for P256Fr (scalar field)
	scalarApi, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return err
	}
	msgHash := hashBytesToElement(api, scalarApi, computedHash)

	// For inactive slots, we still need to run the verification but with dummy data
	// The verification will pass because we provide valid dummy signatures
	// Alternatively, we can use conditional logic to skip verification

	// Verify ECDSA P256 signature
	// Note: For inactive slots, dummy valid signatures must be provided
	c.Pubs[idx].Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), msgHash, &c.Sigs[idx])

	// If we want to conditionally skip verification for inactive slots,
	// we would need to modify the verification logic or use selector patterns
	// For now, we require valid dummy signatures for all slots

	_ = isActive // Can be used for conditional logic if needed

	return nil
}

// ============================================================================
// Alternative: Fixed size variant (simpler, no NumSigs)
// ============================================================================

// NestedBPrNMsgHCircuitFixed verifies exactly N P256 ECDSA signatures
// Use this when the number of signatures is known at compile time
type NestedBPrNMsgHCircuitFixed[N interface{ ~int }] struct {
	// Public input - shared TargetH across all signatures
	TargetH [32]uints.U8 `gnark:",public"`

	// Secret inputs for each signature
	Pubs  []gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	Sigs  []gnark_ecdsa.Signature[emulated.P256Fr]
	PreHs [][32]uints.U8
}

// NestedBPrNMsgH2Circuit verifies exactly 2 signatures
type NestedBPrNMsgH2Circuit struct {
	TargetH [32]uints.U8 `gnark:",public"`

	Pub0  gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	Sig0  gnark_ecdsa.Signature[emulated.P256Fr]
	PreH0 [32]uints.U8

	Pub1  gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	Sig1  gnark_ecdsa.Signature[emulated.P256Fr]
	PreH1 [32]uints.U8
}

func (c *NestedBPrNMsgH2Circuit) Define(api frontend.API) error {
	// Verify signature 0
	if err := verifySingleSignature(api, c.PreH0, c.TargetH, c.Pub0, c.Sig0); err != nil {
		return err
	}

	// Verify signature 1
	if err := verifySingleSignature(api, c.PreH1, c.TargetH, c.Pub1, c.Sig1); err != nil {
		return err
	}

	return nil
}

// NestedBPrNMsgH4Circuit verifies exactly 4 signatures
type NestedBPrNMsgH4Circuit struct {
	TargetH [32]uints.U8 `gnark:",public"`

	Pub0  gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	Sig0  gnark_ecdsa.Signature[emulated.P256Fr]
	PreH0 [32]uints.U8

	Pub1  gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	Sig1  gnark_ecdsa.Signature[emulated.P256Fr]
	PreH1 [32]uints.U8

	Pub2  gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	Sig2  gnark_ecdsa.Signature[emulated.P256Fr]
	PreH2 [32]uints.U8

	Pub3  gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	Sig3  gnark_ecdsa.Signature[emulated.P256Fr]
	PreH3 [32]uints.U8
}

func (c *NestedBPrNMsgH4Circuit) Define(api frontend.API) error {
	if err := verifySingleSignature(api, c.PreH0, c.TargetH, c.Pub0, c.Sig0); err != nil {
		return err
	}
	if err := verifySingleSignature(api, c.PreH1, c.TargetH, c.Pub1, c.Sig1); err != nil {
		return err
	}
	if err := verifySingleSignature(api, c.PreH2, c.TargetH, c.Pub2, c.Sig2); err != nil {
		return err
	}
	if err := verifySingleSignature(api, c.PreH3, c.TargetH, c.Pub3, c.Sig3); err != nil {
		return err
	}
	return nil
}

// verifySingleSignature is the core BPrNMsgHCircuit logic extracted as a helper
func verifySingleSignature(
	api frontend.API,
	preH [32]uints.U8,
	targetH [32]uints.U8,
	pub gnark_ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr],
	sig gnark_ecdsa.Signature[emulated.P256Fr],
) error {
	// Create SHA256 hasher
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}

	// Hash PreH || TargetH
	hasher.Write(preH[:])
	hasher.Write(targetH[:])
	computedHash := hasher.Sum()

	// Convert to scalar field element
	scalarApi, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return err
	}
	msgHash := hashBytesToElement(api, scalarApi, computedHash)

	// Verify signature
	pub.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), msgHash, &sig)

	return nil
}
