package circuits

import (
	"fmt"
	"path/filepath"
	"testing"

	bprnEvent "github.com/beatoz/chaincode-base/event"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

var evtPayload bprnEvent.EventPayload

type InnerProofResult struct {
	Index   int
	Proof   groth16.Proof
	Witness witness.Witness
	Err     error
}

func init() {
	for i := 0; i < 11; i++ {
		evtPayload = append(evtPayload, &bprnEvent.EventLog{
			Chaincode: fmt.Sprintf("chaincode-%d", i),
			Name:      "PostMessageEventLog",
			Values: &bprnEvent.PostMessageEventLogValue{
				SrcChainId: fmt.Sprintf("srcChainId-%d", i),
				SrcDappId:  fmt.Sprintf("srcDappId-%d", i),
				SrcAcctId:  fmt.Sprintf("srcAcctId-%d", i),
				DstChainId: fmt.Sprintf("dstChainId-%d", i),
				DstDappId:  fmt.Sprintf("dstDappId-%d", i),
				DstAcctId:  fmt.Sprintf("dstAcctId-%d", i),
				MsgIdx:     uint64(i * 100),
				MsgPayload: []byte(fmt.Sprintf("hello world-%d", i)),
			},
		})
	}
}

func TestBPrNEventProofCircuit_Compile(t *testing.T) {
	//
	// Inner Circuit
	var innerCircuit P256ProofCircuit
	innerCcs, _, _ := LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &innerCircuit)

	// Create placeholders using inner circuit's constraint system
	placeholderVK := stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs)
	placeholderProof := stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs)
	placeholderWitness := stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs)

	// Build outer circuit with placeholders
	var circuitProofs [MaxP256Proofs]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	var circuitWitnesses [MaxP256Proofs]stdgroth16.Witness[sw_bn254.ScalarField]

	for i := 0; i < MaxP256Proofs; i++ {
		circuitProofs[i] = placeholderProof
		circuitWitnesses[i] = placeholderWitness
	}

	outerCircuit := BPrNEventProofCircuit{
		Proofs:    circuitProofs,
		Witnesses: circuitWitnesses,
		VK:        placeholderVK,
	}

	_, _, _ = LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &outerCircuit)
}

//func TestBPrNEventProofCircuit(t *testing.T) {
//	// Generate P256 key pair
//	privKeys := make([]*ecdsa.PrivateKey, 5)
//	for i := 0; i < len(privKeys); i++ {
//		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//		require.NoError(t, err)
//		privKeys[i] = privKey
//	}
//
//	// Prepare data
//	payloadTree := bprnEvent.NewMerkleTreeType(evtPayload)
//	originPayloadH := sha256.Sum256([]byte("any_random_bytes"))
//	eventPayloadH, err := payloadTree.Root()
//	require.NoError(t, err)
//
//	evtLogIdx := mrand.Intn(len(evtPayload))
//	evtLog := evtPayload[evtLogIdx]
//	evtLogTree := bprnEvent.NewMerkleTreeType(evtLog)
//	evtLogRoot, err := evtLogTree.Root()
//	require.NoError(t, err)
//	evtLogRootH := sha256.Sum256(evtLogRoot[:])
//	evtLogRootBranches, err := payloadTree.Proof(evtLogIdx)
//	require.NoError(t, err)
//
//	require.True(t, MerkleVerify(evtLogIdx, evtLogRootH[:], evtLogRootBranches, eventPayloadH))
//
//	elems := evtLog.Leaves()
//	elemIdx := mrand.Intn(len(elems))
//	evtElemH := sha256.Sum256(elems[elemIdx]) // target to verify
//	evtElemBranches, err := evtLogTree.Proof(elemIdx)
//
//	require.True(t, MerkleVerify(elemIdx, evtElemH[:], evtElemBranches, evtLogRoot))
//
//	// Concatenate OriginPayloadH and EventPayloadH
//	// and hash the concatenated data
//	msgh := sha256.Sum256(append(originPayloadH[:], eventPayloadH[:]...))
//
//	//
//	// Inner Circuit
//	var innerCircuit P256ProofCircuit
//	innerCcs, innerPk, innerVk := LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &innerCircuit)
//
//	numProofs := len(privKeys)
//	innerProofsCh := make(chan *InnerProofResult, numProofs)
//
//	var wg sync.WaitGroup
//	for i := 0; i < len(privKeys); i++ {
//		wg.Add(1)
//		go func(idx int) {
//			defer wg.Done()
//
//			privKey := privKeys[idx]
//
//			// Sign the hash
//			sigDER, err := privKey.Sign(rand.Reader, msgh[:], nil)
//			require.NoError(t, err)
//
//			// Parse DER signature to get R and S
//			r, s, err := proverTypes.ParseDERSignature(sigDER)
//			require.NoError(t, err)
//
//			// Verify signature outside circuit first
//			valid := ecdsa.Verify(&privKey.PublicKey, msgh[:], r, s)
//			require.True(t, valid, "signature should be valid")
//
//			// Create witness for inner circuit
//			assignment := P256ProofCircuit{
//				Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
//					X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
//					Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
//				},
//				Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
//					R: emulated.ValueOf[emulated.P256Fr](r),
//					S: emulated.ValueOf[emulated.P256Fr](s),
//				},
//				H0:   ToU8Array32(originPayloadH[:]),
//				MsgH: ToU8Array32(evtElemH[:]),
//			}
//
//			// Test that the circuit is satisfied
//			assert := test.NewAssert(t)
//			err = test.IsSolved(&P256ProofCircuit{}, &assignment, ecc.BN254.ScalarField())
//			assert.NoError(err)
//
//			wit, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
//			require.NoError(t, err)
//
//			proof, err := groth16.Prove(innerCcs, innerPk, wit)
//			require.NoError(t, err)
//
//			innerProofsCh <- &InnerProofResult{
//				Index:   idx,
//				Proof:   proof,
//				Witness: wit,
//				Err:     nil,
//			}
//		}(i)
//	}
//
//	go func() {
//		wg.Wait()
//		close(innerProofsCh)
//	}()
//
//	// Convert proofs and witnesses
//	var circuitProofs [MaxP256Proofs]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
//	var circuitWitnesses [MaxP256Proofs]stdgroth16.Witness[sw_bn254.ScalarField]
//
//	// Convert inner VK to circuit format
//	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
//	require.NoError(t, err)
//
//	for innerProof := range innerProofsCh {
//		idx := innerProof.Index
//
//		circuitProofs[idx], err = stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof.Proof)
//		require.NoError(t, err)
//
//		pubWit, err := innerProof.Witness.Public()
//		require.NoError(t, err)
//		circuitWitnesses[idx], err = stdgroth16.ValueOfWitness[sw_bn254.ScalarField](pubWit)
//		require.NoError(t, err)
//	}
//
//	//
//	// Outer circuit
//	var outerCircuit BPrNEventProofCircuit
//
//	var _evtLogRootBranches [MaxMerkleDepth][32]uints.U8
//	var _evtElemBranches [MaxMerkleDepth][32]uints.U8
//
//	for i, br := range evtLogRootBranches {
//		_evtLogRootBranches[i] = ToU8Array32(br)
//	}
//	for i, br := range evtElemBranches {
//		_evtElemBranches[i] = ToU8Array32(br)
//	}
//
//	outerAssignment := BPrNEventProofCircuit{
//		NumProofs:            int64(numProofs),
//		Proofs:               circuitProofs,
//		Witnesses:            circuitWitnesses,
//		VK:                   circuitVk,
//		EventPayloadH:        ToU8Array32(originPayloadH[:]),
//		EventLogIdx:          int64(evtLogIdx),
//		EventLogRootBranches: _evtLogRootBranches,
//		EventLogRoot:         ToU8Array32(evtLogRoot),
//		EventElemIdx:         int64(elemIdx),
//		EventElemHBranches:   _evtElemBranches,
//		EventElemH:           ToU8Array32(evtElemH[:]),
//	}
//
//	t.Logf("P256 ECDSA signature verification circuit test passed")
//	t.Logf("OriginPayloadH: %x", originPayloadH)
//	t.Logf("EventPayloadH: %x", eventPayloadH)
//	t.Logf("EventLog Index: %v", evtLogIdx)
//	t.Logf("EventLog Leaf[%v], %v", elemIdx, string(elems[elemIdx]))
//}
//
//func TestBPrNEventProofCircuit_WrongMsgH(t *testing.T) {
//	// Generate P256 key pair
//	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//	require.NoError(t, err)
//
//	// Prepare data
//	preMsgH := sha256.Sum256([]byte("premessage_message"))
//	msgH := sha256.Sum256([]byte("public_message"))
//	wrongMsgH := sha256.Sum256([]byte("wrong_message"))
//
//	// Concatenate OriginPayloadH and EventPayloadH (correct data for signature)
//	data := append(preMsgH[:], msgH[:]...)
//
//	// Hash the concatenated data
//	hash := sha256.Sum256(data)
//
//	// Sign the hash
//	sigDER, err := privKey.Sign(rand.Reader, hash[:], nil)
//	require.NoError(t, err)
//
//	r, s, err := proverTypes.ParseDERSignature(sigDER)
//	require.NoError(t, err)
//
//	var circuit BPrNEventProofCircuit
//
//	// Create witness with Wrong EventPayloadH
//	witness := BPrNEventProofCircuit{
//		OriginPayloadH: ToU8Array32(preMsgH[:]),
//		EventPayloadH:  ToU8Array32(wrongMsgH[:]), // Wrong!
//		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
//			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
//			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
//		},
//		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
//			R: emulated.ValueOf[emulated.P256Fr](r),
//			S: emulated.ValueOf[emulated.P256Fr](s),
//		},
//	}
//
//	// Test that the circuit FAILS
//	assert := test.NewAssert(t)
//	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
//	assert.Error(err, "circuit should fail when EventPayloadH is wrong")
//
//	t.Logf("Wrong EventPayloadH - correctly rejected")
//}
//
//func TestBPrNEventProofCircuit_InvalidSignature(t *testing.T) {
//	// Generate P256 key pair
//	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//	require.NoError(t, err)
//
//	// Prepare data
//	preMsgH := sha256.Sum256([]byte("premessage_message"))
//	msgH := sha256.Sum256([]byte("public_message"))
//
//	// Concatenate OriginPayloadH and EventPayloadH
//	data := append(preMsgH[:], msgH[:]...)
//
//	// Hash the concatenated data
//	hash := sha256.Sum256(data)
//
//	// Sign the hash
//	sigDER, err := privKey.Sign(rand.Reader, hash[:], nil)
//	require.NoError(t, err)
//
//	r, s, err := proverTypes.ParseDERSignature(sigDER)
//	require.NoError(t, err)
//
//	// Modify S to make signature invalid
//	invalidS := new(big.Int).Add(s, big.NewInt(1))
//
//	var circuit BPrNEventProofCircuit
//
//	// Create witness with invalid signature
//	witness := BPrNEventProofCircuit{
//		OriginPayloadH: ToU8Array32(preMsgH[:]),
//		EventPayloadH:  ToU8Array32(msgH[:]),
//		Pub: ecdsaCircuit.PublicKey[emulated.P256Fp, emulated.P256Fr]{
//			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
//			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
//		},
//		Sig: ecdsaCircuit.Signature[emulated.P256Fr]{
//			R: emulated.ValueOf[emulated.P256Fr](r),
//			S: emulated.ValueOf[emulated.P256Fr](invalidS), // Invalid!
//		},
//	}
//
//	// Test that the circuit FAILS
//	assert := test.NewAssert(t)
//	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
//	assert.Error(err, "circuit should fail with invalid signature")
//
//	t.Logf("Invalid signature correctly rejected")
//}
//
//func TestBPrNEventProofCircuit_Setup_Groth16(t *testing.T) {
//	rootDir, _ := types2.ProjectRoot()
//	var c BPrNEventProofCircuit
//	_, _, _ = LoadOrSetupCircuit_Groth16(filepath.Join(rootDir, ".build"), &c)
//}
//
//func TestBPrNEventProofCircuit_Setup_Plonk(t *testing.T) {
//	var c BPrNEventProofCircuit
//
//	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &c)
//	require.NoError(t, err)
//
//	t.Logf("Circuit compiled successfully")
//	t.Logf("Number of constraints: %d", ccs.GetNbConstraints())
//	t.Logf("Number of public inputs: %d", ccs.GetNbPublicVariables())
//	t.Logf("Number of secret inputs: %d", ccs.GetNbSecretVariables())
//
//	// Generate proving key and verifying key using PLONK
//	t.Log("Generating SRS (this may take a while)...")
//
//	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
//	require.NoError(t, err)
//
//	t.Log("Generating proving key and verifying key...")
//
//	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
//	require.NoError(t, err)
//
//	t.Logf("Proving key generated successfully")
//	t.Logf("Verifying key generated successfully")
//
//	// Log sizes
//	var pkBuf, vkBuf bytes.Buffer
//	_, err = pk.WriteTo(&pkBuf)
//	require.NoError(t, err)
//	_, err = vk.WriteTo(&vkBuf)
//	require.NoError(t, err)
//
//	t.Logf("Proving key size: %d bytes (%.2f MB)", pkBuf.Len(), float64(pkBuf.Len())/(1024*1024))
//	t.Logf("Verifying key size: %d bytes (%.2f KB)", vkBuf.Len(), float64(vkBuf.Len())/1024)
//}
