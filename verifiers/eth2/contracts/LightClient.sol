// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "hardhat/console.sol";
import "./ScUpdateVerifier.sol";

contract LightClient {
    uint256 public lastPeriod;
    mapping(uint256 => bytes32) public scPubkeysHashes;
    ScUpdateVerifier public verifier;

    // Beacon chain constants
    uint256 constant SLOTS_PER_EPOCH = 32;
    uint256 constant EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256;

    constructor(uint256 _initialPeriod, bytes32 _initialScPubkeysHash, address _verifierAddress) {
        lastPeriod = _initialPeriod;
        scPubkeysHashes[lastPeriod] = _initialScPubkeysHash;
        verifier = ScUpdateVerifier(_verifierAddress);
    }

    function updateSyncCommittee (
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256 slot,
        bytes calldata nextSc
    ) external {
        // Validate inputs
        require(nextSc.length == 24624, "Invalid nextSc length"); // 513 * 48 bytes

        // Compute and validate period
        uint256 _period = slot / (SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
        require(_period == lastPeriod, "Period must be same");

        // Compute nextSyncCommitteeRoot using SSZ (for proof verification)
        bytes32 nextScRoot = _scRoot(nextSc);

        // Prepare public inputs for the verifier
        // input[0..32] = scPubkeysHash (current sync committee)
        // input[33..64] = NextSyncCommitteeRoot (32 bytes)
        uint256[64] memory input;
        bytes32 currScPubKeyHash = scPubkeysHashes[lastPeriod];

        // input[0] is the current sync committee commitment (syncCommitteeHash)
        for(uint256 i=0; i<32; i++) {
            input[i] = uint256(uint8(currScPubKeyHash[i]));
        }

        // input[1..32] are the 32 bytes of nextScRoot
        for (uint256 i = 0; i < 32; i++) {
            input[i + 32] = uint256(uint8(nextScRoot[i]));
        }

        // Call the verifier with [0,0] for commitments and commitmentPok
        verifier.verifyProof(proof,commitments, commitmentPok, input);

        // If verification succeeds, compute and store hash of nextSc's public keys
        lastPeriod = _period + 1;
        scPubkeysHashes[lastPeriod] = _pubKeysHash(nextSc);
    }

    function _scRoot(bytes memory syncCommitteeData) internal pure returns (bytes32) {
        // SSZ Merkleization for SyncCommittee Container:
        // struct SyncCommittee {
        //     pubkeys: Vector[BLSPubkey, 512]  // 512 * 48 = 24576 bytes
        //     aggregate_pubkey: BLSPubkey      // 48 bytes
        // }
        // Total: 24576 + 48 = 24624 bytes
        // Container HashTreeRoot = hash(pubkeysRoot, aggregatePubkeyRoot)

        require(syncCommitteeData.length == 24624, "Invalid sync committee data length");

        // Part 1: Compute pubkeys root (512 pubkeys, bytes 0-24575)
        bytes32[512] memory leaves;
        for (uint256 i = 0; i < 512; i++) {
            uint256 offset = i * 48;
            bytes32 chunk0;
            bytes32 chunk1;
            assembly {
                chunk0 := mload(add(add(syncCommitteeData, 32), offset))
                let data := mload(add(add(syncCommitteeData, 32), add(offset, 32)))
                chunk1 := and(data, 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000)
            }
            leaves[i] = sha256(abi.encodePacked(chunk0, chunk1));
        }

        // Build Merkle tree from 512 leaves
        bytes32[256] memory level1;
        for (uint256 i = 0; i < 256; i++) {
            level1[i] = sha256(abi.encodePacked(leaves[i * 2], leaves[i * 2 + 1]));
        }
        bytes32[128] memory level2;
        for (uint256 i = 0; i < 128; i++) {
            level2[i] = sha256(abi.encodePacked(level1[i * 2], level1[i * 2 + 1]));
        }
        bytes32[64] memory level3;
        for (uint256 i = 0; i < 64; i++) {
            level3[i] = sha256(abi.encodePacked(level2[i * 2], level2[i * 2 + 1]));
        }
        bytes32[32] memory level4;
        for (uint256 i = 0; i < 32; i++) {
            level4[i] = sha256(abi.encodePacked(level3[i * 2], level3[i * 2 + 1]));
        }
        bytes32[16] memory level5;
        for (uint256 i = 0; i < 16; i++) {
            level5[i] = sha256(abi.encodePacked(level4[i * 2], level4[i * 2 + 1]));
        }
        bytes32[8] memory level6;
        for (uint256 i = 0; i < 8; i++) {
            level6[i] = sha256(abi.encodePacked(level5[i * 2], level5[i * 2 + 1]));
        }
        bytes32[4] memory level7;
        for (uint256 i = 0; i < 4; i++) {
            level7[i] = sha256(abi.encodePacked(level6[i * 2], level6[i * 2 + 1]));
        }
        bytes32[2] memory level8;
        for (uint256 i = 0; i < 2; i++) {
            level8[i] = sha256(abi.encodePacked(level7[i * 2], level7[i * 2 + 1]));
        }
        bytes32 pubkeysRoot = sha256(abi.encodePacked(level8[0], level8[1]));

        // Part 2: Compute aggregate_pubkey root (48 bytes at offset 24576)
        bytes32 aggChunk0;
        bytes32 aggChunk1;
        assembly {
            aggChunk0 := mload(add(add(syncCommitteeData, 32), 24576))
            let data := mload(add(add(syncCommitteeData, 32), 24608))
            aggChunk1 := and(data, 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000)
        }
        bytes32 aggregatePubkeyRoot = sha256(abi.encodePacked(aggChunk0, aggChunk1));

        // Part 3: Container root = hash(pubkeysRoot, aggregatePubkeyRoot)
        return sha256(abi.encodePacked(pubkeysRoot, aggregatePubkeyRoot));
    }

    function _pubKeysHash(bytes calldata pubKeys) internal pure returns (bytes32) {
        require(pubKeys.length >= 512, "pubKeys length must be more than 512");
        uint256 numPubkeys = 512;

        bytes memory allLimbs = new bytes(numPubkeys * 16);
        for (uint256 i = 0; i < numPubkeys; i++) {
            uint256 offset = i * 48; // pubkey's size
            uint256 allLimbsOffset = i * 16;
            assembly {
                let lsb16 := calldataload(add(pubKeys.offset, add(offset, 32))) // [32..48] = 16bytes = 128bits
                lsb16 := shl(128, shr(128, lsb16))

                mstore(add(add(allLimbs, 32), allLimbsOffset), lsb16)
            }
        }
        return sha256(allLimbs);
    }
    // Test function for _pubKeysSha2
    function testPubKeysHash(bytes calldata data) public pure returns (bytes32) {
        return _pubKeysHash(data);
    }

    // Test function for _scRoot
    function testScRoot(bytes calldata syncCommitteeData) public pure returns (bytes32) {
        return _scRoot(syncCommitteeData);
    }
}