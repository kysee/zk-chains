import * as fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';

export function projectRoot(startPath = "."): string {
    let currentPath = path.resolve(startPath);

    console.log("startPath:", startPath);

    while (currentPath !==
    path.parse(currentPath).root) {
        if (fs.existsSync(path.join(currentPath,
            'go.mod'))) {
            console.log("found project root dir:", currentPath)
            return currentPath;
        }
        currentPath = path.dirname(currentPath);
        console.log("next dir:", currentPath)

    }

    throw new Error('not found project root dir');
}

export interface BeaconBlockHeader {
    slot: string;
    proposer_index: string;
    parent_root: string;
    state_root: string;
    body_root: string;
}

export interface ExecutionPayloadHeader {
    parent_hash: string;
    fee_recipient: string;
    state_root: string;
    receipts_root: string;
    logs_bloom: string;
    prev_randao: string;
    block_number: string;
    gas_limit: string;
    gas_used: string;
    timestamp: string;
    extra_data: string;
    base_fee_per_gas: string;
    block_hash: string;
    transactions_root: string;
    withdrawals_root: string;
    blob_gas_used: string;
    excess_blob_gas: string;
}

export interface LightClientHeader {
    beacon: BeaconBlockHeader;
    execution: ExecutionPayloadHeader;
    execution_branch: string[];
}

export interface SyncCommittee {
    aggregate_pubkey: string;
    pubkeys: string[];
}

export interface SyncAggregate {
    sync_committee_bits: string;
    sync_committee_signature: string;
}

export interface LightClientUpdate {
    attested_header: LightClientHeader;
    next_sync_committee: SyncCommittee;
    next_sync_committee_branch: string[];
    finalized_header: LightClientHeader;
    finality_branch: string[];
    sync_aggregate: SyncAggregate;
    signature_slot: string;
}

export interface SyncCommitteeUpdateData {
    data: LightClientUpdate;
    version: string;
}

export function loadSyncCommitteeUpdateData(dataPath:string): SyncCommitteeUpdateData {
    const fileContent = fs.readFileSync(dataPath, 'utf8');
    return JSON.parse(fileContent);
}
//
// export function loadSyncCommittee(dataPath:string): SyncCommittee {
//     const fileContent = fs.readFileSync(dataPath, 'utf8');
//     const jsonData = JSON.parse(fileContent);
//     if(jsonData.data) {
//         return jsonData.data.next_sync_committee;
//     }
//     return jsonData;
// }

/**
 * SyncCommittee의 pubkeys를 바이트로 변환한 다음 SHA256 해시 값을 구한다.
 * @param sc SyncCommittee 객체
 * @returns SHA256 해시 값 (0x prefix가 붙은 hex string)
 */
export function scPubKeysHash(sc: SyncCommittee): string {
    const hasher = createHash('sha256');
    sc.pubkeys.forEach(pubkey => {
        const bytes = hexToBytes(pubkey);
        hasher.update( bytes.slice(32,48) );
    })
    const hash = hasher.digest();
    return '0x' + hash.toString('hex');
}

/**
 * NextSyncCommittee의 pubkeys와 aggregate_pubkey를 바이트로 변환 후 이어붙인다.
 * pubkeys: 512 * 48 bytes = 24576 bytes
 * aggregate_pubkey: 48 bytes
 * 총 24624 bytes
 */
export function syncCommitteeToBytes(sc: SyncCommittee): Uint8Array {
    const pubkeys = sc.pubkeys;
    const aggregatePubkey = sc.aggregate_pubkey;

    if (pubkeys.length !== 512) {
        throw new Error(`Expected 512 pubkeys, got ${pubkeys.length}`);
    }

    // total length: 512 * 48 + 48 = 24624 bytes
    const result = new Uint8Array(512 * 48 + 48);
    let offset = 0;

    // pubkeys 512개를 변환
    pubkeys.forEach((hex, index) => {
        if (typeof hex !== "string") {
            throw new Error(`Pubkey #${index} is not a string`);
        }

        const clean = hex.startsWith("0x") ? hex.slice(2) : hex;

        // 48 bytes = 96 hex chars
        if (clean.length !== 96) {
            throw new Error(`Pubkey #${index} has invalid length: ${clean.length} (expected 96 hex chars)`);
        }

        for (let i = 0; i < clean.length; i += 2) {
            const byteStr = clean.slice(i, i + 2);
            const byte = Number.parseInt(byteStr, 16);
            if (Number.isNaN(byte)) {
                throw new Error(`Pubkey #${index} contains invalid hex: "${byteStr}"`);
            }
            result[offset++] = byte;
        }
    });

    // aggregate_pubkey 변환
    if (typeof aggregatePubkey !== "string") {
        throw new Error("aggregate_pubkey is not a string");
    }

    const cleanAggregate = aggregatePubkey.startsWith("0x") ? aggregatePubkey.slice(2) : aggregatePubkey;

    if (cleanAggregate.length !== 96) {
        throw new Error(`aggregate_pubkey has invalid length: ${cleanAggregate.length} (expected 96 hex chars)`);
    }

    for (let i = 0; i < cleanAggregate.length; i += 2) {
        const byteStr = cleanAggregate.slice(i, i + 2);
        const byte = Number.parseInt(byteStr, 16);
        if (Number.isNaN(byte)) {
            throw new Error(`aggregate_pubkey contains invalid hex: "${byteStr}"`);
        }
        result[offset++] = byte;
    }

    return result;
}

export interface ProofData {
    proof: string[];
    commitments: string[];
    commitmentPok: string[];
}

/**
 * Load proof data from JSON file
 * @param dataPath Path to proof-data.json file
 * @returns ProofData object containing proof, commitments, and commitmentPok
 */
export function loadProofData(dataPath: string): ProofData {
    const fileContent = fs.readFileSync(dataPath, 'utf8');
    const jsonData = JSON.parse(fileContent);

    if (!jsonData.proof || !Array.isArray(jsonData.proof)) {
        throw new Error('Invalid proof-data.json: proof must be an array');
    }

    if (!jsonData.commitments || !Array.isArray(jsonData.commitments)) {
        throw new Error('Invalid proof-data.json: commitments must be an array');
    }

    if (!jsonData.commitmentPok || !Array.isArray(jsonData.commitmentPok)) {
        throw new Error('Invalid proof-data.json: commitmentPok must be an array');
    }

    if (jsonData.proof.length !== 8) {
        throw new Error(`Invalid proof-data.json: proof must have 8 elements, got ${jsonData.proof.length}`);
    }

    if (jsonData.commitments.length !== 2) {
        throw new Error(`Invalid proof-data.json: commitments must have 2 elements, got ${jsonData.commitments.length}`);
    }

    if (jsonData.commitmentPok.length !== 2) {
        throw new Error(`Invalid proof-data.json: commitmentPok must have 2 elements, got ${jsonData.commitmentPok.length}`);
    }

    return {
        proof: jsonData.proof,
        commitments: jsonData.commitments,
        commitmentPok: jsonData.commitmentPok
    };
}



/**
 * Hex string을 Uint8Array로 변환한다.
 * @param hexString 0x prefix가 있을 수도 있고 없을 수도 있는 hex string
 * @returns Uint8Array
 */
export function hexToBytes(hexString: string): Uint8Array {
    const clean = hexString.startsWith("0x") ? hexString.slice(2) : hexString;

    if (clean.length % 2 !== 0) {
        throw new Error(`Invalid hex string length: ${clean.length} (must be even)`);
    }

    const result = new Uint8Array(clean.length / 2);

    for (let i = 0; i < clean.length; i += 2) {
        const byteStr = clean.slice(i, i + 2);
        const byte = Number.parseInt(byteStr, 16);
        if (Number.isNaN(byte)) {
            throw new Error(`Invalid hex string: contains invalid hex "${byteStr}" at position ${i}`);
        }
        result[i / 2] = byte;
    }

    return result;
}