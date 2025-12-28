import { ethers, NonceManager } from "ethers";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import {
	loadProofData,
	loadSyncCommitteeUpdateData,
	projectRoot, scPubKeysHash,
	syncCommitteeToBytes
} from "./utils.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create provider and wallet

const rpcUrl = "http://127.0.0.1:8545/";
const privateKey = "0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e";
const provider = new ethers.JsonRpcProvider(rpcUrl);
const wallet = new ethers.Wallet(privateKey, provider);
const managedWallet = new NonceManager(wallet);

async function deploy() {
	console.log("Network URL:", rpcUrl);
	console.log("Using account:", wallet.address);

	// Load contract artifacts
	const scUpdateVerifierArtifact = JSON.parse(
        fs.readFileSync(
          path.join(__dirname, "../artifacts/contracts/ScUpdateVerifier.sol/ScUpdateVerifier.json"),
          "utf8"
        )
	);

	const lightClientArtifact = JSON.parse(
        fs.readFileSync(
          path.join(__dirname, "../artifacts/contracts/LightClient.sol/LightClient.json"),
          "utf8"
	    )
	);

	// Deploy ScUpdateVerifier
	console.log("\n=== Deploying ScUpdateVerifier ===");
	const ScUpdateVerifierFactory = new ethers.ContractFactory(
	scUpdateVerifierArtifact.abi,
	scUpdateVerifierArtifact.bytecode,
	  managedWallet
	);
	const scUpdateVerifier = await ScUpdateVerifierFactory.deploy();
	await scUpdateVerifier.waitForDeployment();
	const scUpdateVerifierAddress = await scUpdateVerifier.getAddress();
	console.log("ScUpdateVerifier deployed to:", scUpdateVerifierAddress);



	// Deploy LightClient
	const scUpdate0 = loadSyncCommitteeUpdateData(`${projectRoot()}/../data/sc-update-1104.json`);
	const initialPeriod = 1n + BigInt(scUpdate0.data.attested_header.beacon.slot) / 8192n;
	//expected "0x8bd26c003d619dc6aa13e4c7b31d01910a87f43da84070e6cbdd4d45a91da3f3";
	const initialScPubkeysHash = scPubKeysHash(scUpdate0.data.next_sync_committee);

	console.log("\n=== Deploying LightClient ===");
	console.log("Initial period:", initialPeriod);
	console.log("Initial scPubkeysHash:", initialScPubkeysHash);
	console.log("ScUpdateVerifier address:", scUpdateVerifierAddress);

	const LightClientFactory = new ethers.ContractFactory(
		lightClientArtifact.abi,
		lightClientArtifact.bytecode,
		managedWallet
	);
	const lightClient0: any = await LightClientFactory.deploy(
		initialPeriod,
		initialScPubkeysHash,
		scUpdateVerifierAddress
	);
	await lightClient0.waitForDeployment();
	const lightClientAddress = await lightClient0.getAddress();
	console.log("LightClient deployed to:", lightClientAddress);

    return [lightClientAddress, scUpdateVerifierAddress];
}

async function testLightClientUpdate(lightClientAddress: string) {
    const lightClientArtifact = JSON.parse(
        fs.readFileSync(
            path.join(__dirname, "../artifacts/contracts/LightClient.sol/LightClient.json"),
            "utf8"
        )
    );
    const lightClient = new ethers.Contract(lightClientAddress, lightClientArtifact.abi, managedWallet);
    // Verify deployment
    console.log("\n=== Verifying LightClient Deployment ===");
    const period = await lightClient.lastPeriod();
    const scPubkeysHash = await lightClient.scPubkeysHashes(period);
    const verifierAddress = await lightClient.verifier();

    console.log("Stored period:", period);
    console.log("Stored scPubkeysHash:", scPubkeysHash);
    console.log("Stored verifier address:", verifierAddress);

    // Test testScRoot
    const scUpdate = loadSyncCommitteeUpdateData(`${projectRoot()}/../data/sc-update-1105.json`);
    const slot = scUpdate.data.attested_header.beacon.slot;
    const nextSc = scUpdate.data.next_sync_committee;
    const szNextSc = syncCommitteeToBytes(nextSc);
    console.log("szNextSc.pubkes (+aggreagte):", szNextSc.length / 48);
    try {
        const estimatedGas = await lightClient.testScRoot.estimateGas(szNextSc, {gasLimit: 30000000});
        console.log("testScRoot - Estimated gas needed:", estimatedGas.toString());
        console.log("In millions:", (Number(estimatedGas) / 1_000_000).toFixed(2), "M");
    } catch (err) {
        console.error("estimateGas failed:", err);
        process.exit(0);
    }

    const nextScRoot = await lightClient.testScRoot(szNextSc);
    console.log("testScRoot result:", nextScRoot);

    // Test updateSyncCommittee
    const proofData = loadProofData(`${projectRoot()}/../data/proof-data.json`)
    try {
        const estimatedGas = await lightClient.updateSyncCommittee.estimateGas(
            proofData.proof, proofData.commitments, proofData.commitmentPok,
            slot, szNextSc,
            {gasLimit: 30000000});
        console.log("updateSyncCommittee - Estimated gas needed:", estimatedGas.toString());
    } catch (err) {
        console.error("estimateGas failed:", err);
        process.exit(0);
    }

    const tx = await lightClient.updateSyncCommittee(
        proofData.proof, proofData.commitments, proofData.commitmentPok,
        slot, szNextSc,
        {gasLimit: 30000000});
    const receipt = await tx.wait();
    console.log("typeof gasUsed:", typeof receipt.gasUsed);
    console.log("updateSyncCommittee - gasUsed:", receipt.gasUsed,`(${Number(receipt.gasUsed) / 1_000_000}M)`);
    console.log("updateSyncCommittee - fee (ETH):", ethers.formatEther(receipt.gasUsed * BigInt(48e9)));

    const newPeriod = await lightClient.lastPeriod();
    const newScPubkeysHash = await lightClient.scPubkeysHashes(newPeriod);
    console.log("Stored newPeriod:", newPeriod);
    console.log("Stored newScPubkeysHash:", newScPubkeysHash);
    console.log("\n=== Deployment Complete ===");
}


deploy()
    .then(([lightClient, scUpdateVerifier]) => {
        testLightClientUpdate(lightClient);
    })
    .catch((err) => {
        console.error(err);
        process.exit(1);
    });
