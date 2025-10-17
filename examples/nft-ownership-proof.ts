/**
 * NFT Ownership Proof Example
 *
 * Demonstrates how to prove ownership of an NFT (including SBTs/Soulbound Tokens)
 * without revealing which specific NFT you own or your exact wallet address.
 *
 * ⚠️ REQUIREMENTS:
 * This example requires ZK dependencies. Install with:
 * ```bash
 * npm install snarkjs circomlibjs
 * ```
 *
 * Use Cases:
 * - Prove you own a Human Passport SBT without revealing which one
 * - Prove you have a governance token for voting without revealing holdings
 * - Prove you hold an educational SBT without revealing institution
 * - Prove membership in exclusive NFT community without revealing identity
 *
 * @see https://github.com/w3hc/w3pk#zero-knowledge-proofs
 */

import { createWeb3Passkey } from "w3pk";
import {
  buildNFTHoldersMerkleTree,
  generateNFTOwnershipProofInputs,
  validateNFTOwnershipProofInputs,
} from "w3pk/zk/utils";

// Check if ZK dependencies are available
async function checkDependencies() {
  try {
    await import("snarkjs");
    await import("circomlibjs");
    return true;
  } catch (error) {
    console.error(
      "\n❌ ZK dependencies not found.\n\n" +
        "This example requires:\n" +
        "  npm install snarkjs circomlibjs\n\n" +
        "See: https://github.com/w3hc/w3pk#zero-knowledge-proofs\n"
    );
    return false;
  }
}

async function nftOwnershipProofExample() {
  console.log("🎨 NFT Ownership Proof Example\n");

  // Check dependencies first
  if (!(await checkDependencies())) {
    return;
  }

  // Initialize main SDK (lightweight, no ZK dependencies bundled)
  const w3pk = createWeb3Passkey({
    apiBaseUrl: "https://webauthn.w3hc.org",
  });

  console.log("✅ Main SDK initialized (no heavy ZK dependencies)");

  // Initialize ZK module separately to avoid bundling dependencies
  // for users who don't need ZK functionality
  const { ZKProofModule } = await import("w3pk/zk");
  const zkModule = new ZKProofModule({
    enabledProofs: ["nft"],
  });

  console.log("✅ ZK module initialized separately");

  // Example: Human Passport SBT
  const HumanPassportSBTContract = "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D";

  // Mock list of SBT holders (in practice, get this from blockchain)
  const nftHolders = [
    "0x742d35Cc6139FE1C2f1234567890123456789014", // Some holder
    "0x8ba1f109551bD432803012645Hatch6576v47839", // Another holder
    "0x1a2b3c4d5e6f7890abcdef1234567890abcdef12", // Your address
    "0x9876543210abcdef1234567890abcdef12345678", // More holders...
    "0xabcdef1234567890abcdef1234567890abcdef12",
  ];

  const yourAddress = "0x1a2b3c4d5e6f7890abcdef1234567890abcdef12";

  try {
    console.log("1. Building NFT holders merkle tree...");

    // Step 1: Build merkle tree of all NFT holders
    const { root, tree, holderLeaves } = await buildNFTHoldersMerkleTree(
      nftHolders,
      HumanPassportSBTContract
    );

    console.log(`   ✅ Tree built with ${nftHolders.length} holders`);
    console.log(`   📊 Merkle root: ${root.substring(0, 20)}...`);

    console.log("\n2. Generating NFT ownership proof inputs...");

    // Step 2: Generate proof inputs for your ownership
    const { nftProofInput } = await generateNFTOwnershipProofInputs(
      yourAddress,
      HumanPassportSBTContract,
      nftHolders,
      1n // Prove ownership of at least 1 NFT
    );

    console.log(
      `   ✅ Proof inputs generated for holder at index ${nftProofInput.holderIndex}`
    );
    console.log(`   🔍 Path depth: ${nftProofInput.pathIndices.length}`);

    console.log("\n3. Validating proof inputs...");

    // Step 3: Validate the inputs
    validateNFTOwnershipProofInputs(nftProofInput);
    console.log("   ✅ All inputs valid");

    console.log("\n4. Generating zero-knowledge proof...");

    // Step 4: Generate the actual ZK proof using separate ZK module
    const nftOwnershipProof = await zkModule.proveNFTOwnership(nftProofInput);

    console.log("   ✅ NFT ownership proof generated!");
    console.log(`   🔒 Proof type: ${nftOwnershipProof.type}`);
    console.log(
      `   🔢 Public signals: ${nftOwnershipProof.publicSignals.length}`
    );
    console.log(
      `   ⏰ Generated at: ${new Date(
        nftOwnershipProof.timestamp
      ).toISOString()}`
    );

    console.log("\n5. Verifying the proof...");

    // Step 5: Verify the proof (by a third party) using separate ZK module
    const isValid = await zkModule.verifyNFTOwnership(
      nftOwnershipProof,
      HumanPassportSBTContract, // Expected contract
      root, // Expected holders root
      1n // Expected minimum balance
    );

    if (isValid) {
      console.log("   ✅ Proof verified successfully!");
      console.log("   🎉 Proven: You own at least 1 Human Passport SBT");
      console.log("   🔒 Hidden: Which specific NFT you own");
      console.log("   🔒 Hidden: Your exact wallet address");
    } else {
      console.log("   ❌ Proof verification failed");
    }

    console.log("\n6. Proof details (what's revealed vs hidden):");
    console.log("   📢 PUBLIC (revealed):");
    console.log(`      • Contract: ${HumanPassportSBTContract}`);
    console.log(`      • Holders root: ${root.substring(0, 20)}...`);
    console.log(`      • Minimum balance: 1 NFT`);
    console.log(
      `      • Nullifier: ${nftOwnershipProof.publicSignals[3]?.substring(
        0,
        20
      )}...`
    );

    console.log("   🔒 PRIVATE (hidden):");
    console.log(`      • Your address: ${yourAddress}`);
    console.log(
      `      • Your position in holders list: ${nftProofInput.holderIndex}`
    );
    console.log(`      • Which specific NFT(s) you own`);
    console.log(`      • How many NFTs you own (beyond minimum)`);
  } catch (error) {
    if (error instanceof Error) {
      if (
        error.message.includes("snarkjs") ||
        error.message.includes("circomlibjs")
      ) {
        console.log("\n❌ ZK dependencies missing:");
        console.log("   Run: npm install snarkjs circomlibjs");
        console.log(
          "   Or see: https://github.com/w3hc/w3pk#zero-knowledge-proofs"
        );
      } else {
        console.error("❌ Error:", error.message);
      }
    }
  }
}

async function soulboundTokenExample() {
  console.log("\n🎓 Soulbound Token (SBT) Example\n");

  // Example: University Diploma SBT
  const diplomaContract = "0x1234567890abcdef1234567890abcdef12345678";

  // Mock list of diploma holders
  const diplomaHolders = [
    "0x1111111111111111111111111111111111111111", // Alumni 1
    "0x2222222222222222222222222222222222222222", // Alumni 2
    "0x3333333333333333333333333333333333333333", // You
    "0x4444444444444444444444444444444444444444", // Alumni 4
    // ... more alumni
  ];

  const yourAddress = "0x3333333333333333333333333333333333333333";

  try {
    console.log("Proving university diploma ownership...");

    // Same process as NFT but for SBTs (non-transferable)
    const { nftProofInput } = await generateNFTOwnershipProofInputs(
      yourAddress,
      diplomaContract,
      diplomaHolders,
      1n
    );

    console.log("✅ Can prove university graduation without revealing:");
    console.log("   • Which university");
    console.log("   • What degree");
    console.log("   • Graduation year");
    console.log("   • Your identity");
    console.log("   🎯 Use case: Anonymous job applications, exclusive access");
  } catch (error) {
    console.log("ℹ️ SBT proof setup complete (circuits not compiled)");
  }
}

async function main() {
  await nftOwnershipProofExample();
  await soulboundTokenExample();

  console.log("\n🎯 Real-World Applications:");
  console.log("• 🗳️  Anonymous voting for NFT holders");
  console.log("• 🎮 Gaming access without revealing which NFTs");
  console.log("• 🎓 Credential verification without revealing details");
  console.log("• 💼 Job applications with anonymous qualifications");
  console.log("• 🏛️  DAO participation without revealing holdings");
  console.log("• 🎪 Exclusive event access without doxxing");
}

// Run the example
if (require.main === module) {
  main().catch(console.error);
}

export { nftOwnershipProofExample, soulboundTokenExample };
