/**
 * Zero-Knowledge Proof Demo Application
 * Demonstrates privacy-preserving authentication and verification
 */

import { createWeb3Passkey } from "w3pk";
import {
  buildMerkleTree,
  generateMerkleProof,
  generateBlinding,
} from "w3pk/zk/utils";

async function main() {
  console.log("=== w3pk Zero-Knowledge Proof Demo ===\n");

  // Initialize SDK with ZK proofs enabled
  const w3pk = createWeb3Passkey({
    apiBaseUrl: "https://webauthn.w3hc.org",
    zkProofs: {
      enabledProofs: ["membership", "threshold", "range"],
    },
  });

  const zk = w3pk.zk;
  if (!zk) {
    console.error("ZK proofs not available");
    return;
  }

  // ==========================================
  // Demo 1: Anonymous Membership Proof
  // ==========================================
  console.log("📋 Demo 1: Anonymous Membership Proof");
  console.log(
    "Scenario: Prove you're a verified user without revealing identity\n"
  );

  const verifiedUsers = [
    "0x1234567890123456789012345678901234567890",
    "0x2345678901234567890123456789012345678901",
    "0x3456789012345678901234567890123456789012",
    "0x4567890123456789012345678901234567890123",
  ];

  console.log(`Verified user set: ${verifiedUsers.length} members`);

  // You are user at index 2
  const myIndex = 2;
  console.log(`Your position (private): ${myIndex}`);

  // Build merkle tree
  const leaves = verifiedUsers.map((addr) => BigInt(addr).toString());
  const { root, tree } = await buildMerkleTree(leaves);
  console.log(`Merkle root (public): ${root.slice(0, 20)}...`);

  // Generate merkle proof
  const { pathIndices, pathElements } = generateMerkleProof(tree, myIndex);

  // Create ZK proof
  console.log("\nGenerating membership proof...");
  const membershipProof = await zk.proveMembership({
    value: leaves[myIndex],
    pathIndices,
    pathElements,
    root,
  });
  console.log("✓ Proof generated");

  // Verify proof
  const isMember = await zk.verifyMembership(membershipProof, root);
  console.log(`✓ Verification result: ${isMember}`);
  console.log("→ Proved membership without revealing which user!\n");

  // ==========================================
  // Demo 2: Private Balance Threshold
  // ==========================================
  console.log("💰 Demo 2: Private Balance Threshold Proof");
  console.log("Scenario: Prove balance > $1000 without revealing amount\n");

  const actualBalance = 5000n;
  const threshold = 1000n;

  console.log(`Your balance (private): ${actualBalance}`);
  console.log(`Required threshold (public): ${threshold}`);

  const blinding = generateBlinding();
  const commitment = await zk.createCommitment(actualBalance, blinding);
  console.log(`Commitment (public): ${commitment.slice(0, 20)}...`);

  console.log("\nGenerating threshold proof...");
  const thresholdProof = await zk.proveThreshold({
    value: actualBalance,
    blinding,
    threshold,
    commitment,
  });
  console.log("✓ Proof generated");

  const meetsThreshold = await zk.verifyThreshold(
    thresholdProof,
    commitment,
    threshold
  );
  console.log(`✓ Verification result: ${meetsThreshold}`);
  console.log("→ Proved balance > $1000 without revealing $5000!\n");

  // ==========================================
  // Demo 3: Age Range Verification
  // ==========================================
  console.log("🎂 Demo 3: Age Range Proof");
  console.log("Scenario: Prove age 18-65 without revealing exact age\n");

  const actualAge = 25n;
  const minAge = 18n;
  const maxAge = 65n;

  console.log(`Your age (private): ${actualAge}`);
  console.log(`Required range (public): ${minAge}-${maxAge}`);

  const ageBlinding = generateBlinding();
  const ageCommitment = await zk.createCommitment(actualAge, ageBlinding);
  console.log(`Commitment (public): ${ageCommitment.slice(0, 20)}...`);

  console.log("\nGenerating range proof...");
  const rangeProof = await zk.proveRange({
    value: actualAge,
    blinding: ageBlinding,
    min: minAge,
    max: maxAge,
    commitment: ageCommitment,
  });
  console.log("✓ Proof generated");

  const inRange = await zk.verifyRange(
    rangeProof,
    ageCommitment,
    minAge,
    maxAge
  );
  console.log(`✓ Verification result: ${inRange}`);
  console.log("→ Proved age in range without revealing 25!\n");

  // ==========================================
  // Demo 4: Batch Verification
  // ==========================================
  console.log("⚡ Demo 4: Batch Proof Verification");
  console.log("Scenario: Verify multiple proofs efficiently\n");

  console.log("Verifying 3 proofs in batch...");
  const results = await zk.verifyBatch([
    membershipProof,
    thresholdProof,
    rangeProof,
  ]);

  results.forEach((result, i) => {
    const proofTypes = ["membership", "threshold", "range"];
    console.log(`  ${i + 1}. ${proofTypes[i]}: ${result.valid ? "✓" : "✗"}`);
  });
  console.log("→ All proofs verified efficiently!\n");

  // ==========================================
  // Demo 5: Real-World Use Cases
  // ==========================================
  console.log("🌍 Demo 5: Real-World Use Cases\n");

  // Use Case 1: Anonymous Voting
  console.log("1. Anonymous Voting");
  console.log("   - Prove you're an eligible voter");
  console.log("   - Cast vote without revealing identity");
  console.log("   - Prevent double voting with nullifiers\n");

  // Use Case 2: Private Credit Scoring
  console.log("2. Private Credit Scoring");
  console.log("   - Prove credit score > 700");
  console.log("   - Get loan approval without revealing exact score");
  console.log("   - Protect financial privacy\n");

  // Use Case 3: Token Gating
  console.log("3. Token Gating");
  console.log("   - Prove token holdings > minimum");
  console.log("   - Access exclusive content");
  console.log("   - Don't reveal wallet balance\n");

  // Use Case 4: Age Verification
  console.log("4. Age Verification");
  console.log("   - Prove age >= 18 for access");
  console.log("   - No need to share birthdate");
  console.log("   - Compliance without surveillance\n");

  // Use Case 5: Privacy-Preserving KYC
  console.log("5. Privacy-Preserving KYC");
  console.log("   - Prove KYC verification");
  console.log("   - Don't reveal personal documents");
  console.log("   - Reusable across platforms\n");

  // ==========================================
  // Summary
  // ==========================================
  console.log("=== Summary ===");
  console.log("✓ Generated 3 different types of ZK proofs");
  console.log("✓ Verified all proofs successfully");
  console.log("✓ Protected private information throughout");
  console.log("\nZK proofs enable:");
  console.log("  • Privacy by default");
  console.log("  • Selective disclosure");
  console.log("  • Cryptographic guarantees");
  console.log("  • Compliance without surveillance");
}

// Run demo
main().catch(console.error);
