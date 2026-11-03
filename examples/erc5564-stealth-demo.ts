/**
 * ERC-5564 Stealth Address Demo
 *
 * This demo shows how to use ERC-5564 compliant stealth addresses
 * for privacy-preserving transactions.
 *
 * What are stealth addresses?
 * - One-time addresses that only the recipient can identify and spend from
 * - Each payment uses a unique, unlinkable address
 * - No communication needed between sender and recipient
 *
 * How to run:
 *   npm run example:erc5564
 *
 * Learn more:
 *   - ERC-5564 Spec: https://eips.ethereum.org/EIPS/eip-5564
 *   - w3pk Docs: https://github.com/w3hc/w3pk/blob/main/docs/ERC5564_STEALTH_ADDRESSES.md
 */

import { createWeb3Passkey } from "../src/index";

async function main() {
  console.log("\n🥷 ERC-5564 Stealth Address Demo\n");
  console.log("=".repeat(60));
  console.log("This demo shows the complete flow:");
  console.log("1. Recipient generates stealth keys");
  console.log("2. Sender generates stealth address");
  console.log("3. Recipient scans announcements");
  console.log("4. View tag optimization demo");
  console.log("5. Privacy demonstration");
  console.log("=".repeat(60));

  // Initialize w3pk with stealth address support
  const w3pk = createWeb3Passkey({
    apiBaseUrl: "https://webauthn.w3hc.org",
    stealthAddresses: {}, // Enable stealth addresses
  });

  // For demo purposes, we'll simulate with a test mnemonic
  // In production, this would come from WebAuthn authentication
  console.log("\n📝 Step 1: Recipient Setup");
  console.log("-".repeat(60));

  // Get recipient's stealth keys
  const recipientKeys = await w3pk.stealth?.getKeys();
  if (!recipientKeys) {
    throw new Error("Stealth addresses not available");
  }

  console.log("✓ Recipient generated their stealth keys");
  console.log(`  Stealth Meta-Address: ${recipientKeys.stealthMetaAddress}`);
  console.log(`  (This is what the recipient shares publicly)`);

  // ============================================================================
  // SENDER SIDE: Generate stealth address
  // ============================================================================

  console.log("\n📤 Step 2: Sender Generates Stealth Address");
  console.log("-".repeat(60));
  console.log("Sender only knows the recipient's stealth meta-address");
  console.log("They generate a one-time address non-interactively:\n");

  const announcement = await w3pk.stealth?.generateStealthAddress();
  if (!announcement) {
    throw new Error("Failed to generate stealth address");
  }

  console.log("✓ Stealth address generated!");
  console.log(`  Send funds to: ${announcement.stealthAddress}`);
  console.log(`  Ephemeral PubKey: ${announcement.ephemeralPublicKey}`);
  console.log(`  View Tag: ${announcement.viewTag}`);
  console.log("\n💡 Sender publishes this announcement on-chain (e.g., in event logs)");
  console.log("   - The stealth address receives the funds");
  console.log("   - Only the recipient can identify and spend from it");

  // ============================================================================
  // RECIPIENT SIDE: Scan and identify stealth payments
  // ============================================================================

  console.log("\n📥 Step 3: Recipient Scans Announcements");
  console.log("-".repeat(60));
  console.log("Recipient monitors on-chain announcements...\n");

  // Simulate scanning an announcement
  const parseResult = await w3pk.stealth?.parseAnnouncement({
    stealthAddress: announcement.stealthAddress,
    ephemeralPublicKey: announcement.ephemeralPublicKey,
    viewTag: announcement.viewTag,
  });

  if (!parseResult?.isForUser) {
    console.log("❌ This announcement is not for the recipient");
  } else {
    console.log("✅ Found a stealth payment!");
    console.log(`  Stealth Address: ${parseResult.stealthAddress}`);

    // w3pk signs from the stealth address; the app broadcasts with its own RPC
    const signedTx = await w3pk.stealth?.signTransaction(announcement, {
      to: "0x0000000000000000000000000000000000000001",
      value: 1000000000000000n,
      chainId: 11155111,
      nonce: 0,
      gasLimit: 21000n,
      maxFeePerGas: 2000000000n,
      maxPriorityFeePerGas: 1000000000n,
    });
    console.log(`  Signed Tx: ${signedTx?.slice(0, 20)}...`);
    console.log("\n💰 Recipient can now broadcast the signed transaction to spend the funds");
  }

  // ============================================================================
  // EFFICIENCY: View Tag Optimization
  // ============================================================================

  console.log("\n⚡ Step 4: View Tag Optimization Demo");
  console.log("-".repeat(60));

  // Simulate 100 announcements for different recipients
  const announcements = [];

  console.log("Generating 100 announcements for different recipients...");

  for (let i = 0; i < 99; i++) {
    // Generate announcements for other recipients
    // In reality, these would be from on-chain events
    const otherAnnouncement = await w3pk.stealth?.generateStealthAddress();
    if (otherAnnouncement) {
      announcements.push(otherAnnouncement);
    }
  }

  // Add one announcement for our recipient
  const myAnnouncement = await w3pk.stealth?.generateStealthAddress();
  if (myAnnouncement) {
    announcements.push(myAnnouncement);
  }

  console.log(`\n✓ Generated ${announcements.length} announcements`);
  console.log("Scanning with view tag optimization...\n");

  const startTime = Date.now();
  const myPayments = await w3pk.stealth?.scanAnnouncements(
    announcements.map((a) => ({
      stealthAddress: a.stealthAddress,
      ephemeralPublicKey: a.ephemeralPublicKey,
      viewTag: a.viewTag,
    }))
  );
  const scanTime = Date.now() - startTime;

  console.log(`✓ Scan completed in ${scanTime}ms`);
  console.log(`✓ Found ${myPayments?.length || 0} payment(s) for recipient`);
  console.log(
    `\n💡 View tags allow skipping ~99% of announcements after just 1 hash`
  );
  console.log("   This makes scanning extremely efficient!");

  // ============================================================================
  // PRIVACY DEMONSTRATION
  // ============================================================================

  console.log("\n🔒 Step 5: Privacy Demonstration");
  console.log("-".repeat(60));

  const payment1 = await w3pk.stealth?.generateStealthAddress();
  const payment2 = await w3pk.stealth?.generateStealthAddress();
  const payment3 = await w3pk.stealth?.generateStealthAddress();

  console.log("Generated 3 stealth addresses for the same recipient:\n");
  console.log(`  Payment 1: ${payment1?.stealthAddress}`);
  console.log(`  Payment 2: ${payment2?.stealthAddress}`);
  console.log(`  Payment 3: ${payment3?.stealthAddress}`);

  console.log("\n✅ Privacy Benefits:");
  console.log("   - Each address is unique and unlinkable");
  console.log("   - External observers cannot connect them to the same recipient");
  console.log("   - Only the recipient can identify which payments belong to them");
  console.log("   - No interaction required between sender and recipient");

  // ============================================================================
  // SUMMARY
  // ============================================================================

  console.log("\n" + "=".repeat(60));
  console.log("📊 ERC-5564 Summary");
  console.log("=".repeat(60));
  console.log("\n🎯 Standard Compliance:");
  console.log("   ✓ ERC-5564 compliant stealth addresses");
  console.log("   ✓ SECP256k1 scheme with ECDH");
  console.log("   ✓ Compressed public keys (33 bytes each)");
  console.log("   ✓ View tags for efficient scanning");
  console.log("   ✓ Non-interactive address generation");

  console.log("\n⚙️  How It Works:");
  console.log("   1. Recipient generates stealth keys and shares meta-address");
  console.log("   2. Sender generates ephemeral keypair");
  console.log("   3. Sender computes shared secret via ECDH");
  console.log("   4. Stealth address = spending_pubkey + hash(shared_secret) × G");
  console.log("   5. Announcement published on-chain with view tag");
  console.log("   6. Recipient scans using view tag (255/256 skip rate)");
  console.log("   7. Recipient computes stealth private key to spend funds");

  console.log("\n🚀 Use Cases:");
  console.log("   - Private donations and payments");
  console.log("   - Anonymous airdrops");
  console.log("   - Privacy-preserving DeFi");
  console.log("   - Unlinkable transaction chains");
  console.log("   - Dark pool trading");

  console.log("\n" + "=".repeat(60));
  console.log("✨ Demo complete!");
  console.log("=".repeat(60) + "\n");
}

// Run the demo
main().catch((error) => {
  console.error("Error:", error);
  process.exit(1);
});
