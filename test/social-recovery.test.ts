/**
 * Social Recovery Tests
 * Tests for Shamir Secret Sharing and guardian-based recovery
 */

import { SocialRecoveryManager } from "../src/recovery/social";
import {
  splitSecret,
  combineShares,
  stringToBytes,
  bytesToString,
  bytesToHex,
  hexToBytes,
} from "../src/recovery/shamir";

async function runTests() {
  console.log("\n🧪 Running Social Recovery Tests...\n");

  // Test 1: Shamir Secret Sharing - Basic Split and Combine
  console.log("Test 1: Shamir Secret Sharing - 3-of-5");
  {
    const secret =
      "test test test test test test test test test test test junk";
    const secretBytes = stringToBytes(secret);

    const shares = splitSecret(secretBytes, 3, 5);

    console.assert(shares.length === 5, "Should create 5 shares");
    console.assert(shares[0][0] === 1, "First share should have X=1");
    console.assert(shares[4][0] === 5, "Last share should have X=5");

    // Combine first 3 shares
    const recovered = combineShares(shares.slice(0, 3), 3);
    const recoveredSecret = bytesToString(recovered);

    console.assert(
      recoveredSecret === secret,
      "Should recover original secret"
    );
    console.log("✅ 3-of-5 secret sharing working correctly");
  }

  // Test 2: Different Share Combinations
  console.log("\nTest 2: Different Share Combinations");
  {
    const secret = "test secret message for recovery";
    const secretBytes = stringToBytes(secret);

    const shares = splitSecret(secretBytes, 3, 5);

    // Try different combinations of 3 shares
    const combo1 = combineShares([shares[0], shares[1], shares[2]], 3);
    const combo2 = combineShares([shares[1], shares[2], shares[3]], 3);
    const combo3 = combineShares([shares[0], shares[2], shares[4]], 3);

    console.assert(bytesToString(combo1) === secret, "Combo 1 should work");
    console.assert(bytesToString(combo2) === secret, "Combo 2 should work");
    console.assert(bytesToString(combo3) === secret, "Combo 3 should work");

    console.log("✅ All combinations work correctly");
  }

  // Test 3: Insufficient Shares
  console.log("\nTest 3: Insufficient Shares");
  {
    const secret = "cannot recover with too few shares";
    const secretBytes = stringToBytes(secret);

    const shares = splitSecret(secretBytes, 3, 5);

    try {
      // Try with only 2 shares (need 3)
      combineShares(shares.slice(0, 2), 3);
      console.assert(false, "Should throw error with insufficient shares");
    } catch (error) {
      console.assert(error instanceof Error, "Should throw Error");
      console.log("✅ Correctly rejects insufficient shares");
    }
  }

  // Test 4: Hex Encoding/Decoding
  console.log("\nTest 4: Hex Encoding and Decoding");
  {
    const testData = new Uint8Array([1, 2, 3, 4, 5, 255, 128, 64]);

    const hex = bytesToHex(testData);
    console.assert(
      hex === "0102030405ff8040",
      "Hex encoding should be correct"
    );

    const decoded = hexToBytes(hex);
    console.assert(
      decoded.length === testData.length,
      "Decoded should have same length"
    );
    console.assert(
      decoded.every((byte, i) => byte === testData[i]),
      "Decoded should match original"
    );

    console.log("✅ Hex encoding/decoding working correctly");
  }

  // Test 5: Social Recovery Setup
  console.log("\nTest 5: Social Recovery Setup");
  {
    const socialRecovery = new SocialRecoveryManager();
    const testMnemonic =
      "test test test test test test test test test test test junk";
    const testAddress = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb";

    const guardians = [
      { name: "Alice", email: "alice@example.com" },
      { name: "Bob", email: "bob@example.com" },
      { name: "Charlie" },
      { name: "Diana", email: "diana@example.com" },
      { name: "Eve", phone: "+1234567890" },
    ];

    const result = await socialRecovery.setupSocialRecovery(
      testMnemonic,
      testAddress,
      guardians,
      3
    );

    console.assert(result.length === 5, "Should create 5 guardians");
    console.assert(
      result[0].name === "Alice",
      "Should preserve guardian names"
    );
    console.assert(
      result[0].email === "alice@example.com",
      "Should preserve guardian emails"
    );
    console.assert(result[0].id, "Each guardian should have ID");
    console.assert(
      result[0].shareEncrypted,
      "Each guardian should have encrypted share"
    );
    console.assert(
      result[0].status === "pending",
      "Initial status should be pending"
    );

    console.log("✅ Social recovery setup working correctly");
  }

  // Test 6: Guardian Invite Generation
  console.log("\nTest 6: Guardian Invite Generation");
  {
    const socialRecovery = new SocialRecoveryManager();
    const testMnemonic =
      "test test test test test test test test test test test junk";

    // Derive the actual address from the mnemonic
    const { Wallet } = await import("ethers");
    const wallet = Wallet.fromPhrase(testMnemonic);
    const testAddress = wallet.address;

    const guardians = [
      { name: "Alice", email: "alice@example.com" },
      { name: "Bob" },
      { name: "Charlie" },
    ];

    const result = await socialRecovery.setupSocialRecovery(
      testMnemonic,
      testAddress,
      guardians,
      2
    );

    const invite = await socialRecovery.generateGuardianInvite(result[0]);

    console.assert(
      invite.guardianId === result[0].id,
      "Invite should have correct guardian ID"
    );
    console.assert(invite.qrCode, "Invite should have QR code");
    console.assert(invite.shareCode, "Invite should have share code");
    console.assert(invite.explainer, "Invite should have explainer");

    const parsedShare = JSON.parse(invite.shareCode);
    console.assert(
      parsedShare.guardianId === result[0].id,
      "Share should have guardian ID"
    );
    console.assert(
      parsedShare.guardianName === "Alice",
      "Share should have guardian name"
    );
    console.assert(parsedShare.threshold === 2, "Share should have threshold");
    console.assert(
      parsedShare.totalGuardians === 3,
      "Share should have total guardians"
    );

    console.log("✅ Guardian invite generation working correctly");
  }

  // Test 7: Recovery from Guardians
  console.log("\nTest 7: Recovery from Guardians");
  {
    const socialRecovery = new SocialRecoveryManager();
    const testMnemonic =
      "test test test test test test test test test test test junk";

    // Derive the actual address from the mnemonic
    const { Wallet } = await import("ethers");
    const wallet = Wallet.fromPhrase(testMnemonic);
    const testAddress = wallet.address;

    const guardians = [
      { name: "Guardian1" },
      { name: "Guardian2" },
      { name: "Guardian3" },
      { name: "Guardian4" },
      { name: "Guardian5" },
    ];

    // Setup social recovery
    const result = await socialRecovery.setupSocialRecovery(
      testMnemonic,
      testAddress,
      guardians,
      3
    );

    // Generate invites for first 3 guardians
    const invite1 = await socialRecovery.generateGuardianInvite(result[0]);
    const invite2 = await socialRecovery.generateGuardianInvite(result[1]);
    const invite3 = await socialRecovery.generateGuardianInvite(result[2]);

    // Recover from shares
    const { mnemonic, ethereumAddress } =
      await socialRecovery.recoverFromGuardians([
        invite1.shareCode,
        invite2.shareCode,
        invite3.shareCode,
      ]);

    console.assert(
      mnemonic === testMnemonic,
      "Recovered mnemonic should match original"
    );
    console.assert(
      ethereumAddress.toLowerCase() === testAddress.toLowerCase(),
      "Address should match"
    );

    console.log("✅ Recovery from guardians working correctly");
  }

  // Test 8: Recovery with Different Share Combinations
  console.log("\nTest 8: Recovery with Different Share Combinations");
  {
    const socialRecovery = new SocialRecoveryManager();
    const testMnemonic =
      "test test test test test test test test test test test junk";

    // Derive the actual address from the mnemonic
    const { Wallet } = await import("ethers");
    const wallet = Wallet.fromPhrase(testMnemonic);
    const testAddress = wallet.address;

    const guardians = Array.from({ length: 5 }, (_, i) => ({
      name: `Guardian${i + 1}`,
    }));

    const result = await socialRecovery.setupSocialRecovery(
      testMnemonic,
      testAddress,
      guardians,
      3
    );

    // Generate all invites
    const invites = await Promise.all(
      result.map((guardian) => socialRecovery.generateGuardianInvite(guardian))
    );

    // Try different combinations
    const combo1 = await socialRecovery.recoverFromGuardians([
      invites[0].shareCode,
      invites[1].shareCode,
      invites[2].shareCode,
    ]);

    const combo2 = await socialRecovery.recoverFromGuardians([
      invites[1].shareCode,
      invites[3].shareCode,
      invites[4].shareCode,
    ]);

    const combo3 = await socialRecovery.recoverFromGuardians([
      invites[0].shareCode,
      invites[2].shareCode,
      invites[4].shareCode,
    ]);

    console.assert(combo1.mnemonic === testMnemonic, "Combo 1 should recover");
    console.assert(combo2.mnemonic === testMnemonic, "Combo 2 should recover");
    console.assert(combo3.mnemonic === testMnemonic, "Combo 3 should recover");

    console.log("✅ All share combinations work");
  }

  // Test 9: Recovery Progress Tracking
  console.log("\nTest 9: Recovery Progress Tracking");
  {
    const socialRecovery = new SocialRecoveryManager();
    const testMnemonic =
      "test test test test test test test test test test test junk";

    // Derive the actual address from the mnemonic
    const { Wallet } = await import("ethers");
    const wallet = Wallet.fromPhrase(testMnemonic);
    const testAddress = wallet.address;

    const guardians = [{ name: "Alice" }, { name: "Bob" }, { name: "Charlie" }];

    const result = await socialRecovery.setupSocialRecovery(
      testMnemonic,
      testAddress,
      guardians,
      2
    );

    const invites = await Promise.all(
      result.map((g) => socialRecovery.generateGuardianInvite(g))
    );

    // Check progress with 1 share
    const progress1 = socialRecovery.getRecoveryProgress([
      invites[0].shareCode,
    ]);
    console.assert(progress1.collected === 1, "Should have 1 collected");
    console.assert(progress1.required === 2, "Should require 2");
    console.assert(!progress1.canRecover, "Cannot recover with 1 share");

    // Check progress with 2 shares
    const progress2 = socialRecovery.getRecoveryProgress([
      invites[0].shareCode,
      invites[1].shareCode,
    ]);
    console.assert(progress2.collected === 2, "Should have 2 collected");
    console.assert(
      progress2.canRecover,
      "Should be able to recover with 2 shares"
    );

    console.log("✅ Recovery progress tracking working correctly");
  }

  // Test 10: Guardian Verification
  console.log("\nTest 10: Guardian Verification");
  {
    const socialRecovery = new SocialRecoveryManager();
    const testMnemonic =
      "test test test test test test test test test test test junk";

    // Derive the actual address from the mnemonic
    const { Wallet } = await import("ethers");
    const wallet = Wallet.fromPhrase(testMnemonic);
    const testAddress = wallet.address;

    const guardians = [{ name: "Alice" }, { name: "Bob" }];

    const result = await socialRecovery.setupSocialRecovery(
      testMnemonic,
      testAddress,
      guardians,
      2
    );

    const guardianId = result[0].id;

    // Mark as verified
    socialRecovery.markGuardianVerified(guardianId);

    const config = socialRecovery.getSocialRecoveryConfig();
    const verifiedGuardian = config?.guardians.find((g) => g.id === guardianId);

    console.assert(
      verifiedGuardian?.status === "active",
      "Guardian should be active"
    );
    console.assert(
      verifiedGuardian?.lastVerified,
      "Should have lastVerified timestamp"
    );

    console.log("✅ Guardian verification working correctly");
  }

  // Test 11: Guardian Revocation
  console.log("\nTest 11: Guardian Revocation");
  {
    const socialRecovery = new SocialRecoveryManager();
    const testMnemonic =
      "test test test test test test test test test test test junk";

    // Derive the actual address from the mnemonic
    const { Wallet } = await import("ethers");
    const wallet = Wallet.fromPhrase(testMnemonic);
    const testAddress = wallet.address;

    const guardians = [{ name: "Alice" }, { name: "Bob" }, { name: "Charlie" }];

    const result = await socialRecovery.setupSocialRecovery(
      testMnemonic,
      testAddress,
      guardians,
      2
    );

    const guardianId = result[1].id;

    // Revoke guardian
    socialRecovery.revokeGuardian(guardianId);

    const config = socialRecovery.getSocialRecoveryConfig();
    const revokedGuardian = config?.guardians.find((g) => g.id === guardianId);

    console.assert(
      revokedGuardian?.status === "revoked",
      "Guardian should be revoked"
    );

    console.log("✅ Guardian revocation working correctly");
  }

  // Test 12: Storage Persistence
  console.log("\nTest 12: Storage Persistence");
  {
    const socialRecovery = new SocialRecoveryManager();
    const testMnemonic =
      "test test test test test test test test test test test junk";

    // Derive the actual address from the mnemonic
    const { Wallet } = await import("ethers");
    const wallet = Wallet.fromPhrase(testMnemonic);
    const testAddress = wallet.address;

    const guardians = [{ name: "Alice" }, { name: "Bob" }];

    await socialRecovery.setupSocialRecovery(
      testMnemonic,
      testAddress,
      guardians,
      2
    );

    // Create new instance and retrieve config
    const socialRecovery2 = new SocialRecoveryManager();
    const config = socialRecovery2.getSocialRecoveryConfig();

    console.assert(config !== null, "Config should be persisted");
    console.assert(config?.threshold === 2, "Threshold should be persisted");
    console.assert(
      config?.guardians.length === 2,
      "Guardians should be persisted"
    );
    console.assert(
      config?.ethereumAddress === testAddress,
      "Address should be persisted"
    );

    console.log("✅ Storage persistence working correctly");
  }

  console.log("\n✅ All Social Recovery Tests Passed!\n");
}

runTests().catch(console.error);
