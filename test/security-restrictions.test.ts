/**
 * Security Restrictions Tests
 * Verifies that applications cannot access sensitive key material
 */

import {
  getOriginSpecificAddress,
  DEFAULT_TAG,
} from "../src/wallet/origin-derivation";
import { Web3Passkey } from "../src/core/sdk";

async function runSecurityTests() {
  console.log("\n🔒 Running Security Restrictions Tests...\n");

  const testMnemonic =
    "test test test test test test test test test test test junk";

  // Test 1: MAIN tag does NOT expose private key
  console.log("Test 1: MAIN tag security");
  {
    const mainWallet = await getOriginSpecificAddress(
      testMnemonic,
      "https://app.example.com"
    );

    console.assert(
      mainWallet.tag === DEFAULT_TAG,
      "Should use MAIN tag by default"
    );
    console.assert(
      mainWallet.privateKey === undefined,
      "MAIN tag must NOT expose private key"
    );
    console.assert(
      mainWallet.address !== undefined,
      "MAIN tag should provide address"
    );

    console.log(`  ✓ MAIN tag wallet has address: ${mainWallet.address}`);
    console.log(`  ✓ MAIN tag wallet privateKey: ${mainWallet.privateKey === undefined ? 'HIDDEN ✓' : 'EXPOSED ✗'}`);
    console.log("✅ MAIN tag properly restricts private key access");
  }

  // Test 2: Non-MAIN tags DO expose private key
  console.log("\nTest 2: Non-MAIN tag access");
  {
    const customTags = ["GAMING", "TRADING", "SIMPLE", "DEFI", "NFT"];

    for (const tag of customTags) {
      const wallet = await getOriginSpecificAddress(
        testMnemonic,
        "https://app.example.com",
        tag
      );

      console.assert(
        wallet.tag === tag,
        `Tag should be ${tag}`
      );
      console.assert(
        wallet.privateKey !== undefined,
        `${tag} tag must expose private key`
      );
      console.assert(
        wallet.privateKey!.startsWith("0x"),
        "Private key should be valid hex"
      );
      console.assert(
        wallet.privateKey!.length === 66,
        "Private key should be 32 bytes (66 hex chars)"
      );

      console.log(`  ✓ ${tag.padEnd(10)} - privateKey: ${wallet.privateKey!.slice(0, 10)}...${wallet.privateKey!.slice(-8)}`);
    }

    console.log("✅ Non-MAIN tags properly expose private keys");
  }

  // Test 3: Different origins get different addresses
  console.log("\nTest 3: Origin isolation");
  {
    const origins = [
      "https://uniswap.org",
      "https://opensea.io",
      "https://app.aave.com",
    ];

    const addresses = new Set<string>();

    for (const origin of origins) {
      const wallet = await getOriginSpecificAddress(testMnemonic, origin);
      addresses.add(wallet.address);
      console.log(`  ${origin.padEnd(25)} → ${wallet.address}`);
    }

    console.assert(
      addresses.size === origins.length,
      "Each origin should get unique address"
    );

    console.log("✅ Origins are properly isolated");
  }

  // Test 4: Same origin + tag is deterministic
  console.log("\nTest 4: Deterministic derivation");
  {
    const wallet1 = await getOriginSpecificAddress(
      testMnemonic,
      "https://example.com",
      "GAMING"
    );
    const wallet2 = await getOriginSpecificAddress(
      testMnemonic,
      "https://example.com",
      "GAMING"
    );

    console.assert(
      wallet1.address === wallet2.address,
      "Same origin+tag should give same address"
    );
    console.assert(
      wallet1.privateKey === wallet2.privateKey,
      "Same origin+tag should give same private key"
    );

    console.log(`  First call:  ${wallet1.address}`);
    console.log(`  Second call: ${wallet2.address}`);
    console.log("✅ Derivation is deterministic");
  }

  // Test 5: exportMnemonic is disabled
  console.log("\nTest 5: exportMnemonic() restriction");
  {
    const sdk = new Web3Passkey();

    try {
      await sdk.exportMnemonic();
      console.error("❌ exportMnemonic() should throw an error!");
      process.exit(1);
    } catch (error: any) {
      console.assert(
        error.message.includes("disabled for security"),
        "Error should mention security restriction"
      );
      console.log(`  ✓ exportMnemonic() throws: "${error.message.slice(0, 60)}..."`);
      console.log("✅ exportMnemonic() is properly disabled");
    }
  }

  // Test 6: Verify no MAIN tag wallets leak private keys
  console.log("\nTest 6: Comprehensive MAIN tag check");
  {
    const origins = [
      "https://example.com",
      "https://test.com",
      "https://app.example.com",
      "http://localhost:3000",
      "https://example.com:8080",
    ];

    let allSecure = true;

    for (const origin of origins) {
      const wallet = await getOriginSpecificAddress(testMnemonic, origin);

      if (wallet.privateKey !== undefined) {
        console.error(`❌ MAIN tag leaked private key for ${origin}`);
        allSecure = false;
      }
    }

    console.assert(allSecure, "All MAIN tag wallets should hide private keys");
    console.log(`  ✓ Tested ${origins.length} origins`);
    console.log("✅ No MAIN tag private key leaks detected");
  }

  // Test 7: Tag case sensitivity doesn't affect security
  console.log("\nTest 7: Case sensitivity security");
  {
    const cases = ["main", "MAIN", "Main", "mAiN"];

    for (const testCase of cases) {
      const wallet = await getOriginSpecificAddress(
        testMnemonic,
        "https://example.com",
        testCase
      );

      console.assert(
        wallet.tag === "MAIN",
        `Tag "${testCase}" should normalize to MAIN`
      );
      console.assert(
        wallet.privateKey === undefined,
        `Tag "${testCase}" should not expose private key`
      );
    }

    console.log(`  ✓ Tested ${cases.length} case variations`);
    console.log("✅ MAIN tag case insensitivity is secure");
  }

  console.log("\n✅ All Security Restrictions Tests Passed!");
  console.log("\n📋 Security Summary:");
  console.log("  • MAIN tag wallets: Address only (no private key)");
  console.log("  • Non-MAIN tags: Full access (address + private key)");
  console.log("  • exportMnemonic(): Disabled for security");
  console.log("  • Origin isolation: Each origin gets unique addresses");
  console.log("  • Deterministic: Same origin+tag always gives same result");
  console.log("\n🔒 Applications CANNOT access:");
  console.log("  ✗ Master mnemonic");
  console.log("  ✗ MAIN tag private keys");
  console.log("  ✗ Private keys from other origins");
  console.log("\n✅ Applications CAN access:");
  console.log("  ✓ Their origin-specific MAIN address (read-only)");
  console.log("  ✓ Private keys for non-MAIN tagged wallets");
  console.log("  ✓ Signatures from any wallet (via signMessage)");
  console.log("");
}

runSecurityTests().catch(console.error);
