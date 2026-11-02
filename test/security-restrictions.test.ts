/**
 * Security Restrictions Tests
 * Verifies that applications cannot access sensitive key material based on security mode
 */

import assert from "node:assert";
import {
  getOriginSpecificAddress,
  DEFAULT_TAG,
  DEFAULT_MODE,
} from "../src/wallet/origin-derivation";
import { Web3Passkey } from "../src/core/sdk";

async function runSecurityTests() {
  console.log("\n🔒 Running Security Restrictions Tests...\n");

  const testMnemonic =
    "test test test test test test test test test test test junk";

  // Test 1: STANDARD mode does NOT expose private key
  console.log("Test 1: STANDARD mode security");
  {
    const wallet = await getOriginSpecificAddress(
      testMnemonic,
      "https://app.example.com"
    );

    assert(
      wallet.mode === DEFAULT_MODE,
      "Should use STANDARD mode by default"
    );
    assert(
      wallet.privateKey === undefined,
      "STANDARD mode must NOT expose private key"
    );
    assert(
      wallet.address !== undefined,
      "STANDARD mode should provide address"
    );

    console.log(`  ✓ STANDARD mode wallet has address: ${wallet.address}`);
    console.log(`  ✓ STANDARD mode wallet privateKey: ${wallet.privateKey === undefined ? 'HIDDEN ✓' : 'EXPOSED ✗'}`);
    console.log("✅ STANDARD mode properly restricts private key access");
  }

  // Test 2: STRICT mode does NOT expose private key
  console.log("\nTest 2: STRICT mode security");
  {
    const wallet = await getOriginSpecificAddress(
      testMnemonic,
      "https://app.example.com",
      'STRICT'
    );

    assert(
      wallet.mode === 'STRICT',
      "Should use STRICT mode"
    );
    assert(
      wallet.privateKey === undefined,
      "STRICT mode must NOT expose private key"
    );
    assert(
      wallet.address !== undefined,
      "STRICT mode should provide address"
    );

    console.log(`  ✓ STRICT mode wallet has address: ${wallet.address}`);
    console.log(`  ✓ STRICT mode wallet privateKey: ${wallet.privateKey === undefined ? 'HIDDEN ✓' : 'EXPOSED ✗'}`);
    console.log("✅ STRICT mode properly restricts private key access");
  }

  // Test 3: YOLO mode DOES expose private key
  console.log("\nTest 3: YOLO mode access");
  {
    const wallet = await getOriginSpecificAddress(
      testMnemonic,
      "https://app.example.com",
      'YOLO'
    );

    assert(
      wallet.mode === 'YOLO',
      "Should use YOLO mode"
    );
    assert(
      wallet.privateKey !== undefined,
      "YOLO mode must expose private key"
    );
    assert(
      wallet.privateKey!.startsWith("0x"),
      "Private key should be valid hex"
    );
    assert(
      wallet.privateKey!.length === 66,
      "Private key should be 32 bytes (66 hex chars)"
    );

    console.log(`  ✓ YOLO mode - privateKey: ${wallet.privateKey!.slice(0, 10)}...${wallet.privateKey!.slice(-8)}`);
    console.log("✅ YOLO mode properly exposes private key");
  }

  // Test 4: Different origins get different addresses
  console.log("\nTest 4: Origin isolation");
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

    assert(
      addresses.size === origins.length,
      "Each origin should get unique address"
    );

    console.log("✅ Origins are properly isolated");
  }

  // Test 5: Same origin + mode + tag is deterministic
  console.log("\nTest 5: Deterministic derivation");
  {
    const wallet1 = await getOriginSpecificAddress(
      testMnemonic,
      "https://example.com",
      'YOLO',
      'GAMING'
    );
    const wallet2 = await getOriginSpecificAddress(
      testMnemonic,
      "https://example.com",
      'YOLO',
      'GAMING'
    );

    assert(
      wallet1.address === wallet2.address,
      "Same origin+mode+tag should give same address"
    );
    assert(
      wallet1.privateKey === wallet2.privateKey,
      "Same origin+mode+tag should give same private key"
    );

    console.log(`  First call:  ${wallet1.address}`);
    console.log(`  Second call: ${wallet2.address}`);
    console.log("✅ Derivation is deterministic");
  }

  // Test 6: exportMnemonic is not part of the SDK
  console.log("\nTest 6: exportMnemonic() is not exposed");
  {
    const sdk = new Web3Passkey();
    assert(
      !("exportMnemonic" in sdk),
      "exportMnemonic() should not exist on the SDK"
    );
    console.log("✅ exportMnemonic() is not exposed");
  }

  // Test 7: Verify STANDARD and STRICT modes never leak private keys
  console.log("\nTest 7: Comprehensive STANDARD/STRICT mode check");
  {
    const origins = [
      "https://example.com",
      "https://test.com",
      "https://app.example.com",
      "http://localhost:3000",
      "https://example.com:8080",
    ];

    const modes: Array<'STANDARD' | 'STRICT'> = ['STANDARD', 'STRICT'];
    let allSecure = true;

    for (const mode of modes) {
      for (const origin of origins) {
        const wallet = await getOriginSpecificAddress(testMnemonic, origin, mode);

        if (wallet.privateKey !== undefined) {
          console.error(`❌ ${mode} mode leaked private key for ${origin}`);
          allSecure = false;
        }
      }
    }

    assert(allSecure, "All STANDARD/STRICT mode wallets should hide private keys");
    console.log(`  ✓ Tested ${origins.length * modes.length} combinations`);
    console.log("✅ No STANDARD/STRICT mode private key leaks detected");
  }

  // Test 8: Different modes produce different addresses
  console.log("\nTest 8: Mode isolation");
  {
    const origin = "https://example.com";
    const tag = DEFAULT_TAG;

    const standard = await getOriginSpecificAddress(testMnemonic, origin, 'STANDARD', tag);
    const strict = await getOriginSpecificAddress(testMnemonic, origin, 'STRICT', tag);
    const yolo = await getOriginSpecificAddress(testMnemonic, origin, 'YOLO', tag);

    assert(
      standard.address !== strict.address,
      "STANDARD and STRICT should produce different addresses"
    );
    assert(
      standard.address !== yolo.address,
      "STANDARD and YOLO should produce different addresses"
    );
    assert(
      strict.address !== yolo.address,
      "STRICT and YOLO should produce different addresses"
    );

    console.log(`  STANDARD: ${standard.address}`);
    console.log(`  STRICT:   ${strict.address}`);
    console.log(`  YOLO:     ${yolo.address}`);
    console.log("✅ Different modes produce different addresses");
  }

  console.log("\n✅ All Security Restrictions Tests Passed!");
  console.log("\n📋 Security Summary:");
  console.log("  • STANDARD mode: Address only (no private key), persistent sessions allowed");
  console.log("  • STRICT mode: Address only (no private key), no persistent sessions");
  console.log("  • YOLO mode: Full access (address + private key), persistent sessions allowed");
  console.log("  • exportMnemonic(): Not exposed");
  console.log("  • Origin isolation: Each origin gets unique addresses");
  console.log("  • Mode isolation: Each mode gets unique addresses");
  console.log("  • Deterministic: Same origin+mode+tag always gives same result");
  console.log("\n🔒 Applications CANNOT access:");
  console.log("  ✗ Master mnemonic");
  console.log("  ✗ Private keys in STANDARD mode");
  console.log("  ✗ Private keys in STRICT mode");
  console.log("  ✗ Private keys from other origins");
  console.log("  ✗ Private keys from other modes");
  console.log("\n✅ Applications CAN access:");
  console.log("  ✓ Their origin-specific address (STANDARD/STRICT/YOLO)");
  console.log("  ✓ Private keys in YOLO mode");
  console.log("  ✓ Signatures from any wallet (via signMessage)");
  console.log("");
}

runSecurityTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
