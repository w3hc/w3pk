/**
 * Sign Message Tests
 * Tests for mode-based message signing
 */

import { getOriginSpecificAddress } from "../src/wallet/origin-derivation";
import { verifyMessage } from "ethers";
import type { SecurityMode } from "../src/types";

async function runTests() {
  console.log("\n✍️  Running Sign Message Tests...\n");

  const testMnemonic =
    "test test test test test test test test test test test junk";
  const message = "Hello, Web3!";
  const origin = "https://example.com";

  // Test 1: Sign with STANDARD mode (default)
  console.log("Test 1: Sign with STANDARD mode");
  {
    const wallet = await getOriginSpecificAddress(testMnemonic, origin);

    // Simulate signing (we need the private key internally for signing)
    const { Wallet } = await import("ethers");
    const { deriveWalletFromMnemonic } = await import("../src/wallet/generate");
    const { privateKey } = deriveWalletFromMnemonic(testMnemonic, wallet.index);
    const signer = new Wallet(privateKey);

    const signature = await signer.signMessage(message);
    const recovered = verifyMessage(message, signature);

    console.assert(
      recovered.toLowerCase() === wallet.address.toLowerCase(),
      "Recovered address should match wallet address"
    );

    console.log(`  ✓ Signed with STANDARD mode`);
    console.log(`  ✓ Address: ${wallet.address}`);
    console.log(`  ✓ Signature verified`);
    console.log("✅ STANDARD mode signing works");
  }

  // Test 2: Sign with STRICT mode
  console.log("\nTest 2: Sign with STRICT mode");
  {
    const wallet = await getOriginSpecificAddress(testMnemonic, origin, 'STRICT');

    const { Wallet } = await import("ethers");
    const { deriveWalletFromMnemonic } = await import("../src/wallet/generate");
    const { privateKey } = deriveWalletFromMnemonic(testMnemonic, wallet.index);
    const signer = new Wallet(privateKey);

    const signature = await signer.signMessage(message);
    const recovered = verifyMessage(message, signature);

    console.assert(
      recovered.toLowerCase() === wallet.address.toLowerCase(),
      "Recovered address should match wallet address"
    );

    console.log(`  ✓ Signed with STRICT mode`);
    console.log(`  ✓ Address: ${wallet.address}`);
    console.log(`  ✓ Signature verified`);
    console.log("✅ STRICT mode signing works");
  }

  // Test 3: Sign with YOLO mode
  console.log("\nTest 3: Sign with YOLO mode");
  {
    const wallet = await getOriginSpecificAddress(testMnemonic, origin, 'YOLO');

    console.assert(
      wallet.privateKey !== undefined,
      "YOLO mode should expose private key"
    );

    const { Wallet } = await import("ethers");
    const signer = new Wallet(wallet.privateKey!);

    const signature = await signer.signMessage(message);
    const recovered = verifyMessage(message, signature);

    console.assert(
      recovered.toLowerCase() === wallet.address.toLowerCase(),
      "Recovered address should match wallet address"
    );

    console.log(`  ✓ Signed with YOLO mode`);
    console.log(`  ✓ Address: ${wallet.address}`);
    console.log(`  ✓ Private key available`);
    console.log(`  ✓ Signature verified`);
    console.log("✅ YOLO mode signing works");
  }

  // Test 4: Different modes produce different signatures
  console.log("\nTest 4: Different modes produce different signatures");
  {
    const modes: SecurityMode[] = ['STANDARD', 'STRICT', 'YOLO'];
    const signatures = new Map<string, string>();
    const addresses = new Map<string, string>();

    for (const mode of modes) {
      const wallet = await getOriginSpecificAddress(testMnemonic, origin, mode);

      const { Wallet } = await import("ethers");
      const { deriveWalletFromMnemonic } = await import("../src/wallet/generate");
      const { privateKey } = deriveWalletFromMnemonic(testMnemonic, wallet.index);
      const signer = new Wallet(privateKey);

      const signature = await signer.signMessage(message);
      signatures.set(mode, signature);
      addresses.set(mode, wallet.address);

      console.log(`  ${mode.padEnd(10)}: ${wallet.address}`);
    }

    // All addresses should be different
    const uniqueAddresses = new Set(addresses.values());
    console.assert(
      uniqueAddresses.size === modes.length,
      "Each mode should produce a unique address"
    );

    // All signatures should be different (since addresses are different)
    const uniqueSignatures = new Set(signatures.values());
    console.assert(
      uniqueSignatures.size === modes.length,
      "Each mode should produce a unique signature"
    );

    console.log("✅ Different modes produce different signatures");
  }

  // Test 5: Same mode produces same signature
  console.log("\nTest 5: Same mode produces same signature (deterministic)");
  {
    const mode: SecurityMode = 'YOLO';
    const wallet1 = await getOriginSpecificAddress(testMnemonic, origin, mode);
    const wallet2 = await getOriginSpecificAddress(testMnemonic, origin, mode);

    console.assert(
      wallet1.address === wallet2.address,
      "Same mode should produce same address"
    );

    const { Wallet } = await import("ethers");
    const signer1 = new Wallet(wallet1.privateKey!);
    const signer2 = new Wallet(wallet2.privateKey!);

    const signature1 = await signer1.signMessage(message);
    const signature2 = await signer2.signMessage(message);

    console.assert(
      signature1 === signature2,
      "Same mode should produce same signature"
    );

    console.log(`  ✓ Address: ${wallet1.address}`);
    console.log(`  ✓ Signature is deterministic`);
    console.log("✅ Deterministic signing works");
  }

  // Test 6: Custom tags produce different signatures
  console.log("\nTest 6: Custom tags produce different signatures");
  {
    const mode: SecurityMode = 'YOLO';
    const tags = ['MAIN', 'GAMING', 'TRADING'];
    const signatures = new Map<string, string>();
    const addresses = new Map<string, string>();

    for (const tag of tags) {
      const wallet = await getOriginSpecificAddress(testMnemonic, origin, mode, tag);

      const { Wallet } = await import("ethers");
      const signer = new Wallet(wallet.privateKey!);

      const signature = await signer.signMessage(message);
      signatures.set(tag, signature);
      addresses.set(tag, wallet.address);

      console.log(`  ${tag.padEnd(10)}: ${wallet.address}`);
    }

    // All addresses should be different
    const uniqueAddresses = new Set(addresses.values());
    console.assert(
      uniqueAddresses.size === tags.length,
      "Each tag should produce a unique address"
    );

    // All signatures should be different (since addresses are different)
    const uniqueSignatures = new Set(signatures.values());
    console.assert(
      uniqueSignatures.size === tags.length,
      "Each tag should produce a unique signature"
    );

    console.log("✅ Different tags produce different signatures");
  }

  console.log("\n✅ All Sign Message Tests Passed!\n");
  console.log("📋 Summary:");
  console.log("  • STANDARD mode: Can sign messages (address-only derivation)");
  console.log("  • STRICT mode: Can sign messages (requires auth each time)");
  console.log("  • YOLO mode: Can sign messages (with private key access)");
  console.log("  • Different modes: Produce different signatures");
  console.log("  • Different tags: Produce different signatures");
  console.log("  • Deterministic: Same mode+tag always produces same signature");
  console.log("");
}

runTests().catch(console.error);
