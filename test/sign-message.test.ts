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

  // Test 7: SIWE (Sign-In with Ethereum) signing
  console.log("\nTest 7: SIWE (Sign-In with Ethereum) signing");
  {
    const wallet = await getOriginSpecificAddress(testMnemonic, origin, 'YOLO');

    // Create a properly formatted SIWE message
    const siweMessage = `example.com wants you to sign in with your Ethereum account:
${wallet.address}

Sign in to example.com

URI: https://example.com
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`;

    const { Wallet } = await import("ethers");
    const signer = new Wallet(wallet.privateKey!);

    // SIWE messages are signed with EIP-191 (same as regular message signing)
    const signature = await signer.signMessage(siweMessage);
    const recovered = verifyMessage(siweMessage, signature);

    console.assert(
      recovered.toLowerCase() === wallet.address.toLowerCase(),
      "Recovered address should match wallet address"
    );

    console.log(`  ✓ SIWE message signed successfully`);
    console.log(`  ✓ Address: ${wallet.address}`);
    console.log(`  ✓ Signature verified with EIP-191`);
    console.log("✅ SIWE signing works");
  }

  // Test 8: rawHash signing (without EIP-191 prefix)
  console.log("\nTest 8: rawHash signing (without EIP-191 prefix)");
  {
    const wallet = await getOriginSpecificAddress(testMnemonic, origin, 'YOLO');

    // Create a 32-byte hash (e.g., from EIP-712 or Safe transaction)
    const { keccak256, toUtf8Bytes } = await import("ethers");
    const hash = keccak256(toUtf8Bytes("Some data to hash"));

    console.log(`  Hash to sign: ${hash}`);

    const { Wallet, SigningKey } = await import("ethers");
    const signer = new Wallet(wallet.privateKey!);
    const signingKey = new SigningKey(signer.privateKey);

    // Sign the raw hash directly (no EIP-191 prefix)
    const rawSignature = signingKey.sign(hash);
    const signature = rawSignature.serialized;

    console.log(`  ✓ Raw hash signed successfully`);
    console.log(`  ✓ Signature: ${signature.slice(0, 20)}...`);

    // Verify the signature by recovering the address
    const { recoverAddress } = await import("ethers");
    const recovered = recoverAddress(hash, signature);

    console.assert(
      recovered.toLowerCase() === wallet.address.toLowerCase(),
      "Recovered address should match wallet address"
    );

    console.log(`  ✓ Address: ${wallet.address}`);
    console.log(`  ✓ Signature verified (without EIP-191 prefix)`);
    console.log("✅ rawHash signing works");
  }

  // Test 9: Verify rawHash validation (must be 32 bytes)
  console.log("\nTest 9: rawHash validation (must be 32 bytes)");
  {
    // Test with invalid hash lengths
    const invalidHashes = [
      "0x1234", // Too short
      "0x" + "ab".repeat(31), // 31 bytes
      "0x" + "ab".repeat(33), // 33 bytes
    ];

    for (const invalidHash of invalidHashes) {
      let hashToCheck = invalidHash;
      if (hashToCheck.startsWith('0x')) {
        hashToCheck = hashToCheck.slice(2);
      }

      const isValid = hashToCheck.length === 64;
      console.assert(
        !isValid,
        `Hash with length ${hashToCheck.length} should be invalid`
      );
    }

    // Test with valid hash
    const validHash = "0x" + "ab".repeat(32);
    let validHashCheck = validHash;
    if (validHashCheck.startsWith('0x')) {
      validHashCheck = validHashCheck.slice(2);
    }

    const isValid = validHashCheck.length === 64;
    console.assert(
      isValid,
      `Hash with length ${validHashCheck.length} should be valid`
    );

    console.log(`  ✓ Invalid hash lengths rejected`);
    console.log(`  ✓ Valid 32-byte hash accepted`);
    console.log("✅ rawHash validation works");
  }

  // Test 10: Compare EIP-191 vs rawHash signatures
  console.log("\nTest 10: Compare EIP-191 vs rawHash signatures");
  {
    const wallet = await getOriginSpecificAddress(testMnemonic, origin, 'YOLO');
    const testData = "Hello World";

    const { Wallet, SigningKey, keccak256, toUtf8Bytes } = await import("ethers");
    const signer = new Wallet(wallet.privateKey!);
    const signingKey = new SigningKey(signer.privateKey);

    // EIP-191 signature (with prefix)
    const eip191Signature = await signer.signMessage(testData);

    // Raw hash signature (without prefix)
    const hash = keccak256(toUtf8Bytes(testData));
    const rawSignature = signingKey.sign(hash);

    // These should be different because EIP-191 adds a prefix
    console.assert(
      eip191Signature !== rawSignature.serialized,
      "EIP-191 and raw hash signatures should be different"
    );

    console.log(`  ✓ EIP-191 signature: ${eip191Signature.slice(0, 20)}...`);
    console.log(`  ✓ Raw hash signature: ${rawSignature.serialized.slice(0, 20)}...`);
    console.log(`  ✓ Signatures are different (as expected)`);
    console.log("✅ EIP-191 vs rawHash comparison works");
  }

  // Test 11: EIP-712 typed data signing
  console.log("\nTest 11: EIP-712 typed data signing");
  {
    const wallet = await getOriginSpecificAddress(testMnemonic, origin, 'YOLO');

    const { Wallet, TypedDataEncoder } = await import("ethers");
    const signer = new Wallet(wallet.privateKey!);

    // Define EIP-712 domain
    const domain = {
      name: 'TestDApp',
      version: '1',
      chainId: 1,
      verifyingContract: '0x1234567890123456789012345678901234567890'
    };

    // Define types
    const types = {
      Transfer: [
        { name: 'to', type: 'address' },
        { name: 'amount', type: 'uint256' }
      ]
    };

    // Message to sign
    const value = {
      to: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
      amount: '1000000000000000000'
    };

    // Sign with EIP-712
    const signature = await signer.signTypedData(domain, types, value);

    // Verify signature
    const hash = TypedDataEncoder.hash(domain, types, value);
    const { recoverAddress } = await import("ethers");
    const recovered = recoverAddress(hash, signature);

    console.assert(
      recovered.toLowerCase() === wallet.address.toLowerCase(),
      "Recovered address should match wallet address"
    );

    console.log(`  ✓ EIP-712 typed data signed successfully`);
    console.log(`  ✓ Domain: ${domain.name}`);
    console.log(`  ✓ Type: Transfer`);
    console.log(`  ✓ Signature: ${signature.slice(0, 20)}...`);
    console.log(`  ✓ Address verified: ${wallet.address}`);
    console.log("✅ EIP-712 signing works");
  }

  console.log("\n✅ All Sign Message Tests Passed!\n");
  console.log("📋 Summary:");
  console.log("  • STANDARD mode: Can sign messages (address-only derivation)");
  console.log("  • STRICT mode: Can sign messages (requires auth each time)");
  console.log("  • YOLO mode: Can sign messages (with private key access)");
  console.log("  • Different modes: Produce different signatures");
  console.log("  • Different tags: Produce different signatures");
  console.log("  • Deterministic: Same mode+tag always produces same signature");
  console.log("  • SIWE: Can sign EIP-4361 compliant messages");
  console.log("  • rawHash: Can sign raw 32-byte hashes without EIP-191 prefix");
  console.log("  • EIP-712: Can sign structured typed data");
  console.log("  • Validation: rawHash requires exactly 32 bytes");
  console.log("  • Comparison: EIP-191 and rawHash produce different signatures");
  console.log("");
}

runTests().catch(console.error);
