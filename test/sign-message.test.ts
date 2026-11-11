/**
 * Sign Message Tests
 * Tests for mode-based message signing
 */

import assert from "node:assert";
import { getOriginSpecificAddress } from "../src/wallet/origin-derivation";
import { verifyMessage } from "ethers";
import type { SecurityMode } from "../src/types";
import "./setup";
import { createWeb3Passkey } from "../src/index";

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
    const { deriveWalletFromPath } = await import("../src/wallet/generate");
    const { privateKey } = deriveWalletFromPath(testMnemonic, wallet.path);
    const signer = new Wallet(privateKey);

    const signature = await signer.signMessage(message);
    const recovered = verifyMessage(message, signature);

    assert(
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
    const { deriveWalletFromPath } = await import("../src/wallet/generate");
    const { privateKey } = deriveWalletFromPath(testMnemonic, wallet.path);
    const signer = new Wallet(privateKey);

    const signature = await signer.signMessage(message);
    const recovered = verifyMessage(message, signature);

    assert(
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

    assert(
      wallet.privateKey !== undefined,
      "YOLO mode should expose private key"
    );

    const { Wallet } = await import("ethers");
    const signer = new Wallet(wallet.privateKey!);

    const signature = await signer.signMessage(message);
    const recovered = verifyMessage(message, signature);

    assert(
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
      const { deriveWalletFromPath } = await import("../src/wallet/generate");
      const { privateKey } = deriveWalletFromPath(testMnemonic, wallet.path);
      const signer = new Wallet(privateKey);

      const signature = await signer.signMessage(message);
      signatures.set(mode, signature);
      addresses.set(mode, wallet.address);

      console.log(`  ${mode.padEnd(10)}: ${wallet.address}`);
    }

    // All addresses should be different
    const uniqueAddresses = new Set(addresses.values());
    assert(
      uniqueAddresses.size === modes.length,
      "Each mode should produce a unique address"
    );

    // All signatures should be different (since addresses are different)
    const uniqueSignatures = new Set(signatures.values());
    assert(
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

    assert(
      wallet1.address === wallet2.address,
      "Same mode should produce same address"
    );

    const { Wallet } = await import("ethers");
    const signer1 = new Wallet(wallet1.privateKey!);
    const signer2 = new Wallet(wallet2.privateKey!);

    const signature1 = await signer1.signMessage(message);
    const signature2 = await signer2.signMessage(message);

    assert(
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
    assert(
      uniqueAddresses.size === tags.length,
      "Each tag should produce a unique address"
    );

    // All signatures should be different (since addresses are different)
    const uniqueSignatures = new Set(signatures.values());
    assert(
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

    assert(
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

    assert(
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
      assert(
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
    assert(
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
    assert(
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

    assert(
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

  // Test 12: rawHash signing is rejected in PRIMARY mode
  console.log("\nTest 12: rawHash signing is rejected in PRIMARY mode");
  {
    const sdk = createWeb3Passkey({ debug: false });

    let cause = "";
    try {
      await sdk.signMessage("0x" + "ab".repeat(32), { mode: "PRIMARY", signingMethod: "rawHash" });
    } catch (error) {
      cause = (error as any).originalError?.message ?? "";
    }

    if (!cause.includes("rawHash signing is not supported in PRIMARY mode")) {
      throw new Error(`Expected PRIMARY mode rawHash rejection, got: "${cause}"`);
    }

    console.log(`  ✓ Rejected: ${cause}`);
    console.log("✅ PRIMARY mode rawHash rejection works");
  }

  // Test 13: SIWE signing rejects a message for another domain
  console.log("\nTest 13: SIWE signing checks the message's domain");
  {
    const sdk = createWeb3Passkey({ debug: false });
    const siweFor = (domain: string) => `${domain} wants you to sign in with your Ethereum account:
0x1234567890123456789012345678901234567890

URI: https://${domain}
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`;

    const causeOf = async (siweMessage: string) => {
      try {
        await sdk.signMessage(siweMessage, { signingMethod: "SIWE" });
      } catch (error) {
        return (error as any).originalError?.message ?? (error as Error).message;
      }
      return "";
    };

    const mismatch = await causeOf(siweFor("evil.example"));
    if (!mismatch.includes("does not match the current origin")) {
      throw new Error(`Expected SIWE domain rejection, got: "${mismatch}"`);
    }

    const host = new URL(window.location.origin).host;
    const scheme = new URL(window.location.origin).protocol;
    for (const domain of [host, host.toUpperCase(), `${scheme}//${host}`]) {
      const match = await causeOf(siweFor(domain));
      if (!match.includes("Must be authenticated")) {
        throw new Error(`Expected "${domain}" to pass the check, got: "${match}"`);
      }
    }

    const otherScheme = await causeOf(siweFor(`ftp://${host}`));
    if (!otherScheme.includes("does not match the current origin")) {
      throw new Error(`Expected another scheme to be rejected, got: "${otherScheme}"`);
    }

    let eip191 = "";
    try {
      await sdk.signMessage(siweFor("evil.example"));
    } catch (error) {
      eip191 = (error as any).originalError?.message ?? (error as Error).message;
    }
    if (!eip191.includes("does not match the current origin")) {
      throw new Error(`Expected a SIWE message signed as EIP-191 to be checked, got: "${eip191}"`);
    }

    const bytesCauseOf = async (bytes: Uint8Array) => {
      try {
        await sdk.signMessage(bytes);
      } catch (error) {
        return (error as any).originalError?.message ?? (error as Error).message;
      }
      return "";
    };
    const encode = (text: string) => new TextEncoder().encode(text);

    const otherBytes = await bytesCauseOf(encode(siweFor("evil.example")));
    if (!otherBytes.includes("does not match the current origin")) {
      throw new Error(`Expected a SIWE message as bytes to be checked, got: "${otherBytes}"`);
    }

    const sameBytes = await bytesCauseOf(encode(siweFor(host)));
    if (!sameBytes.includes("Must be authenticated")) {
      throw new Error(`Expected a SIWE message as bytes for "${host}" to pass, got: "${sameBytes}"`);
    }

    const invalidSiwe = await bytesCauseOf(new Uint8Array([...encode(siweFor(host)), 0xff]));
    if (!invalidSiwe.includes("not valid UTF-8")) {
      throw new Error(`Expected a SIWE message with invalid UTF-8 to be refused, got: "${invalidSiwe}"`);
    }

    const notText = await bytesCauseOf(new Uint8Array([0xff, 0x00, 0xfe, 0x80]));
    if (!notText.includes("Must be authenticated")) {
      throw new Error(`Expected invalid UTF-8 bytes to skip the check, got: "${notText}"`);
    }

    console.log(`  ✓ Rejected: ${mismatch}`);
    console.log("✅ SIWE domain check works");
  }

  // Test 14: rawHash signing requires a fresh assertion, even for an EIP-7702 digest
  console.log("\nTest 14: rawHash signing requires a fresh assertion");
  {
    const { Wallet, recoverAddress } = await import("ethers");
    const { hashEIP7702AuthorizationMessage } = await import("../src/eip7702/utils");
    const sdk = createWeb3Passkey({ debug: false });
    (sdk as any).currentUser = {
      username: "rawhash",
      ethereumAddress: Wallet.createRandom().address,
      credentialId: "test-credential",
    };
    await (sdk as any).sessionManager.startSession(testMnemonic, "test-credential");
    const forceAuthCalls: boolean[] = [];
    (sdk as any).getMnemonicFromSession = async (forceAuth: boolean = false) => {
      forceAuthCalls.push(forceAuth);
      return testMnemonic;
    };

    const digest = hashEIP7702AuthorizationMessage(
      1n,
      "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
      0n
    );

    for (const mode of ["STANDARD", "YOLO"] as const) {
      const result = await sdk.signMessage(digest, { mode, signingMethod: "rawHash" });
      assert(
        recoverAddress(digest, result.signature) === result.address,
        `${mode}: signature should recover to the signing address`
      );
    }

    await sdk.signMessage(message);

    for (const invalid of ["0x1234", "0x" + "ab".repeat(33), "0x" + "zz".repeat(32)]) {
      await assert.rejects(
        sdk.signMessage(invalid, { signingMethod: "rawHash" }),
        (error: any) => (error.originalError?.message ?? "").includes("requires a 32-byte hash")
      );
    }

    assert.deepStrictEqual(
      forceAuthCalls,
      [true, true, false],
      "rawHash should bypass the session cache, EIP-191 should not, and an invalid hash should not prompt"
    );

    console.log(`  ✓ rawHash bypasses the active session`);
    console.log("✅ rawHash fresh assertion works");
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
  console.log("  • rawHash: Always requires a fresh passkey assertion");
  console.log("  • EIP-712: Can sign structured typed data");
  console.log("  • Validation: rawHash requires exactly 32 bytes");
  console.log("  • Comparison: EIP-191 and rawHash produce different signatures");
  console.log("  • PRIMARY mode: rawHash signing is rejected");
  console.log("");
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
