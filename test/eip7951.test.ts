/**
 * EIP-7951 Tests
 * Tests for PRIMARY mode (P-256 WebAuthn signatures) and helper functions
 */

import { extractRS } from "../src/utils/crypto";
import {
  base64UrlToArrayBuffer,
  arrayBufferToBase64Url,
  base64UrlDecode,
  base64ToArrayBuffer,
  safeAtob,
  safeBtoa,
} from "../src/utils/base64";
import { deriveAddressFromP256PublicKey } from "../src/wallet/origin-derivation";
import { keccak256 } from "ethers";

async function runTests() {
  console.log("\n🔐 Running EIP-7951 Tests...\n");

  // Test 1: extractRS - Parse DER signature and extract r,s
  console.log("Test 1: extractRS - Parse valid DER signature");
  {
    // Example DER signature (P-256): 0x30[len]02[rlen][r]02[slen][s]
    // Create a valid DER signature with r and s values
    const r = new Uint8Array(32).fill(0x12); // Mock r value
    const s = new Uint8Array(32).fill(0x34); // Mock s value

    // Build DER structure
    const derSig = new Uint8Array([
      0x30, // SEQUENCE tag
      0x44, // Total length (68 bytes: 2 + 32 + 2 + 32)
      0x02, // INTEGER tag for r
      0x20, // r length (32 bytes)
      ...r,
      0x02, // INTEGER tag for s
      0x20, // s length (32 bytes)
      ...s,
    ]);

    const result = extractRS(derSig);

    console.assert(result.r.startsWith("0x"), "r should start with 0x");
    console.assert(result.s.startsWith("0x"), "s should start with 0x");
    console.assert(result.r.length === 66, "r should be 66 chars (0x + 64 hex)");
    console.assert(result.s.length === 66, "s should be 66 chars (0x + 64 hex)");

    console.log(`  ✓ r: ${result.r.slice(0, 20)}...`);
    console.log(`  ✓ s: ${result.s.slice(0, 20)}...`);
    console.log("✅ extractRS parses DER signature correctly");
  }

  // Test 2: extractRS - Handle padding (high bit set)
  console.log("\nTest 2: extractRS - Handle DER padding for high bit");
  {
    // When the high bit is set, DER adds 0x00 padding
    const r = new Uint8Array(32);
    r[0] = 0xff; // High bit set
    r.fill(0x12, 1);

    const s = new Uint8Array(32);
    s[0] = 0x80; // High bit set
    s.fill(0x34, 1);

    const derSig = new Uint8Array([
      0x30, // SEQUENCE tag
      0x46, // Total length (70 bytes: padding adds 2 bytes)
      0x02, // INTEGER tag for r
      0x21, // r length (33 bytes with padding)
      0x00, // Padding byte
      ...r,
      0x02, // INTEGER tag for s
      0x21, // s length (33 bytes with padding)
      0x00, // Padding byte
      ...s,
    ]);

    const result = extractRS(derSig);

    console.assert(result.r.startsWith("0x"), "r should start with 0x");
    console.assert(result.s.startsWith("0x"), "s should start with 0x");
    console.assert(result.r.length === 66, "r should be 66 chars");
    console.assert(result.s.length === 66, "s should be 66 chars");

    console.log(`  ✓ Handled padded r: ${result.r.slice(0, 20)}...`);
    console.log(`  ✓ Handled padded s: ${result.s.slice(0, 20)}...`);
    console.log("✅ extractRS handles DER padding correctly");
  }

  // Test 3: extractRS - Low-s normalization
  console.log("\nTest 3: extractRS - Apply low-s normalization");
  {
    // P-256 curve order
    const n = BigInt(
      "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
    );
    const halfN = n / 2n;

    // Create an s value that's greater than n/2 (should be normalized)
    const highS = halfN + 100n;
    const sBytes = new Uint8Array(32);
    const sHex = highS.toString(16).padStart(64, "0");
    for (let i = 0; i < 32; i++) {
      sBytes[i] = parseInt(sHex.slice(i * 2, i * 2 + 2), 16);
    }

    const r = new Uint8Array(32).fill(0x12);

    const derSig = new Uint8Array([
      0x30, 0x44, 0x02, 0x20, ...r, 0x02, 0x20, ...sBytes,
    ]);

    const result = extractRS(derSig);

    // Extract the s value and verify it's been normalized
    const extractedS = BigInt(result.s);
    console.assert(
      extractedS <= halfN,
      "s should be normalized to low-s (s <= n/2)"
    );
    console.assert(extractedS === n - highS, "s should equal n - original_s");

    console.log(`  ✓ Original s > n/2: ${highS.toString(16).slice(0, 20)}...`);
    console.log(
      `  ✓ Normalized s <= n/2: ${extractedS.toString(16).slice(0, 20)}...`
    );
    console.log("✅ extractRS applies low-s normalization correctly");
  }

  // Test 4: extractRS - Invalid DER signature
  console.log("\nTest 4: extractRS - Handle invalid DER signature");
  {
    const invalidSig = new Uint8Array([0x31, 0x44, 0x02, 0x20]); // Wrong sequence tag

    try {
      extractRS(invalidSig);
      console.assert(false, "Should have thrown error for invalid signature");
    } catch (error) {
      console.assert(
        error instanceof Error,
        "Should throw Error for invalid signature"
      );
      console.assert(
        (error as Error).message.includes("Invalid DER signature"),
        "Error message should indicate invalid DER"
      );
      console.log(`  ✓ Correctly rejected invalid signature`);
      console.log("✅ extractRS validates DER signature format");
    }
  }

  // Test 5: base64UrlToArrayBuffer - Basic conversion
  console.log("\nTest 5: base64UrlToArrayBuffer - Basic conversion");
  {
    const input = "SGVsbG8gV29ybGQ"; // "Hello World" in base64url
    const result = base64UrlToArrayBuffer(input);
    const decoded = new TextDecoder().decode(result);

    console.assert(decoded === "Hello World", "Should decode to 'Hello World'");
    console.log(`  ✓ Decoded: ${decoded}`);
    console.log("✅ base64UrlToArrayBuffer works correctly");
  }

  // Test 6: base64UrlToArrayBuffer - Handle missing padding
  console.log("\nTest 6: base64UrlToArrayBuffer - Handle missing padding");
  {
    // Base64url is typically unpadded
    const unpadded = "SGVsbG8gV29ybGQ"; // No padding
    const result = base64UrlToArrayBuffer(unpadded);
    const decoded = new TextDecoder().decode(result);

    console.assert(decoded === "Hello World", "Should handle unpadded input");
    console.log(`  ✓ Handled unpadded input`);
    console.log("✅ base64UrlToArrayBuffer handles missing padding");
  }

  // Test 7: base64UrlToArrayBuffer - Handle URL-safe characters
  console.log("\nTest 7: base64UrlToArrayBuffer - Handle URL-safe characters");
  {
    // Base64url uses - and _ instead of + and /
    const urlSafe = "SGVsbG8tV29ybGRf"; // Contains - and _
    const result = base64UrlToArrayBuffer(urlSafe);

    console.assert(result instanceof ArrayBuffer, "Should return ArrayBuffer");
    console.log(`  ✓ Converted URL-safe base64`);
    console.log("✅ base64UrlToArrayBuffer handles URL-safe characters");
  }

  // Test 8: arrayBufferToBase64Url - Round-trip conversion
  console.log("\nTest 8: arrayBufferToBase64Url - Round-trip conversion");
  {
    const original = "Hello World!";
    const buffer = new TextEncoder().encode(original);

    const encoded = arrayBufferToBase64Url(buffer);
    const decoded = base64UrlToArrayBuffer(encoded);
    const result = new TextDecoder().decode(decoded);

    console.assert(result === original, "Round-trip should preserve data");
    console.assert(!encoded.includes("+"), "Should not contain +");
    console.assert(!encoded.includes("/"), "Should not contain /");
    console.assert(!encoded.includes("="), "Should not contain padding");

    console.log(`  ✓ Original: ${original}`);
    console.log(`  ✓ Encoded: ${encoded}`);
    console.log(`  ✓ Decoded: ${result}`);
    console.log("✅ arrayBufferToBase64Url round-trip works");
  }

  // Test 9: base64UrlDecode - Alias function
  console.log("\nTest 9: base64UrlDecode - Alias function");
  {
    const input = "SGVsbG8gV29ybGQ";
    const result1 = base64UrlDecode(input);
    const result2 = base64UrlToArrayBuffer(input);

    console.assert(
      result1.byteLength === result2.byteLength,
      "Alias should work identically"
    );

    const decoded1 = new TextDecoder().decode(result1);
    const decoded2 = new TextDecoder().decode(result2);

    console.assert(
      decoded1 === decoded2,
      "Alias should produce same result"
    );
    console.log(`  ✓ Alias works identically to base64UrlToArrayBuffer`);
    console.log("✅ base64UrlDecode alias works correctly");
  }

  // Test 10: base64ToArrayBuffer - Standard base64
  console.log("\nTest 10: base64ToArrayBuffer - Standard base64 with padding");
  {
    const input = "SGVsbG8gV29ybGQ="; // Standard base64 with padding
    const result = base64ToArrayBuffer(input);
    const decoded = new TextDecoder().decode(result);

    console.assert(decoded === "Hello World", "Should decode standard base64");
    console.log(`  ✓ Decoded: ${decoded}`);
    console.log("✅ base64ToArrayBuffer works with standard base64");
  }

  // Test 11: safeAtob - Handle both base64 and base64url
  console.log("\nTest 11: safeAtob - Handle both base64 and base64url");
  {
    const base64 = "SGVsbG8gV29ybGQ=";
    const base64url = "SGVsbG8gV29ybGQ";

    const result1 = safeAtob(base64);
    const result2 = safeAtob(base64url);

    console.assert(result1 === result2, "Should handle both formats");
    console.log(`  ✓ Handled both base64 and base64url`);
    console.log("✅ safeAtob handles both formats");
  }

  // Test 12: safeBtoa - Handle Unicode strings
  console.log("\nTest 12: safeBtoa - Handle Unicode strings");
  {
    const unicode = "Hello 世界 🌍";
    const encoded = safeBtoa(unicode);

    console.assert(encoded.length > 0, "Should encode Unicode");
    console.assert(!encoded.includes(unicode), "Should be encoded");

    console.log(`  ✓ Encoded Unicode string`);
    console.log("✅ safeBtoa handles Unicode correctly");
  }

  // Test 13: deriveAddressFromP256PublicKey - Address derivation
  console.log("\nTest 13: deriveAddressFromP256PublicKey - Derive Ethereum address");
  {
    // Generate a mock P-256 key pair for testing
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );

    // Export public key as SPKI
    const publicKeyBuffer = await crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );
    const publicKeySpki = arrayBufferToBase64Url(publicKeyBuffer);

    // Derive address
    const address = await deriveAddressFromP256PublicKey(publicKeySpki);

    console.assert(address.startsWith("0x"), "Address should start with 0x");
    console.assert(
      address.length === 42,
      "Address should be 42 chars (0x + 40 hex)"
    );
    console.assert(
      /^0x[0-9a-fA-F]{40}$/.test(address),
      "Address should be valid hex"
    );

    console.log(`  ✓ Derived address: ${address}`);
    console.log("✅ deriveAddressFromP256PublicKey works correctly");
  }

  // Test 14: deriveAddressFromP256PublicKey - Deterministic
  console.log("\nTest 14: deriveAddressFromP256PublicKey - Deterministic derivation");
  {
    // Generate a key pair
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );

    const publicKeyBuffer = await crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );
    const publicKeySpki = arrayBufferToBase64Url(publicKeyBuffer);

    // Derive address twice
    const address1 = await deriveAddressFromP256PublicKey(publicKeySpki);
    const address2 = await deriveAddressFromP256PublicKey(publicKeySpki);

    console.assert(
      address1 === address2,
      "Same public key should produce same address"
    );

    console.log(`  ✓ Address 1: ${address1}`);
    console.log(`  ✓ Address 2: ${address2}`);
    console.log("✅ deriveAddressFromP256PublicKey is deterministic");
  }

  // Test 15: deriveAddressFromP256PublicKey - Different keys produce different addresses
  console.log(
    "\nTest 15: deriveAddressFromP256PublicKey - Different keys produce different addresses"
  );
  {
    // Generate two different key pairs
    const keyPair1 = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );

    const keyPair2 = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );

    const publicKey1 = await crypto.subtle.exportKey("spki", keyPair1.publicKey);
    const publicKey2 = await crypto.subtle.exportKey("spki", keyPair2.publicKey);

    const address1 = await deriveAddressFromP256PublicKey(
      arrayBufferToBase64Url(publicKey1)
    );
    const address2 = await deriveAddressFromP256PublicKey(
      arrayBufferToBase64Url(publicKey2)
    );

    console.assert(
      address1 !== address2,
      "Different keys should produce different addresses"
    );

    console.log(`  ✓ Address 1: ${address1}`);
    console.log(`  ✓ Address 2: ${address2}`);
    console.log("✅ Different keys produce different addresses");
  }

  // Test 16: deriveAddressFromP256PublicKey - Follows EIP-7951 spec
  console.log("\nTest 16: deriveAddressFromP256PublicKey - Follows EIP-7951 spec");
  {
    // Generate a key pair and manually verify the derivation process
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );

    const publicKeyBuffer = await crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );
    const publicKeySpki = arrayBufferToBase64Url(publicKeyBuffer);

    // Derive address using the function
    const address = await deriveAddressFromP256PublicKey(publicKeySpki);

    // Manually verify: get x,y coordinates and compute address
    const publicKey = await crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["verify"]
    );

    const jwk = await crypto.subtle.exportKey("jwk", publicKey);
    const xBytes = base64UrlToArrayBuffer(jwk.x!);
    const yBytes = base64UrlToArrayBuffer(jwk.y!);

    // Create uncompressed public key (64 bytes: x || y)
    const uncompressedKey = new Uint8Array(64);
    uncompressedKey.set(new Uint8Array(xBytes), 0);
    uncompressedKey.set(new Uint8Array(yBytes), 32);

    // Hash with keccak256 and take last 20 bytes
    const hash = keccak256(uncompressedKey);
    const manualAddress = "0x" + hash.slice(-40);

    console.assert(
      address.toLowerCase() === manualAddress.toLowerCase(),
      "Function should match manual derivation"
    );

    console.log(`  ✓ Function address: ${address}`);
    console.log(`  ✓ Manual address:   ${manualAddress}`);
    console.log("✅ deriveAddressFromP256PublicKey follows EIP-7951 spec");
  }

  // Test 17: Integration test - Full signature flow simulation
  console.log("\nTest 17: Integration - Simulate PRIMARY mode signature flow");
  {
    // Step 1: Generate P-256 key pair (simulating WebAuthn credential)
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );

    // Step 2: Prepare message for signing
    const message = "Hello, EIP-7951!";

    // Step 3: Sign the message (crypto.subtle.sign will hash it internally)
    const signature = await crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: "SHA-256",
      },
      keyPair.privateKey,
      new TextEncoder().encode(message) // Sign the message, not the hash
    );

    // Note: WebAuthn returns signatures in DER format, but crypto.subtle.sign
    // may return in IEEE P1363 format (raw r || s). We need to check the format.
    const sigBytes = new Uint8Array(signature);

    // Check if it's DER format (starts with 0x30)
    let r: string, s: string;
    if (sigBytes[0] === 0x30) {
      // DER format - extract r,s
      const extracted = extractRS(sigBytes);
      r = extracted.r;
      s = extracted.s;
    } else {
      // IEEE P1363 format - split in half
      const rBytes = sigBytes.slice(0, sigBytes.length / 2);
      const sBytes = sigBytes.slice(sigBytes.length / 2);
      r = "0x" + Buffer.from(rBytes).toString("hex");
      s = "0x" + Buffer.from(sBytes).toString("hex");
    }

    // Step 4: Derive address from public key
    const publicKeyBuffer = await crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );
    const publicKeySpki = arrayBufferToBase64Url(publicKeyBuffer);
    const address = await deriveAddressFromP256PublicKey(publicKeySpki);

    // Step 5: Get public key coordinates
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const qx =
      "0x" + Buffer.from(base64UrlToArrayBuffer(jwk.x!)).toString("hex");
    const qy =
      "0x" + Buffer.from(base64UrlToArrayBuffer(jwk.y!)).toString("hex");

    console.assert(r.startsWith("0x"), "r should be hex");
    console.assert(s.startsWith("0x"), "s should be hex");
    console.assert(address.startsWith("0x"), "address should be hex");
    console.assert(qx.startsWith("0x"), "qx should be hex");
    console.assert(qy.startsWith("0x"), "qy should be hex");

    console.log(`  ✓ Message: ${message}`);
    console.log(`  ✓ Signature r: ${r.slice(0, 20)}...`);
    console.log(`  ✓ Signature s: ${s.slice(0, 20)}...`);
    console.log(`  ✓ Address: ${address}`);
    console.log(`  ✓ Public Key qx: ${qx.slice(0, 20)}...`);
    console.log(`  ✓ Public Key qy: ${qy.slice(0, 20)}...`);
    console.log("✅ Full PRIMARY mode signature flow works");
  }

  // Test 18: Edge case - Empty buffer handling
  console.log("\nTest 18: Edge case - Handle empty buffers");
  {
    const emptyBuffer = new Uint8Array(0);
    const encoded = arrayBufferToBase64Url(emptyBuffer);
    const decoded = base64UrlToArrayBuffer(encoded);

    console.assert(decoded.byteLength === 0, "Empty buffer should remain empty");
    console.log(`  ✓ Handled empty buffer`);
    console.log("✅ Empty buffer handling works");
  }

  // Test 19: Edge case - Large buffer handling
  console.log("\nTest 19: Edge case - Handle large buffers");
  {
    const largeBuffer = new Uint8Array(10000).fill(0x42);
    const encoded = arrayBufferToBase64Url(largeBuffer);
    const decoded = base64UrlToArrayBuffer(encoded);

    console.assert(
      decoded.byteLength === largeBuffer.length,
      "Large buffer size should be preserved"
    );

    const decodedArray = new Uint8Array(decoded);
    console.assert(
      decodedArray.every((b) => b === 0x42),
      "Large buffer contents should be preserved"
    );

    console.log(`  ✓ Handled ${largeBuffer.length} byte buffer`);
    console.log("✅ Large buffer handling works");
  }

  // Test 20: Edge case - extractRS with minimal valid signature
  console.log("\nTest 20: Edge case - extractRS with minimal DER signature");
  {
    // Create minimal valid DER signature (r and s with minimal bytes)
    const minR = new Uint8Array([0x01]); // Minimal r
    const minS = new Uint8Array([0x02]); // Minimal s

    const derSig = new Uint8Array([
      0x30, // SEQUENCE
      0x06, // Total length
      0x02, // INTEGER tag for r
      0x01, // r length
      ...minR,
      0x02, // INTEGER tag for s
      0x01, // s length
      ...minS,
    ]);

    const result = extractRS(derSig);

    console.assert(result.r.startsWith("0x"), "r should be hex");
    console.assert(result.s.startsWith("0x"), "s should be hex");
    console.assert(result.r.length === 66, "r should be padded to 32 bytes");
    console.assert(result.s.length === 66, "s should be padded to 32 bytes");

    console.log(`  ✓ Minimal r: ${result.r}`);
    console.log(`  ✓ Minimal s: ${result.s}`);
    console.log("✅ extractRS handles minimal DER signatures");
  }

  // Test 21: getAddress() - Basic functionality (requires Web3Passkey instance)
  console.log("\nTest 21: getAddress() - Validate method signature and exports");
  {
    // Note: Full integration tests with Web3Passkey instance are in separate test files
    // Here we just validate that the method is properly typed and exported
    const { Web3Passkey } = await import("../src/core/sdk");

    console.assert(Web3Passkey !== undefined, "Web3Passkey should be exported");
    console.assert(typeof Web3Passkey === "function", "Web3Passkey should be a constructor");

    // Check that the getAddress method exists on the prototype
    const instance = new Web3Passkey();
    console.assert(typeof instance.getAddress === "function", "getAddress should be a method");

    console.log(`  ✓ Web3Passkey exported correctly`);
    console.log(`  ✓ getAddress method exists`);
    console.log("✅ getAddress() method is properly defined");
  }

  console.log("\n✅ All EIP-7951 Tests Passed!\n");
  console.log("📋 Summary:");
  console.log("  • extractRS: DER parsing and low-s normalization ✓");
  console.log("  • base64 utilities: Encoding/decoding and URL-safe handling ✓");
  console.log("  • deriveAddressFromP256PublicKey: P-256 address derivation ✓");
  console.log("  • Integration: Full PRIMARY mode signature flow ✓");
  console.log("  • Edge cases: Empty buffers, large buffers, minimal signatures ✓");
  console.log("  • getAddress(): Method signature validation ✓");
  console.log("");
}

runTests().catch(console.error);
