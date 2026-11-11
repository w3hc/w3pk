/**
 * SIWE (Sign-In with Ethereum) Utility Tests
 * Tests for EIP-4361 compliant message construction and validation
 */

import assert from "node:assert";
import {
  generateSiweNonce,
  createSiweMessage,
  parseSiweMessage,
  validateSiweMessage,
  verifySiweSignature,
  type SiweMessage,
} from "../src/siwe";
import { SiweMessage as SiweLibMessage } from "siwe";

async function runTests() {
  console.log("\n🔐 Running SIWE Utility Tests...\n");

  // Test 1: Generate nonce
  console.log("Test 1: Generate SIWE nonce");
  {
    const nonce = generateSiweNonce();

    assert(nonce.length === 11, "Default nonce should be 11 characters");
    assert(/^[a-zA-Z0-9]+$/.test(nonce), "Nonce should be alphanumeric");

    const nonce20 = generateSiweNonce(20);
    assert(nonce20.length === 20, "Custom length nonce should match");

    // Test uniqueness
    const nonce2 = generateSiweNonce();
    assert(nonce !== nonce2, "Nonces should be unique");

    console.log(`  ✓ Generated nonce: ${nonce}`);
    console.log(`  ✓ Custom length nonce (20): ${nonce20}`);
    console.log("✅ Nonce generation works");
  }

  // Test 1b: Nonce bytes past the last multiple of 62 are dropped
  console.log("\nTest 1b: Nonce has no modulo bias");
  {
    const original = crypto.getRandomValues;
    const batches = [[248, 255, 0, 61], [62, 1]];
    crypto.getRandomValues = (<T extends ArrayBufferView>(array: T): T => {
      (array as unknown as Uint8Array).set(batches.shift()!);
      return array;
    }) as typeof crypto.getRandomValues;
    let nonce: string;
    try {
      nonce = generateSiweNonce(4);
    } finally {
      crypto.getRandomValues = original;
    }
    assert(nonce === "A9AB", `Bytes 248 and 255 should be skipped, got ${nonce}`);

    const counts = new Map<string, number>();
    for (let i = 0; i < 2000; i++) {
      for (const char of generateSiweNonce(62)) counts.set(char, (counts.get(char) ?? 0) + 1);
    }
    assert(counts.size === 62, "Every character should appear");
    for (const [char, count] of counts) {
      assert(count > 1700 && count < 2300, `"${char}" appears ${count} times out of an expected 2000`);
    }

    console.log("  ✓ Bytes >= 248 are rejected");
    console.log("  ✓ Characters are uniformly distributed");
    console.log("✅ Nonce rejection sampling works");
  }

  // Test 2: Create basic SIWE message (required fields only)
  console.log("\nTest 2: Create basic SIWE message");
  {
    const params: SiweMessage = {
      domain: "example.com",
      address: "0x1234567890123456789012345678901234567890",
      uri: "https://example.com/login",
      version: "1",
      chainId: 1,
      nonce: generateSiweNonce(),
      issuedAt: "2021-09-30T16:25:24Z",
    };

    const message = createSiweMessage(params);

    assert(message.includes("example.com wants you to sign in"), "Should include domain");
    assert(message.includes(params.address), "Should include address");
    assert(message.includes("URI: https://example.com/login"), "Should include URI");
    assert(message.includes("Version: 1"), "Should include version");
    assert(message.includes("Chain ID: 1"), "Should include chain ID");
    assert(message.includes(`Nonce: ${params.nonce}`), "Should include nonce");
    assert(message.includes("Issued At: 2021-09-30T16:25:24Z"), "Should include issued at");

    console.log("  ✓ Message includes all required fields");
    console.log("✅ Basic SIWE message creation works");
  }

  // Test 3: Create SIWE message with optional fields
  console.log("\nTest 3: Create SIWE message with optional fields");
  {
    const params: SiweMessage = {
      domain: "app.example.com",
      address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
      statement: "Sign in to Example App",
      uri: "https://app.example.com/login",
      version: "1",
      chainId: 1,
      nonce: generateSiweNonce(),
      issuedAt: "2024-01-01T12:00:00Z",
      expirationTime: "2024-01-01T13:00:00Z",
      notBefore: "2024-01-01T11:55:00Z",
      requestId: "req-12345",
      resources: [
        "https://example.com/terms",
        "https://example.com/privacy",
      ],
    };

    const message = createSiweMessage(params);

    assert(message.includes("Sign in to Example App"), "Should include statement");
    assert(message.includes("Expiration Time: 2024-01-01T13:00:00Z"), "Should include expiration");
    assert(message.includes("Not Before: 2024-01-01T11:55:00Z"), "Should include not-before");
    assert(message.includes("Request ID: req-12345"), "Should include request ID");
    assert(message.includes("Resources:"), "Should include resources header");
    assert(message.includes("- https://example.com/terms"), "Should include resource 1");
    assert(message.includes("- https://example.com/privacy"), "Should include resource 2");

    console.log("  ✓ Message includes all optional fields");
    console.log("✅ Full SIWE message creation works");
  }

  // Test 4: Parse SIWE message
  console.log("\nTest 4: Parse SIWE message");
  {
    const nonce = generateSiweNonce();
    const originalParams: SiweMessage = {
      domain: "example.com",
      address: "0x1234567890123456789012345678901234567890",
      statement: "Welcome to Example",
      uri: "https://example.com",
      version: "1",
      chainId: 1,
      nonce,
      issuedAt: "2024-01-01T12:00:00Z",
      expirationTime: "2024-01-02T12:00:00Z",
    };

    const message = createSiweMessage(originalParams);
    const parsed = parseSiweMessage(message);

    assert(parsed.domain === originalParams.domain, "Domain should match");
    assert(parsed.address === originalParams.address, "Address should match");
    assert(parsed.statement === originalParams.statement, "Statement should match");
    assert(parsed.uri === originalParams.uri, "URI should match");
    assert(parsed.version === originalParams.version, "Version should match");
    assert(parsed.chainId === originalParams.chainId, "Chain ID should match");
    assert(parsed.nonce === originalParams.nonce, "Nonce should match");
    assert(parsed.issuedAt === originalParams.issuedAt, "Issued at should match");
    assert(parsed.expirationTime === originalParams.expirationTime, "Expiration should match");

    console.log("  ✓ All fields parsed correctly");
    console.log("✅ SIWE message parsing works");
  }

  // Test 5: Validate SIWE message
  console.log("\nTest 5: Validate SIWE message");
  {
    const validParams: SiweMessage = {
      domain: "example.com",
      address: "0x1234567890123456789012345678901234567890",
      uri: "https://example.com",
      version: "1",
      chainId: 1,
      nonce: generateSiweNonce(),
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + 3600000).toISOString(), // 1 hour from now
    };

    const validMessage = createSiweMessage(validParams);
    const validation = validateSiweMessage(validMessage, {
      domain: "example.com",
      chainId: 1,
    });

    assert(validation.valid === true, "Valid message should pass validation");
    assert(validation.errors.length === 0, "Should have no errors");

    console.log("  ✓ Valid message passes validation");
    console.log("✅ SIWE message validation works");
  }

  // Test 6: Validate expired message
  console.log("\nTest 6: Validate expired message");
  {
    const expiredParams: SiweMessage = {
      domain: "example.com",
      address: "0x1234567890123456789012345678901234567890",
      uri: "https://example.com",
      version: "1",
      chainId: 1,
      nonce: generateSiweNonce(),
      issuedAt: new Date(Date.now() - 7200000).toISOString(), // 2 hours ago
      expirationTime: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago (expired)
    };

    const expiredMessage = createSiweMessage(expiredParams);
    const validation = validateSiweMessage(expiredMessage);

    assert(validation.valid === false, "Expired message should fail validation");
    assert(validation.errors.some(e => e.includes("expired")), "Should have expiration error");

    console.log("  ✓ Expired message fails validation");
    console.log("✅ Expiration check works");
  }

  // Test 7: Validate domain mismatch
  console.log("\nTest 7: Validate domain mismatch");
  {
    const params: SiweMessage = {
      domain: "example.com",
      address: "0x1234567890123456789012345678901234567890",
      uri: "https://example.com",
      version: "1",
      chainId: 1,
      nonce: generateSiweNonce(),
      issuedAt: new Date().toISOString(),
    };

    const message = createSiweMessage(params);
    const validation = validateSiweMessage(message, {
      domain: "different.com", // Different domain
    });

    assert(validation.valid === false, "Mismatched domain should fail");
    assert(validation.errors.some(e => e.includes("Domain mismatch")), "Should have domain error");

    console.log("  ✓ Domain mismatch detected");
    console.log("✅ Domain validation works");
  }

  // Test 8: Sign and verify SIWE message
  console.log("\nTest 8: Sign and verify SIWE message");
  {
    const { Wallet } = await import("ethers");

    // Create a test wallet
    const wallet = Wallet.createRandom();
    const address = wallet.address;

    const params: SiweMessage = {
      domain: "example.com",
      address,
      statement: "Sign in to Example",
      uri: "https://example.com",
      version: "1",
      chainId: 1,
      nonce: generateSiweNonce(),
      issuedAt: new Date().toISOString(),
    };

    const message = createSiweMessage(params);

    // Sign the message with EIP-191
    const signature = await wallet.signMessage(message);

    // Verify the signature
    const verification = await verifySiweSignature(message, signature);

    assert(verification.valid === true, "Signature should be valid");
    assert(verification.address?.toLowerCase() === address.toLowerCase(), "Address should match");

    console.log(`  ✓ Message signed by: ${address}`);
    console.log(`  ✓ Signature verified: ${signature.slice(0, 20)}...`);
    console.log("✅ SIWE signature verification works");
  }

  // Test 9: Detect invalid signature
  console.log("\nTest 9: Detect invalid signature");
  {
    const { Wallet } = await import("ethers");

    const wallet1 = Wallet.createRandom();
    const wallet2 = Wallet.createRandom();

    const params: SiweMessage = {
      domain: "example.com",
      address: wallet1.address,
      uri: "https://example.com",
      version: "1",
      chainId: 1,
      nonce: generateSiweNonce(),
      issuedAt: new Date().toISOString(),
    };

    const message = createSiweMessage(params);

    // Sign with wallet1
    const signature = await wallet1.signMessage(message);

    // Try to verify with wallet2's address (should fail)
    const verification = await verifySiweSignature(message, signature, wallet2.address);

    assert(verification.valid === false, "Wrong address should fail verification");
    assert(verification.error !== undefined, "Should have error message");

    console.log("  ✓ Invalid signature detected");
    console.log("✅ Signature validation works");
  }

  // Test 10: Roundtrip test (create -> parse -> recreate)
  console.log("\nTest 10: Roundtrip test (create -> parse -> recreate)");
  {
    const originalParams: SiweMessage = {
      domain: "app.example.com",
      address: "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
      statement: "I accept the Terms of Service",
      uri: "https://app.example.com/login",
      version: "1",
      chainId: 137,
      nonce: generateSiweNonce(),
      issuedAt: "2024-06-15T10:30:00Z",
      expirationTime: "2024-06-15T11:30:00Z",
      requestId: "request-xyz-789",
      resources: ["https://app.example.com/tos"],
    };

    const message1 = createSiweMessage(originalParams);
    const parsed = parseSiweMessage(message1);
    const message2 = createSiweMessage(parsed);

    assert(message1 === message2, "Roundtrip should produce identical message");

    console.log("  ✓ Original and roundtrip messages match");
    console.log("✅ Roundtrip consistency works");
  }

  // Test 11: Compatibility with the siwe library, with and without a statement
  console.log("\nTest 11: Compatibility with the siwe library");
  {
    const base: SiweMessage = {
      domain: "localhost:3000",
      address: "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
      uri: "http://localhost:3000",
      version: "1",
      chainId: 1,
      nonce: generateSiweNonce(),
      issuedAt: "2026-09-30T10:00:00.000Z",
    };

    for (const params of [base, { ...base, statement: "Sign in to Wulong" }]) {
      const message = createSiweMessage(params);
      const expected = new SiweLibMessage({ ...params }).prepareMessage();
      if (message !== expected) {
        throw new Error(`Message differs from siwe output:\n${message}\n---\n${expected}`);
      }

      const parsed = new SiweLibMessage(message);
      if (parsed.prepareMessage() !== message) {
        throw new Error("siwe should parse the message back unchanged");
      }
    }

    console.log("  ✓ Messages match siwe's prepareMessage() output");
    console.log("✅ siwe compatibility works");
  }

  // Test 12: Not-before in the future fails without being asked
  console.log("\nTest 12: Validate not-yet-valid message");
  {
    const message = createSiweMessage({
      domain: "example.com",
      address: "0x1234567890123456789012345678901234567890",
      uri: "https://example.com",
      version: "1",
      chainId: 1,
      nonce: generateSiweNonce(),
      issuedAt: new Date().toISOString(),
      notBefore: new Date(Date.now() + 3600000).toISOString(),
    });

    const validation = validateSiweMessage(message);
    assert(validation.valid === false, "Not-yet-valid message should fail validation");
    assert(validation.errors.some(e => e.includes("not yet valid")), "Should have not-before error");

    console.log("  ✓ Not-before is checked by default");
    console.log("✅ Not-before check works");
  }

  // Test 13: Invalid dates fail validation
  console.log("\nTest 13: Validate invalid dates");
  {
    const base: SiweMessage = {
      domain: "example.com",
      address: "0x1234567890123456789012345678901234567890",
      uri: "https://example.com",
      version: "1",
      chainId: 1,
      nonce: generateSiweNonce(),
      issuedAt: new Date().toISOString(),
    };

    const cases: Array<[Partial<SiweMessage>, string]> = [
      [{ expirationTime: "not-a-date" }, "Invalid Expiration Time"],
      [{ notBefore: "not-a-date" }, "Invalid Not Before"],
      [{ issuedAt: "not-a-date" }, "Invalid Issued At"],
      [{ expirationTime: "3000" }, "Invalid Expiration Time"],
      [{ notBefore: "Jan 1 2000" }, "Invalid Not Before"],
    ];
    for (const [fields, expected] of cases) {
      const validation = validateSiweMessage(createSiweMessage({ ...base, ...fields }));
      assert(validation.valid === false, `${expected} should fail validation`);
      assert(validation.errors.some(e => e.includes(expected)), `Should report ${expected}`);
    }

    console.log("  ✓ Invalid dates fail validation");
    console.log("✅ Date validation works");
  }

  // Test 14: Line breaks in domain, uri and resources are rejected
  console.log("\nTest 14: Reject line breaks in fields");
  {
    const base: SiweMessage = {
      domain: "example.com",
      address: "0x1234567890123456789012345678901234567890",
      uri: "https://example.com",
      version: "1",
      chainId: 1,
      nonce: generateSiweNonce(),
      issuedAt: new Date().toISOString(),
    };

    const injected = "\nExpiration Time: 2999-01-01T00:00:00Z";
    const cases: Array<[Partial<SiweMessage>, string]> = [
      [{ domain: `example.com${injected}` }, "Domain"],
      [{ domain: "example.com\r" }, "Domain"],
      [{ uri: `https://example.com${injected}` }, "URI"],
      [{ resources: ["https://example.com/tos", `https://example.com${injected}`] }, "Resources"],
      [{ statement: "Sign in\rnow" }, "Statement"],
    ];
    for (const [fields, expected] of cases) {
      assert.throws(
        () => createSiweMessage({ ...base, ...fields }),
        (error: Error) => error.message.startsWith(`${expected} cannot contain line breaks`),
        `${expected} with a line break should be rejected`
      );

      const validation = validateSiweMessage({ ...base, ...fields });
      assert(validation.valid === false, `${expected} with a line break should fail validation`);
    }

    console.log("  ✓ Line breaks are rejected");
    console.log("✅ Line break checks work");
  }

  console.log("\n✅ All SIWE Utility Tests Passed!\n");
  console.log("📋 Summary:");
  console.log("  • Nonce generation: Secure random alphanumeric strings");
  console.log("  • Message creation: EIP-4361 compliant formatting");
  console.log("  • Message parsing: Accurate field extraction");
  console.log("  • Validation: Domain, chain ID, expiration checks");
  console.log("  • Signature verification: EIP-191 compatible");
  console.log("  • Error detection: Invalid signatures and expired messages");
  console.log("  • Roundtrip: Consistent encode/decode");
  console.log("");
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
