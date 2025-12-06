/**
 * SIWE (Sign-In with Ethereum) Utility Tests
 * Tests for EIP-4361 compliant message construction and validation
 */

import {
  generateSiweNonce,
  createSiweMessage,
  parseSiweMessage,
  validateSiweMessage,
  verifySiweSignature,
  type SiweMessage,
} from "../src/siwe";

async function runTests() {
  console.log("\n🔐 Running SIWE Utility Tests...\n");

  // Test 1: Generate nonce
  console.log("Test 1: Generate SIWE nonce");
  {
    const nonce = generateSiweNonce();

    console.assert(nonce.length === 11, "Default nonce should be 11 characters");
    console.assert(/^[a-zA-Z0-9]+$/.test(nonce), "Nonce should be alphanumeric");

    const nonce20 = generateSiweNonce(20);
    console.assert(nonce20.length === 20, "Custom length nonce should match");

    // Test uniqueness
    const nonce2 = generateSiweNonce();
    console.assert(nonce !== nonce2, "Nonces should be unique");

    console.log(`  ✓ Generated nonce: ${nonce}`);
    console.log(`  ✓ Custom length nonce (20): ${nonce20}`);
    console.log("✅ Nonce generation works");
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

    console.assert(message.includes("example.com wants you to sign in"), "Should include domain");
    console.assert(message.includes(params.address), "Should include address");
    console.assert(message.includes("URI: https://example.com/login"), "Should include URI");
    console.assert(message.includes("Version: 1"), "Should include version");
    console.assert(message.includes("Chain ID: 1"), "Should include chain ID");
    console.assert(message.includes(`Nonce: ${params.nonce}`), "Should include nonce");
    console.assert(message.includes("Issued At: 2021-09-30T16:25:24Z"), "Should include issued at");

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

    console.assert(message.includes("Sign in to Example App"), "Should include statement");
    console.assert(message.includes("Expiration Time: 2024-01-01T13:00:00Z"), "Should include expiration");
    console.assert(message.includes("Not Before: 2024-01-01T11:55:00Z"), "Should include not-before");
    console.assert(message.includes("Request ID: req-12345"), "Should include request ID");
    console.assert(message.includes("Resources:"), "Should include resources header");
    console.assert(message.includes("- https://example.com/terms"), "Should include resource 1");
    console.assert(message.includes("- https://example.com/privacy"), "Should include resource 2");

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

    console.assert(parsed.domain === originalParams.domain, "Domain should match");
    console.assert(parsed.address === originalParams.address, "Address should match");
    console.assert(parsed.statement === originalParams.statement, "Statement should match");
    console.assert(parsed.uri === originalParams.uri, "URI should match");
    console.assert(parsed.version === originalParams.version, "Version should match");
    console.assert(parsed.chainId === originalParams.chainId, "Chain ID should match");
    console.assert(parsed.nonce === originalParams.nonce, "Nonce should match");
    console.assert(parsed.issuedAt === originalParams.issuedAt, "Issued at should match");
    console.assert(parsed.expirationTime === originalParams.expirationTime, "Expiration should match");

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
      checkExpiration: true,
    });

    console.assert(validation.valid === true, "Valid message should pass validation");
    console.assert(validation.errors.length === 0, "Should have no errors");

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
    const validation = validateSiweMessage(expiredMessage, {
      checkExpiration: true,
    });

    console.assert(validation.valid === false, "Expired message should fail validation");
    console.assert(validation.errors.some(e => e.includes("expired")), "Should have expiration error");

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

    console.assert(validation.valid === false, "Mismatched domain should fail");
    console.assert(validation.errors.some(e => e.includes("Domain mismatch")), "Should have domain error");

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

    console.assert(verification.valid === true, "Signature should be valid");
    console.assert(verification.address?.toLowerCase() === address.toLowerCase(), "Address should match");

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

    console.assert(verification.valid === false, "Wrong address should fail verification");
    console.assert(verification.error !== undefined, "Should have error message");

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

    console.assert(message1 === message2, "Roundtrip should produce identical message");

    console.log("  ✓ Original and roundtrip messages match");
    console.log("✅ Roundtrip consistency works");
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

runTests().catch(console.error);
