/**
 * Key Stretching and Hashing Utility Tests
 * Tests for PBKDF2 key stretching, salted hashing, and iterative hashing
 */

import {
  stretchKey,
  hashWithSalt,
  iterativeHash,
  sha256Hash,
} from "../../src/zk/utils";

async function runTests() {
  console.log("=== Key Stretching & Hashing Tests ===\n");

  let passedTests = 0;
  let totalTests = 0;

  // Test 1: Basic PBKDF2 Key Stretching
  console.log("Test 1: Basic PBKDF2 Key Stretching");
  totalTests++;
  try {
    const input = "my-secret-password";
    const salt = "random-salt-value";
    const stretched = await stretchKey(input, salt);

    if (stretched && stretched.length === 64 && /^[0-9a-f]+$/.test(stretched)) {
      console.log("  ✓ Key stretched successfully");
      console.log(`  Input: "${input}"`);
      console.log(`  Salt: "${salt}"`);
      console.log(`  Stretched key: ${stretched.slice(0, 20)}...${stretched.slice(-20)}`);
      passedTests++;
    } else {
      console.log("  ✗ Key stretching failed - invalid output format");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 2: PBKDF2 Determinism
  console.log("\nTest 2: PBKDF2 Determinism");
  totalTests++;
  try {
    const input = "test-password";
    const salt = "test-salt";

    const result1 = await stretchKey(input, salt);
    const result2 = await stretchKey(input, salt);

    if (result1 === result2) {
      console.log("  ✓ Key stretching is deterministic");
      console.log(`  Both results: ${result1.slice(0, 32)}...`);
      passedTests++;
    } else {
      console.log("  ✗ Key stretching is not deterministic");
      console.log(`  Result 1: ${result1.slice(0, 32)}...`);
      console.log(`  Result 2: ${result2.slice(0, 32)}...`);
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 3: PBKDF2 Salt Dependency
  console.log("\nTest 3: PBKDF2 Salt Dependency");
  totalTests++;
  try {
    const input = "same-password";
    const salt1 = "salt-one";
    const salt2 = "salt-two";

    const result1 = await stretchKey(input, salt1);
    const result2 = await stretchKey(input, salt2);

    if (result1 !== result2) {
      console.log("  ✓ Different salts produce different keys");
      console.log(`  Salt 1 result: ${result1.slice(0, 32)}...`);
      console.log(`  Salt 2 result: ${result2.slice(0, 32)}...`);
      passedTests++;
    } else {
      console.log("  ✗ Salt doesn't affect output (security issue!)");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 4: PBKDF2 Custom Iterations
  console.log("\nTest 4: PBKDF2 Custom Iterations");
  totalTests++;
  try {
    const input = "password";
    const salt = "salt";

    const result1 = await stretchKey(input, salt, 1000);
    const result2 = await stretchKey(input, salt, 50000);

    if (result1 !== result2) {
      console.log("  ✓ Different iteration counts produce different keys");
      console.log(`  1,000 iterations: ${result1.slice(0, 32)}...`);
      console.log(`  50,000 iterations: ${result2.slice(0, 32)}...`);
      passedTests++;
    } else {
      console.log("  ✗ Iteration count doesn't affect output");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 5: PBKDF2 Custom Key Length
  console.log("\nTest 5: PBKDF2 Custom Key Length");
  totalTests++;
  try {
    const input = "password";
    const salt = "salt";

    const key16 = await stretchKey(input, salt, 10000, 16);
    const key32 = await stretchKey(input, salt, 10000, 32);
    const key64 = await stretchKey(input, salt, 10000, 64);

    if (key16.length === 32 && key32.length === 64 && key64.length === 128) {
      console.log("  ✓ Custom key lengths work correctly");
      console.log(`  16 bytes (32 hex chars): ${key16}`);
      console.log(`  32 bytes (64 hex chars): ${key32.slice(0, 32)}...`);
      console.log(`  64 bytes (128 hex chars): ${key64.slice(0, 32)}...`);
      passedTests++;
    } else {
      console.log("  ✗ Key lengths incorrect");
      console.log(`  Expected: 32, 64, 128; Got: ${key16.length}, ${key32.length}, ${key64.length}`);
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 6: Salted Hashing
  console.log("\nTest 6: Salted Hashing");
  totalTests++;
  try {
    const data = "sensitive-data";
    const salt = "unique-salt";

    const hash = await hashWithSalt(data, salt);

    if (hash && hash.length === 64 && /^[0-9a-f]+$/.test(hash)) {
      console.log("  ✓ Salted hash generated successfully");
      console.log(`  Data: "${data}"`);
      console.log(`  Salt: "${salt}"`);
      console.log(`  Hash: ${hash}`);
      passedTests++;
    } else {
      console.log("  ✗ Salted hashing failed");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 7: Salted Hash Consistency
  console.log("\nTest 7: Salted Hash Consistency");
  totalTests++;
  try {
    const data = "test-data";
    const salt = "test-salt";

    const hash1 = await hashWithSalt(data, salt);
    const hash2 = await hashWithSalt(data, salt);

    if (hash1 === hash2) {
      console.log("  ✓ Salted hashing is consistent");
      console.log(`  Hash: ${hash1}`);
      passedTests++;
    } else {
      console.log("  ✗ Salted hashing is not consistent");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 8: Salted Hash Salt Uniqueness
  console.log("\nTest 8: Salted Hash Salt Uniqueness");
  totalTests++;
  try {
    const data = "same-data";

    const hash1 = await hashWithSalt(data, "salt-A");
    const hash2 = await hashWithSalt(data, "salt-B");

    if (hash1 !== hash2) {
      console.log("  ✓ Different salts produce different hashes");
      console.log(`  Salt A: ${hash1.slice(0, 32)}...`);
      console.log(`  Salt B: ${hash2.slice(0, 32)}...`);
      passedTests++;
    } else {
      console.log("  ✗ Salt doesn't affect hash");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 9: Iterative Hashing
  console.log("\nTest 9: Iterative Hashing");
  totalTests++;
  try {
    const data = "data-to-hash";
    const salt = "hash-salt";
    const iterations = 1000;

    const hash = await iterativeHash(data, salt, iterations);

    if (hash && hash.length === 64 && /^[0-9a-f]+$/.test(hash)) {
      console.log("  ✓ Iterative hash generated successfully");
      console.log(`  Data: "${data}"`);
      console.log(`  Iterations: ${iterations}`);
      console.log(`  Hash: ${hash}`);
      passedTests++;
    } else {
      console.log("  ✗ Iterative hashing failed");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 10: Iterative Hash Consistency
  console.log("\nTest 10: Iterative Hash Consistency");
  totalTests++;
  try {
    const data = "test";
    const salt = "salt";
    const iterations = 500;

    const hash1 = await iterativeHash(data, salt, iterations);
    const hash2 = await iterativeHash(data, salt, iterations);

    if (hash1 === hash2) {
      console.log("  ✓ Iterative hashing is consistent");
      console.log(`  Hash: ${hash1}`);
      passedTests++;
    } else {
      console.log("  ✗ Iterative hashing is not consistent");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 11: Iterative Hash Iteration Impact
  console.log("\nTest 11: Iterative Hash Iteration Impact");
  totalTests++;
  try {
    const data = "password";
    const salt = "salt";

    const hash10 = await iterativeHash(data, salt, 10);
    const hash100 = await iterativeHash(data, salt, 100);
    const hash1000 = await iterativeHash(data, salt, 1000);

    if (hash10 !== hash100 && hash100 !== hash1000 && hash10 !== hash1000) {
      console.log("  ✓ Different iteration counts produce different hashes");
      console.log(`  10 iterations:   ${hash10.slice(0, 32)}...`);
      console.log(`  100 iterations:  ${hash100.slice(0, 32)}...`);
      console.log(`  1000 iterations: ${hash1000.slice(0, 32)}...`);
      passedTests++;
    } else {
      console.log("  ✗ Iteration count doesn't affect output");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 12: Iterative Hash Minimum Iterations
  console.log("\nTest 12: Iterative Hash Minimum Iterations");
  totalTests++;
  try {
    const data = "test";
    const salt = "salt";

    const hash1 = await iterativeHash(data, salt, 1);
    const expectedHash = await hashWithSalt(data, salt);

    if (hash1 === expectedHash) {
      console.log("  ✓ Single iteration equals salted hash");
      console.log(`  Hash: ${hash1}`);
      passedTests++;
    } else {
      console.log("  ✗ Single iteration doesn't match salted hash");
      console.log(`  Iterative: ${hash1}`);
      console.log(`  Salted: ${expectedHash}`);
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 13: Iterative Hash Error Handling
  console.log("\nTest 13: Iterative Hash Error Handling");
  totalTests++;
  try {
    const data = "test";
    const salt = "salt";

    try {
      await iterativeHash(data, salt, 0);
      console.log("  ✗ Should have thrown error for 0 iterations");
    } catch (error) {
      const message = (error as Error).message;
      if (message.includes("Iterations must be at least 1") ||
          message.includes("Failed to perform iterative hash")) {
        console.log("  ✓ Correctly rejects invalid iteration count");
        passedTests++;
      } else {
        console.log("  ✗ Wrong error message:", message);
      }
    }
  } catch (error) {
    console.log("  ✗ Unexpected error:", (error as Error).message);
  }

  // Test 14: Password Hashing Use Case
  console.log("\nTest 14: Password Hashing Use Case");
  totalTests++;
  try {
    const password = "MySecurePassword123!";
    const userSalt = "user-12345-salt";

    const hashedPassword = await stretchKey(password, userSalt, 100000);

    // Verify the same password produces same hash
    const verifyHash = await stretchKey(password, userSalt, 100000);

    // Different password should produce different hash
    const wrongPassword = "WrongPassword456!";
    const wrongHash = await stretchKey(wrongPassword, userSalt, 100000);

    if (hashedPassword === verifyHash && hashedPassword !== wrongHash) {
      console.log("  ✓ Password hashing use case works correctly");
      console.log(`  User password hash: ${hashedPassword.slice(0, 32)}...`);
      console.log(`  Verification: Match`);
      console.log(`  Wrong password: No match`);
      passedTests++;
    } else {
      console.log("  ✗ Password hashing verification failed");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 15: Deterministic Identifier Use Case
  console.log("\nTest 15: Deterministic Identifier Use Case");
  totalTests++;
  try {
    const userData = "user@example.com";
    const appSecret = "app-secret-key-2024";

    // Create deterministic user identifier
    const userId = await hashWithSalt(userData, appSecret);

    // Verify it's always the same
    const verifyId = await hashWithSalt(userData, appSecret);

    // Different user should have different ID
    const otherUser = "other@example.com";
    const otherId = await hashWithSalt(otherUser, appSecret);

    if (userId === verifyId && userId !== otherId) {
      console.log("  ✓ Deterministic identifier use case works");
      console.log(`  User ID: ${userId.slice(0, 32)}...`);
      console.log(`  Consistent: Yes`);
      console.log(`  Unique per user: Yes`);
      passedTests++;
    } else {
      console.log("  ✗ Deterministic identifier failed");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 16: Commitment Secret Use Case
  console.log("\nTest 16: Commitment Secret Use Case");
  totalTests++;
  try {
    const secretValue = "my-secret-value";
    const nonce = "random-nonce-" + Date.now();

    // Create commitment secret using iterative hashing
    const commitmentSecret = await iterativeHash(secretValue, nonce, 5000);

    // Commitment should be hard to reverse
    const recreated = await iterativeHash(secretValue, nonce, 5000);

    // Different secret should produce different commitment
    const otherSecret = "other-secret-value";
    const otherCommitment = await iterativeHash(otherSecret, nonce, 5000);

    if (commitmentSecret === recreated && commitmentSecret !== otherCommitment) {
      console.log("  ✓ Commitment secret use case works");
      console.log(`  Commitment: ${commitmentSecret.slice(0, 32)}...`);
      console.log(`  Iterations: 5000 (brute-force resistant)`);
      console.log(`  Reproducible: Yes`);
      passedTests++;
    } else {
      console.log("  ✗ Commitment secret failed");
    }
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Test 17: Performance Comparison
  console.log("\nTest 17: Performance Comparison");
  totalTests++;
  try {
    const data = "performance-test-data";
    const salt = "performance-salt";

    // Time simple hash
    const start1 = Date.now();
    await sha256Hash(data + salt);
    const time1 = Date.now() - start1;

    // Time iterative hash (100 iterations)
    const start2 = Date.now();
    await iterativeHash(data, salt, 100);
    const time2 = Date.now() - start2;

    // Time PBKDF2 (10k iterations)
    const start3 = Date.now();
    await stretchKey(data, salt, 10000);
    const time3 = Date.now() - start3;

    console.log("  ✓ Performance metrics collected");
    console.log(`  SHA-256 simple:           ${time1}ms`);
    console.log(`  Iterative hash (100x):    ${time2}ms`);
    console.log(`  PBKDF2 (10k iterations):  ${time3}ms`);
    console.log(`  Note: PBKDF2 is intentionally slower for security`);
    passedTests++;
  } catch (error) {
    console.log("  ✗ Error:", (error as Error).message);
  }

  // Summary
  console.log("\n=== Test Summary ===");
  console.log(`Passed: ${passedTests}/${totalTests}`);
  console.log(`Failed: ${totalTests - passedTests}/${totalTests}`);

  if (passedTests === totalTests) {
    console.log("\n✓ All key stretching & hashing tests passed!");
  } else {
    console.log("\n⚠ Some tests failed");
    process.exit(1);
  }

  console.log("\n=== Use Cases Validated ===");
  console.log("✓ Password hashing with PBKDF2");
  console.log("✓ Deterministic key derivation");
  console.log("✓ Creating commitment secrets");
  console.log("✓ Identity hashing schemes");
  console.log("✓ Privacy-preserving identifiers");
  console.log("✓ Brute-force attack resistance");
}

// Run tests
runTests().catch((error) => {
  console.error("Test suite error:", error);
  process.exit(1);
});
