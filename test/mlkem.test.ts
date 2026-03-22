/**
 * ML-KEM Post-Quantum Encryption Tests
 * Tests for ML-KEM-1024 encryption, decryption, and deterministic key derivation
 *
 * NOTE: This file contains TEST FIXTURES only - not real secrets!
 * Test private key: Standard Ethereum test vector
 */

import {
  mlkemEncrypt,
  mlkemDecrypt,
  deriveMLKemKeypair,
  mlkemEncryptWithKey,
  mlkemDecryptWithKey,
} from '../src/crypto/mlkem';
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  logDetail,
  assert,
  assertEqual,
  assertTruthy,
  assertThrows,
} from './test-utils';

async function runTests() {
  startTestSuite('ML-KEM Post-Quantum Encryption Tests');

  // Test private keys (standard test vectors - NOT real keys!)
  const testPrivateKey1 = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const testPrivateKey2 = '0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';

  // Test 1: Deterministic Key Derivation
  await runTest('Derive ML-KEM keypair from Ethereum private key', async () => {
    const keypair1 = await deriveMLKemKeypair(testPrivateKey1, 'test-context');
    const keypair2 = await deriveMLKemKeypair(testPrivateKey1, 'test-context');

    // Same input should produce same output (deterministic)
    assertEqual(
      Buffer.from(keypair1.publicKey).toString('hex'),
      Buffer.from(keypair2.publicKey).toString('hex'),
      'Same private key + context should produce same public key'
    );
    assertEqual(
      Buffer.from(keypair1.privateKey).toString('hex'),
      Buffer.from(keypair2.privateKey).toString('hex'),
      'Same private key + context should produce same private key'
    );

    // Check key sizes
    assertEqual(keypair1.publicKey.length, 1568, 'ML-KEM-1024 public key should be 1568 bytes');
    assertEqual(keypair1.privateKey.length, 3168, 'ML-KEM-1024 private key should be 3168 bytes');

    passTest('Deterministic key derivation working correctly');
  });

  // Test 2: Context-based Domain Separation
  await runTest('Different contexts produce different keys', async () => {
    const keypair1 = await deriveMLKemKeypair(testPrivateKey1, 'context-1');
    const keypair2 = await deriveMLKemKeypair(testPrivateKey1, 'context-2');

    const pubKey1Hex = Buffer.from(keypair1.publicKey).toString('hex');
    const pubKey2Hex = Buffer.from(keypair2.publicKey).toString('hex');

    assert(
      pubKey1Hex !== pubKey2Hex,
      'Different contexts should produce different public keys'
    );

    passTest('Context-based domain separation working');
  });

  // Test 3: Single Recipient Encryption/Decryption
  await runTest('Single recipient encryption and decryption', async () => {
    const plaintext = 'This is a secret message for quantum-safe encryption testing';

    const keypair = await deriveMLKemKeypair(testPrivateKey1, 'test');

    // Encrypt
    const encrypted = await mlkemEncrypt(plaintext, keypair.publicKey);

    // Check payload structure
    assertEqual(encrypted.recipients.length, 1, 'Should have 1 recipient');
    assertTruthy(encrypted.encryptedData, 'Should have encrypted data');
    assertTruthy(encrypted.iv, 'Should have IV');
    assertTruthy(encrypted.authTag, 'Should have auth tag');

    // Decrypt
    const decrypted = await mlkemDecrypt(encrypted, keypair.privateKey, keypair.publicKey);

    assertEqual(decrypted, plaintext, 'Decrypted text should match original');

    passTest('Single recipient encryption/decryption successful');
  });

  // Test 4: Multi-Recipient Encryption
  await runTest('Multi-recipient encryption', async () => {
    const plaintext = 'Secret data for multiple recipients';

    const keypair1 = await deriveMLKemKeypair(testPrivateKey1, 'user1');
    const keypair2 = await deriveMLKemKeypair(testPrivateKey2, 'user2');

    // Encrypt for both recipients
    const encrypted = await mlkemEncrypt(plaintext, [keypair1.publicKey, keypair2.publicKey]);

    assertEqual(encrypted.recipients.length, 2, 'Should have 2 recipients');

    // Both recipients can decrypt
    const decrypted1 = await mlkemDecrypt(encrypted, keypair1.privateKey, keypair1.publicKey);
    const decrypted2 = await mlkemDecrypt(encrypted, keypair2.privateKey, keypair2.publicKey);

    assertEqual(decrypted1, plaintext, 'Recipient 1 should decrypt correctly');
    assertEqual(decrypted2, plaintext, 'Recipient 2 should decrypt correctly');

    passTest('Multi-recipient encryption working correctly');
  });

  // Test 5: Encrypt with Key (Convenience Function)
  await runTest('mlkemEncryptWithKey convenience function', async () => {
    const plaintext = 'Testing convenience function';

    const serverKeypair = await deriveMLKemKeypair(testPrivateKey2, 'server');

    // Encrypt using client's private key (client auto-added as recipient)
    const encrypted = await mlkemEncryptWithKey(
      plaintext,
      testPrivateKey1,
      [serverKeypair.publicKey],
      'client'
    );

    // Should have 2 recipients: client (auto-added) + server
    assertEqual(encrypted.recipients.length, 2, 'Should have 2 recipients (client + server)');

    // Client can decrypt
    const clientDecrypted = await mlkemDecryptWithKey(encrypted, testPrivateKey1, 'client');
    assertEqual(clientDecrypted, plaintext, 'Client should decrypt successfully');

    // Server can decrypt
    const serverDecrypted = await mlkemDecrypt(
      encrypted,
      serverKeypair.privateKey,
      serverKeypair.publicKey
    );
    assertEqual(serverDecrypted, plaintext, 'Server should decrypt successfully');

    passTest('Convenience functions working correctly');
  });

  // Test 6: Decryption with Public Key Hint (Faster Lookup)
  await runTest('Decrypt with public key hint for faster lookup', async () => {
    const plaintext = 'Testing with public key hint';

    const keypair1 = await deriveMLKemKeypair(testPrivateKey1, 'user1');
    const keypair2 = await deriveMLKemKeypair(testPrivateKey2, 'user2');

    const encrypted = await mlkemEncrypt(plaintext, [keypair1.publicKey, keypair2.publicKey]);

    // Decrypt with public key hint (faster than trying all recipients)
    const decrypted = await mlkemDecrypt(encrypted, keypair2.privateKey, keypair2.publicKey);

    assertEqual(decrypted, plaintext, 'Should decrypt with public key hint');

    passTest('Public key hint optimization working');
  });

  // Test 7: Wrong Private Key Should Fail
  await runTest('Decryption with wrong private key should fail', async () => {
    const plaintext = 'Secret message';

    const keypair1 = await deriveMLKemKeypair(testPrivateKey1, 'user1');
    const keypair2 = await deriveMLKemKeypair(testPrivateKey2, 'user2');

    const encrypted = await mlkemEncrypt(plaintext, keypair1.publicKey);

    let errorThrown = false;
    try {
      // Try to decrypt with wrong private key
      await mlkemDecrypt(encrypted, keypair2.privateKey, keypair2.publicKey);
    } catch (error) {
      errorThrown = true;
      logDetail('Expected error caught: ' + (error as Error).message);
    }

    assert(errorThrown, 'Should throw error when using wrong private key');

    passTest('Security validation working correctly');
  });

  // Test 8: Empty Plaintext
  await runTest('Encrypt and decrypt empty string', async () => {
    const plaintext = '';

    const keypair = await deriveMLKemKeypair(testPrivateKey1, 'test');

    const encrypted = await mlkemEncrypt(plaintext, keypair.publicKey);
    const decrypted = await mlkemDecrypt(encrypted, keypair.privateKey, keypair.publicKey);

    assertEqual(decrypted, plaintext, 'Empty string should encrypt/decrypt correctly');

    passTest('Empty plaintext handling working');
  });

  // Test 9: Large Plaintext
  await runTest('Encrypt and decrypt large plaintext', async () => {
    // Generate 10KB of test data
    const plaintext = 'A'.repeat(10000);

    const keypair = await deriveMLKemKeypair(testPrivateKey1, 'test');

    const encrypted = await mlkemEncrypt(plaintext, keypair.publicKey);
    const decrypted = await mlkemDecrypt(encrypted, keypair.privateKey, keypair.publicKey);

    assertEqual(decrypted, plaintext, 'Large plaintext should encrypt/decrypt correctly');
    assertEqual(decrypted.length, 10000, 'Decrypted length should match original');

    passTest('Large plaintext handling working');
  });

  // Test 10: Unicode and Special Characters
  await runTest('Encrypt and decrypt Unicode characters', async () => {
    const plaintext = '你好世界 🌍 Test émojis 🔐 Spëcîål çhãrs';

    const keypair = await deriveMLKemKeypair(testPrivateKey1, 'test');

    const encrypted = await mlkemEncrypt(plaintext, keypair.publicKey);
    const decrypted = await mlkemDecrypt(encrypted, keypair.privateKey, keypair.publicKey);

    assertEqual(decrypted, plaintext, 'Unicode characters should be preserved');

    passTest('Unicode handling working correctly');
  });

  // Test 11: Hex String vs Uint8Array Input
  await runTest('Accept both hex string and Uint8Array for private key', async () => {
    const hexKey = testPrivateKey1;
    const uint8Key = Buffer.from(hexKey.slice(2), 'hex');

    const keypair1 = await deriveMLKemKeypair(hexKey, 'test');
    const keypair2 = await deriveMLKemKeypair(uint8Key, 'test');

    assertEqual(
      Buffer.from(keypair1.publicKey).toString('hex'),
      Buffer.from(keypair2.publicKey).toString('hex'),
      'Hex and Uint8Array input should produce same result'
    );

    passTest('Input format flexibility working');
  });

  endTestSuite();
}

// Run tests
runTests().catch(error => {
  console.error('Test execution failed:', error);
  process.exit(1);
});
