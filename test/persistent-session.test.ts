/**
 * Tests for persistent session functionality
 */

import {
  PersistentSessionStorage,
  encryptMnemonicForPersistence,
  decryptMnemonicFromPersistence,
} from '../src/core/persistent-session';
import type { PersistentSessionData } from '../src/core/persistent-session';

console.log('\n==================================================');
console.log('🚀 Persistent Session Tests');
console.log('==================================================\n');

async function runTests() {
  // Check if running in browser environment
  if (typeof indexedDB === 'undefined') {
    console.log('  ℹ️  Skipped: IndexedDB not available (requires browser environment)');
    console.log('  ℹ️  Persistent session tests require a browser');
    console.log('  ℹ️  Run tests in browser or use test/webauthn-native.html\n');
    console.log('==================================================');
    console.log('✅ Test suite validated (skipped in Node.js)');
    console.log('==================================================\n');
    return;
  }

  const storage = new PersistentSessionStorage();
  const testAddress = '0x1234567890123456789012345678901234567890';
  const testMnemonic = 'test test test test test test test test test test test junk';
  const testCredentialId = 'test-credential-id';
  const testPublicKey = 'test-public-key';

  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, message: string) {
    if (condition) {
      passed++;
      console.log(`  ✅ ${message}`);
    } else {
      failed++;
      console.log(`  ❌ ${message}`);
    }
  }

  await storage.init();
  await storage.clear();

  // Test 1: Store and retrieve a persistent session
  console.log('Test 1: Store and retrieve a persistent session');
  try {
    const sessionData: PersistentSessionData = {
      encryptedMnemonic: 'encrypted-mnemonic-data',
      expiresAt: Date.now() + 1000 * 60 * 60, // 1 hour from now
      credentialId: testCredentialId,
      ethereumAddress: testAddress,
      securityMode: 'STANDARD',
      createdAt: Date.now(),
    };

    await storage.store(sessionData);
    const retrieved = await storage.retrieve(testAddress);

    assert(retrieved !== null, 'Session was stored and retrieved');
    assert(retrieved?.ethereumAddress === testAddress, 'Ethereum address matches');
    assert(retrieved?.credentialId === testCredentialId, 'Credential ID matches');
    assert(retrieved?.securityMode === 'STANDARD', 'Security mode is STANDARD');
  } catch (error) {
    console.log('  ❌ Error:', error);
    failed++;
  }
  console.log('');

  // Test 2: Prevent storing STRICT mode sessions
  console.log('Test 2: Prevent storing STRICT mode sessions');
  try {
    const sessionData: PersistentSessionData = {
      encryptedMnemonic: 'encrypted-mnemonic-data',
      expiresAt: Date.now() + 1000 * 60 * 60,
      credentialId: testCredentialId,
      ethereumAddress: testAddress,
      securityMode: 'STRICT',
      createdAt: Date.now(),
    };

    let errorThrown = false;
    try {
      await storage.store(sessionData);
    } catch (error: any) {
      errorThrown = error.message.includes('Cannot persist STRICT mode sessions');
    }

    assert(errorThrown, 'STRICT mode sessions are rejected');
  } catch (error) {
    console.log('  ❌ Error:', error);
    failed++;
  }
  console.log('');

  // Test 3: Allow storing YOLO mode sessions
  console.log('Test 3: Allow storing YOLO mode sessions');
  try {
    await storage.clear();
    const sessionData: PersistentSessionData = {
      encryptedMnemonic: 'encrypted-mnemonic-data',
      expiresAt: Date.now() + 1000 * 60 * 60,
      credentialId: testCredentialId,
      ethereumAddress: testAddress,
      securityMode: 'YOLO',
      createdAt: Date.now(),
    };

    await storage.store(sessionData);
    const retrieved = await storage.retrieve(testAddress);

    assert(retrieved !== null, 'YOLO session was stored');
    assert(retrieved?.securityMode === 'YOLO', 'Security mode is YOLO');
  } catch (error) {
    console.log('  ❌ Error:', error);
    failed++;
  }
  console.log('');

  // Test 4: Return null for expired sessions
  console.log('Test 4: Return null for expired sessions');
  try {
    await storage.clear();
    const sessionData: PersistentSessionData = {
      encryptedMnemonic: 'encrypted-mnemonic-data',
      expiresAt: Date.now() - 1000, // Expired 1 second ago
      credentialId: testCredentialId,
      ethereumAddress: testAddress,
      securityMode: 'STANDARD',
      createdAt: Date.now() - 10000,
    };

    await storage.store(sessionData);
    const retrieved = await storage.retrieve(testAddress);

    assert(retrieved === null, 'Expired session returns null');
  } catch (error) {
    console.log('  ❌ Error:', error);
    failed++;
  }
  console.log('');

  // Test 5: Delete a session
  console.log('Test 5: Delete a session');
  try {
    await storage.clear();
    const sessionData: PersistentSessionData = {
      encryptedMnemonic: 'encrypted-mnemonic-data',
      expiresAt: Date.now() + 1000 * 60 * 60,
      credentialId: testCredentialId,
      ethereumAddress: testAddress,
      securityMode: 'STANDARD',
      createdAt: Date.now(),
    };

    await storage.store(sessionData);
    await storage.delete(testAddress);
    const retrieved = await storage.retrieve(testAddress);

    assert(retrieved === null, 'Session was deleted');
  } catch (error) {
    console.log('  ❌ Error:', error);
    failed++;
  }
  console.log('');

  // Test 6: Encrypt and decrypt mnemonic
  console.log('Test 6: Encrypt and decrypt mnemonic');
  try {
    const encrypted = await encryptMnemonicForPersistence(
      testMnemonic,
      testCredentialId,
      testPublicKey
    );

    assert(encrypted.length > 0, 'Mnemonic was encrypted');
    assert(encrypted !== testMnemonic, 'Encrypted mnemonic is different from original');

    const decrypted = await decryptMnemonicFromPersistence(
      encrypted,
      testCredentialId,
      testPublicKey
    );

    assert(decrypted === testMnemonic, 'Decrypted mnemonic matches original');
  } catch (error) {
    console.log('  ❌ Error:', error);
    failed++;
  }
  console.log('');

  // Test 7: Fail to decrypt with wrong credential ID
  console.log('Test 7: Fail to decrypt with wrong credential ID');
  try {
    const encrypted = await encryptMnemonicForPersistence(
      testMnemonic,
      testCredentialId,
      testPublicKey
    );

    let errorThrown = false;
    try {
      await decryptMnemonicFromPersistence(encrypted, 'wrong-credential-id', testPublicKey);
    } catch (error) {
      errorThrown = true;
    }

    assert(errorThrown, 'Decryption fails with wrong credential ID');
  } catch (error) {
    console.log('  ❌ Error:', error);
    failed++;
  }
  console.log('');

  // Test 8: Fail to decrypt with wrong public key
  console.log('Test 8: Fail to decrypt with wrong public key');
  try {
    const encrypted = await encryptMnemonicForPersistence(
      testMnemonic,
      testCredentialId,
      testPublicKey
    );

    let errorThrown = false;
    try {
      await decryptMnemonicFromPersistence(encrypted, testCredentialId, 'wrong-public-key');
    } catch (error) {
      errorThrown = true;
    }

    assert(errorThrown, 'Decryption fails with wrong public key');
  } catch (error) {
    console.log('  ❌ Error:', error);
    failed++;
  }
  console.log('');

  // Clean up
  await storage.clear();

  // Summary
  console.log('==================================================');
  console.log(`✅ Persistent Session Tests: ${passed} passed, ${failed} failed`);
  console.log('==================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(console.error);
