/**
 * Tests for persistent session functionality
 *
 * Persistent sessions are encrypted under a key derived from the WebAuthn
 * PRF extension output. The PRF/crypto tests run everywhere (Node has
 * WebCrypto); the IndexedDB storage tests require a browser.
 */

import { PersistentSessionStorage } from '../src/core/persistent-session';
import type { PersistentSessionData } from '../src/core/persistent-session';
import { derivePrfSessionKey, PRF_INPUT, encryptData, decryptData } from '../src/wallet/crypto';

console.log('\n==================================================');
console.log('🚀 Persistent Session Tests');
console.log('==================================================\n');

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

const testMnemonic = 'test test test test test test test test test test test junk';

/** Simulate an authenticator PRF output: 32 random bytes */
function fakePrfOutput(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * PRF-derived session key tests (run in Node and browser)
 */
async function runPrfCryptoTests() {
  // Test A: PRF input is fixed — the whole design depends on determinism
  console.log('Test A: PRF input constant');
  assert(PRF_INPUT.length > 0, 'PRF input is non-empty');
  assert(
    new TextDecoder().decode(PRF_INPUT) === 'w3pk-prf-input-v1',
    'PRF input is the fixed versioned constant (deterministic across assertions)'
  );
  console.log('');

  // Test B: Encrypt/decrypt roundtrip with a PRF-derived key
  console.log('Test B: Encrypt and decrypt mnemonic with PRF-derived key');
  const prfOutput = fakePrfOutput();
  const key = await derivePrfSessionKey(prfOutput);

  const encrypted = await encryptData(testMnemonic, key);
  assert(encrypted.length > 0, 'Mnemonic was encrypted');
  assert(encrypted !== testMnemonic, 'Encrypted mnemonic differs from original');

  const decrypted = await decryptData(encrypted, key);
  assert(decrypted === testMnemonic, 'Decrypted mnemonic matches original');
  console.log('');

  // Test C: Same PRF output derives an equivalent key (renewal decrypts old blob)
  console.log('Test C: Key derivation is deterministic per PRF output');
  const keyAgain = await derivePrfSessionKey(prfOutput);
  const decryptedWithRederived = await decryptData(encrypted, keyAgain);
  assert(
    decryptedWithRederived === testMnemonic,
    'Key re-derived from the same PRF output decrypts the existing blob'
  );
  console.log('');

  // Test D: A different PRF output cannot decrypt
  console.log('Test D: Wrong PRF output fails to decrypt');
  const wrongKey = await derivePrfSessionKey(fakePrfOutput());
  let errorThrown = false;
  try {
    await decryptData(encrypted, wrongKey);
  } catch {
    errorThrown = true;
  }
  assert(errorThrown, 'Decryption fails with a key from a different PRF output');
  console.log('');

  // Test E: Derived key is non-extractable
  console.log('Test E: Session key is non-extractable');
  assert(key.extractable === false, 'CryptoKey is non-extractable');
  let exportFailed = false;
  try {
    await crypto.subtle.exportKey('raw', key);
  } catch {
    exportFailed = true;
  }
  assert(exportFailed, 'exportKey on the session key throws');
  console.log('');

  // Test F: PRF output length is validated
  console.log('Test F: PRF output length validation');
  let lengthErrorThrown = false;
  try {
    await derivePrfSessionKey(new Uint8Array(16));
  } catch {
    lengthErrorThrown = true;
  }
  assert(lengthErrorThrown, 'Non-32-byte PRF output is rejected');
  console.log('');
}

/**
 * IndexedDB storage tests (browser only)
 */
async function runStorageTests() {
  if (typeof indexedDB === 'undefined') {
    console.log('  ℹ️  Storage tests skipped: IndexedDB not available (requires browser environment)');
    console.log('  ℹ️  Run in browser or use test/webauthn-native.html\n');
    return;
  }

  const storage = new PersistentSessionStorage();
  const testAddress = '0x1234567890123456789012345678901234567890';
  const testCredentialId = 'test-credential-id';
  const sessionKey = await derivePrfSessionKey(fakePrfOutput());
  const encryptedMnemonic = await encryptData(testMnemonic, sessionKey);

  await storage.init();
  await storage.clear();

  // Test 1: Store and retrieve a persistent session (silent-restore flavor)
  console.log('Test 1: Store and retrieve a persistent session');
  try {
    const sessionData: PersistentSessionData = {
      encryptedMnemonic,
      sessionKey,
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
    assert(retrieved?.sessionKey instanceof CryptoKey, 'Stored CryptoKey survives the roundtrip');
    assert(retrieved?.sessionKey?.extractable === false, 'Stored key is still non-extractable');

    if (retrieved?.sessionKey) {
      const decrypted = await decryptData(retrieved.encryptedMnemonic, retrieved.sessionKey);
      assert(decrypted === testMnemonic, 'Blob decrypts with the stored key (silent restore)');
    }
  } catch (error) {
    console.log('  ❌ Error:', error);
    failed++;
  }
  console.log('');

  // Test 2: Prevent storing STRICT mode sessions
  console.log('Test 2: Prevent storing STRICT mode sessions');
  try {
    const sessionData: PersistentSessionData = {
      encryptedMnemonic,
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

  // Test 3: requireReauth records carry no session key
  console.log('Test 3: requireReauth records store no key');
  try {
    await storage.clear();
    const sessionData: PersistentSessionData = {
      encryptedMnemonic,
      // sessionKey deliberately absent: decryption requires a fresh assertion
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
    assert(retrieved?.sessionKey === undefined, 'No key on disk — blob is hardware-bound');
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
      encryptedMnemonic,
      sessionKey,
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
      encryptedMnemonic,
      sessionKey,
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

  // Clean up
  await storage.clear();
}

async function runTests() {
  await runPrfCryptoTests();
  await runStorageTests();

  // Summary
  console.log('==================================================');
  console.log(`✅ Persistent Session Tests: ${passed} passed, ${failed} failed`);
  console.log('==================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error('Test run crashed:', error);
  process.exit(1);
});
