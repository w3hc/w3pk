/**
 * ML-KEM Post-Quantum Encryption Tests
 * Tests for hybrid ML-KEM-1024 + X25519 HPKE encryption, decryption, and deterministic key derivation
 *
 * NOTE: This file contains TEST FIXTURES only - not real secrets!
 */

import {
  mlkemEncrypt,
  mlkemDecrypt,
  deriveMLKemKeypair,
  mlkemEncryptWithKey,
  mlkemDecryptWithKey,
  hpkeKeySchedule,
} from '../src/crypto/mlkem';
import { bip39Seed, deriveMLKemPublicKey } from '../src/core/mlkem';
import { getOriginSpecificAddress } from '../src/wallet/origin-derivation';
import { deriveWalletFromPath } from '../src/wallet/generate';
import { Mnemonic, getBytes } from 'ethers';
import { extract, expand } from '@noble/hashes/hkdf.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { createMlKem1024 } from 'mlkem';
import { x25519 } from '@noble/curves/ed25519.js';
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

  const testSeed1 = new Uint8Array(64).map((_, i) => i);
  const testSeed2 = new Uint8Array(64).map((_, i) => 255 - i);
  const origin = 'https://example.com';
  const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

  // Test 1: Deterministic Key Derivation
  await runTest('Derive ML-KEM keypair from a BIP-39 seed', async () => {
    const keypair1 = await deriveMLKemKeypair(testSeed1, { origin, context: 'test-context' });
    const keypair2 = await deriveMLKemKeypair(testSeed1, { origin, context: 'test-context' });

    // Same input should produce same output (deterministic)
    assertEqual(
      Buffer.from(keypair1.publicKey).toString('hex'),
      Buffer.from(keypair2.publicKey).toString('hex'),
      'Same seed + options should produce same public key'
    );
    assertEqual(
      Buffer.from(keypair1.privateKey).toString('hex'),
      Buffer.from(keypair2.privateKey).toString('hex'),
      'Same seed + options should produce same private key'
    );

    // Check key sizes
    assertEqual(keypair1.publicKey.length, 1600, 'Hybrid public key should be 1568 + 32 bytes');
    assertEqual(keypair1.privateKey.length, 3200, 'Hybrid private key should be 3168 + 32 bytes');

    passTest('Deterministic key derivation working correctly');
  });

  // Test 2: Context-based Domain Separation
  await runTest('Different contexts produce different keys', async () => {
    const keypair1 = await deriveMLKemKeypair(testSeed1, { origin, context: 'context-1' });
    const keypair2 = await deriveMLKemKeypair(testSeed1, { origin, context: 'context-2' });

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

    const keypair = await deriveMLKemKeypair(testSeed1, { origin, context: 'test' });

    // Encrypt
    const encrypted = await mlkemEncrypt(plaintext, keypair.publicKey);

    // Check payload structure
    assertEqual(encrypted.recipients.length, 1, 'Should have 1 recipient');
    assertTruthy(encrypted.encryptedData, 'Should have encrypted data');
    assertTruthy(encrypted.iv, 'Should have IV');
    assertTruthy(encrypted.authTag, 'Should have auth tag');

    // Decrypt
    const decrypted = await mlkemDecrypt(encrypted, keypair.privateKey);

    assertEqual(decrypted, plaintext, 'Decrypted text should match original');

    passTest('Single recipient encryption/decryption successful');
  });

  // Test 4: Multi-Recipient Encryption
  await runTest('Multi-recipient encryption', async () => {
    const plaintext = 'Secret data for multiple recipients';

    const keypair1 = await deriveMLKemKeypair(testSeed1, { origin, context: 'user1' });
    const keypair2 = await deriveMLKemKeypair(testSeed2, { origin, context: 'user2' });

    // Encrypt for both recipients
    const encrypted = await mlkemEncrypt(plaintext, [keypair1.publicKey, keypair2.publicKey]);

    assertEqual(encrypted.recipients.length, 2, 'Should have 2 recipients');

    // Both recipients can decrypt
    const decrypted1 = await mlkemDecrypt(encrypted, keypair1.privateKey);
    const decrypted2 = await mlkemDecrypt(encrypted, keypair2.privateKey);

    assertEqual(decrypted1, plaintext, 'Recipient 1 should decrypt correctly');
    assertEqual(decrypted2, plaintext, 'Recipient 2 should decrypt correctly');

    passTest('Multi-recipient encryption working correctly');
  });

  // Test 5: Encrypt with Key (Convenience Function)
  await runTest('mlkemEncryptWithKey convenience function', async () => {
    const plaintext = 'Testing convenience function';

    const serverKeypair = await deriveMLKemKeypair(testSeed2, { origin, context: 'server' });

    // Encrypt using client's private key (client auto-added as recipient)
    const encrypted = await mlkemEncryptWithKey(
      plaintext,
      testSeed1,
      [serverKeypair.publicKey],
      { origin, context: 'client' }
    );

    // Should have 2 recipients: client (auto-added) + server
    assertEqual(encrypted.recipients.length, 2, 'Should have 2 recipients (client + server)');

    // Client can decrypt
    const clientDecrypted = await mlkemDecryptWithKey(encrypted, testSeed1, { origin, context: 'client' });
    assertEqual(clientDecrypted, plaintext, 'Client should decrypt successfully');

    // Server can decrypt
    const serverDecrypted = await mlkemDecrypt(encrypted, serverKeypair.privateKey);
    assertEqual(serverDecrypted, plaintext, 'Server should decrypt successfully');

    passTest('Convenience functions working correctly');
  });

  // Test 7: Wrong Private Key Should Fail
  await runTest('Decryption with wrong private key should fail', async () => {
    const plaintext = 'Secret message';

    const keypair1 = await deriveMLKemKeypair(testSeed1, { origin, context: 'user1' });
    const keypair2 = await deriveMLKemKeypair(testSeed2, { origin, context: 'user2' });

    const encrypted = await mlkemEncrypt(plaintext, keypair1.publicKey);

    let errorThrown = false;
    try {
      // Try to decrypt with wrong private key
      await mlkemDecrypt(encrypted, keypair2.privateKey);
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

    const keypair = await deriveMLKemKeypair(testSeed1, { origin, context: 'test' });

    const encrypted = await mlkemEncrypt(plaintext, keypair.publicKey);
    const decrypted = await mlkemDecrypt(encrypted, keypair.privateKey);

    assertEqual(decrypted, plaintext, 'Empty string should encrypt/decrypt correctly');

    passTest('Empty plaintext handling working');
  });

  // Test 9: Large Plaintext
  await runTest('Encrypt and decrypt large plaintext', async () => {
    // Generate 10KB of test data
    const plaintext = 'A'.repeat(10000);

    const keypair = await deriveMLKemKeypair(testSeed1, { origin, context: 'test' });

    const encrypted = await mlkemEncrypt(plaintext, keypair.publicKey);
    const decrypted = await mlkemDecrypt(encrypted, keypair.privateKey);

    assertEqual(decrypted, plaintext, 'Large plaintext should encrypt/decrypt correctly');
    assertEqual(decrypted.length, 10000, 'Decrypted length should match original');

    passTest('Large plaintext handling working');
  });

  // Test 10: Unicode and Special Characters
  await runTest('Encrypt and decrypt Unicode characters', async () => {
    const plaintext = '你好世界 🌍 Test émojis 🔐 Spëcîål çhãrs';

    const keypair = await deriveMLKemKeypair(testSeed1, { origin, context: 'test' });

    const encrypted = await mlkemEncrypt(plaintext, keypair.publicKey);
    const decrypted = await mlkemDecrypt(encrypted, keypair.privateKey);

    assertEqual(decrypted, plaintext, 'Unicode characters should be preserved');

    passTest('Unicode handling working correctly');
  });

  const rejectionOf = async (fn: () => Promise<unknown>): Promise<Error> => {
    try {
      await fn();
    } catch (error) {
      return error as Error;
    }
    throw new Error('Expected promise to reject');
  };

  await runTest('Origin, mode, tag and context each separate the keys', async () => {
    const base = await deriveMLKemKeypair(testSeed1, { origin });
    const variants = await Promise.all([
      deriveMLKemKeypair(testSeed1, { origin: 'https://other.example.com' }),
      deriveMLKemKeypair(testSeed1, { origin, mode: 'STRICT' }),
      deriveMLKemKeypair(testSeed1, { origin, mode: 'YOLO' }),
      deriveMLKemKeypair(testSeed1, { origin, tag: 'GAMING' }),
      deriveMLKemKeypair(testSeed1, { origin, context: 'other' }),
      deriveMLKemKeypair(testSeed2, { origin }),
    ]);
    const publicKeys = new Set([base, ...variants].map(k => hex(k.publicKey)));
    assertEqual(publicKeys.size, variants.length + 1, 'Every variant gives a distinct public key');

    const xKeys = new Set([base, ...variants].map(k => hex(k.publicKey.subarray(1568))));
    assertEqual(xKeys.size, variants.length + 1, 'Every variant gives a distinct X25519 key');

    passTest('Origin, mode, tag and context separation working');
  });

  await runTest('Field boundaries are unambiguous', async () => {
    const a = await deriveMLKemKeypair(testSeed1, { origin, tag: 'AB', context: 'c' });
    const b = await deriveMLKemKeypair(testSeed1, { origin, tag: 'A', context: 'Bc' });
    assert(hex(a.publicKey) !== hex(b.publicKey), 'Shifting a byte between tag and context changes the key');

    passTest('Length-prefixed info fields');
  });

  await runTest('Defaults and normalization match origin-specific addresses', async () => {
    const explicit = await deriveMLKemKeypair(testSeed1, {
      origin,
      mode: 'STANDARD',
      tag: 'MAIN',
      context: 'mlkem-v1',
    });
    const defaults = await deriveMLKemKeypair(testSeed1, { origin });
    assertEqual(hex(defaults.publicKey), hex(explicit.publicKey), 'Defaults are STANDARD, MAIN, mlkem-v1');

    const unnormalized = await deriveMLKemKeypair(testSeed1, { origin: 'HTTPS://Example.com:443/path', tag: 'main' });
    assertEqual(hex(unnormalized.publicKey), hex(explicit.publicKey), 'Origin normalized, tag uppercased');

    passTest('Defaults and normalization consistent');
  });

  await runTest('Keys come from the seed through HKDF only', async () => {
    const enc = new TextEncoder();
    const field = (value: string) => {
      const bytes = enc.encode(value);
      const out = new Uint8Array(4 + bytes.length);
      new DataView(out.buffer).setUint32(0, bytes.length, false);
      out.set(bytes, 4);
      return out;
    };
    const info = (purpose: string) =>
      Buffer.concat([purpose, origin, 'STANDARD', 'MAIN', 'mlkem-v1'].map(field));

    const prk = extract(sha256, testSeed1, enc.encode('w3pk-kem-keypair-v4'));
    const mlkem = await createMlKem1024();
    const [pkM] = mlkem.deriveKeyPair(expand(sha256, prk, info('ml-kem-1024'), 64));
    const pkX = x25519.getPublicKey(expand(sha256, prk, info('x25519'), 32));

    const keypair = await deriveMLKemKeypair(testSeed1, { origin });
    assertEqual(hex(keypair.publicKey), hex(Buffer.concat([pkM, pkX])), 'Matches the documented HKDF derivation');

    passTest('Derivation reproduced from the seed alone');
  });

  await runTest('BIP-39 seed matches ethers and the SDK no longer uses the signing key', async () => {
    const mnemonic = 'test test test test test test test test test test test junk';
    const seed = bip39Seed(mnemonic);
    assertEqual(hex(seed), Mnemonic.fromPhrase(mnemonic).computeSeed().slice(2), 'Seed matches ethers computeSeed');

    const previousWindow = (globalThis as any).window;
    (globalThis as any).window = { location: { origin } };
    try {
      const ctx = {
        currentUser: {} as any,
        getMnemonicFromSession: async () => mnemonic,
      };
      const sdkKey = await deriveMLKemPublicKey(ctx, { tag: 'main' });
      const expected = await deriveMLKemKeypair(getBytes(Mnemonic.fromPhrase(mnemonic).computeSeed()), { origin });
      assertEqual(sdkKey, Buffer.from(expected.publicKey).toString('base64'), 'SDK derives from the seed, origin, mode and tag');

      const { path } = await getOriginSpecificAddress(mnemonic, origin);
      const signingKey = getBytes(deriveWalletFromPath(mnemonic, path).privateKey);
      const signingSeed = new Uint8Array(64);
      signingSeed.set(signingKey);
      const fromSigningKey = await deriveMLKemKeypair(signingSeed, { origin });
      assert(hex(fromSigningKey.publicKey) !== hex(expected.publicKey), 'Signing key does not give the KEM key');
    } finally {
      (globalThis as any).window = previousWindow;
    }

    passTest('SDK derivation independent of the signing key');
  });

  await runTest('Invalid seed and mode rejected', async () => {
    const shortSeed = await rejectionOf(() => deriveMLKemKeypair(new Uint8Array(32), { origin }));
    assertEqual(shortSeed.message, 'Invalid BIP-39 seed: expected 64 bytes', 'Short seed rejected');

    const badMode = await rejectionOf(() => deriveMLKemKeypair(testSeed1, { origin, mode: 'NOPE' as any }));
    assertEqual(badMode.message, 'Unknown security mode: NOPE', 'Unknown mode rejected');

    const badOrigin = await rejectionOf(() => deriveMLKemKeypair(testSeed1, { origin: 'not a url' }));
    assert(badOrigin.message.startsWith('Invalid origin URL'), 'Invalid origin rejected');

    passTest('Inputs validated');
  });


  const flipByte = (base64: string, index: number): string => {
    const bytes = Buffer.from(base64, 'base64');
    bytes[index] ^= 0x01;
    return bytes.toString('base64');
  };

  await runTest('HPKE key schedule matches RFC 9180 test vector A.6.1', async () => {
    const hex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
    const suiteId = new Uint8Array([...Buffer.from('HPKE'), 0x00, 0x12, 0x00, 0x03, 0x00, 0x02]);
    const { key, baseNonce } = hpkeKeySchedule(
      sha512,
      suiteId,
      hex('776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818'),
      hex('4f6465206f6e2061204772656369616e2055726e'),
      32,
      12
    );
    assertEqual(Buffer.from(key).toString('hex'), '751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70', 'key');
    assertEqual(Buffer.from(baseNonce).toString('hex'), '55ff7a7d739c69f44b25447b', 'base_nonce');

    const aead = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: baseNonce, additionalData: hex('436f756e742d30') },
      aead,
      hex('4265617574792069732074727574682c20747275746820626561757479')
    );
    assertEqual(
      Buffer.from(ct).toString('hex'),
      '170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a',
      'sequence 0 ciphertext'
    );

    passTest('RFC 9180 key schedule reproduced');
  });

  await runTest('Encrypt writes v3 HPKE payloads', async () => {
    const keypair = await deriveMLKemKeypair(testSeed1, { origin, context: 'test' });
    const encrypted = await mlkemEncrypt('v3 format', keypair.publicKey);
    const [recipient] = encrypted.recipients;

    assertEqual(encrypted.version, 3, 'Payload should be version 3');
    assertEqual(recipient.publicKey, Buffer.from(keypair.publicKey).toString('base64'), 'Recipient public key');
    assertEqual(Buffer.from(recipient.enc, 'base64').length, 1600, 'enc is 1568 ML-KEM + 32 X25519 bytes');
    assertEqual(Buffer.from(recipient.ciphertext, 'base64').length, 48, 'Sealed data key is 32 + 16 tag bytes');

    passTest('v3 payload format correct');
  });

  await runTest('v3 round-trip for three recipients', async () => {
    const plaintext = 'three recipients';
    const keypairs = await Promise.all([
      deriveMLKemKeypair(testSeed1, { origin, context: 'a' }),
      deriveMLKemKeypair(testSeed1, { origin, context: 'b' }),
      deriveMLKemKeypair(testSeed2, { origin, context: 'c' }),
    ]);
    const encrypted = await mlkemEncrypt(plaintext, keypairs.map(k => Buffer.from(k.publicKey).toString('base64')));

    assertEqual(encrypted.recipients.length, 3, 'Three recipient entries');
    for (const keypair of keypairs) {
      assertEqual(await mlkemDecrypt(encrypted, keypair.privateKey), plaintext, 'Each recipient decrypts');
    }
    const base64Key = Buffer.from(keypairs[1].privateKey).toString('base64');
    assertEqual(await mlkemDecrypt(encrypted, base64Key), plaintext, 'Base64 private key accepted');

    passTest('Multi-recipient v3 round-trip working');
  });

  await runTest('v1 and v2 payloads are rejected', async () => {
    const keypair = await deriveMLKemKeypair(testSeed1, { origin, context: 'test' });
    const encrypted = await mlkemEncrypt('old formats', keypair.publicKey);

    const v1: any = { ...encrypted };
    delete v1.version;
    const v1Error = await rejectionOf(() => mlkemDecrypt(v1, keypair.privateKey));
    assertEqual(v1Error.message, 'Unsupported payload version: undefined', 'v1 rejected');

    const v2: any = { ...encrypted, version: 2 };
    const v2Error = await rejectionOf(() => mlkemDecrypt(v2, keypair.privateKey));
    assertEqual(v2Error.message, 'Unsupported payload version: 2', 'v2 rejected');

    passTest('Only v3 is read');
  });

  await runTest('Altering the X25519 or ML-KEM part fails to decrypt', async () => {
    const keypair = await deriveMLKemKeypair(testSeed1, { origin, context: 'test' });

    for (const [part, index] of [['ML-KEM ciphertext', 0], ['ML-KEM ciphertext end', 1567], ['X25519 ephemeral key', 1568], ['X25519 ephemeral key end', 1599]] as const) {
      const encrypted = await mlkemEncrypt('tamper test', keypair.publicKey);
      encrypted.recipients[0].enc = flipByte(encrypted.recipients[0].enc, index);
      await rejectionOf(() => mlkemDecrypt(encrypted, keypair.privateKey));
      logDetail(`Tampered ${part} rejected`);
    }

    const sealedKey = await mlkemEncrypt('tamper test', keypair.publicKey);
    sealedKey.recipients[0].ciphertext = flipByte(sealedKey.recipients[0].ciphertext, 0);
    await rejectionOf(() => mlkemDecrypt(sealedKey, keypair.privateKey));

    const data = await mlkemEncrypt('tamper test', keypair.publicKey);
    data.encryptedData = flipByte(data.encryptedData, 0);
    await rejectionOf(() => mlkemDecrypt(data, keypair.privateKey));

    passTest('Both KEM halves, the sealed key and the data are authenticated');
  });

  await runTest('A recipient entry only opens for the recipient it was sealed to', async () => {
    const alice = await deriveMLKemKeypair(testSeed1, { origin, context: 'alice' });
    const bob = await deriveMLKemKeypair(testSeed2, { origin, context: 'bob' });
    const encrypted = await mlkemEncrypt('binding', [alice.publicKey, bob.publicKey]);

    const [toAlice, toBob] = encrypted.recipients;
    encrypted.recipients = [
      { ...toAlice, publicKey: toBob.publicKey },
      { ...toBob, publicKey: toAlice.publicKey },
    ];

    await rejectionOf(() => mlkemDecrypt(encrypted, alice.privateKey));
    await rejectionOf(() => mlkemDecrypt(encrypted, bob.privateKey));

    passTest('Swapped recipient entries fail to decrypt');
  });

  await runTest('Recipients outside the payload are rejected', async () => {
    const keypair1 = await deriveMLKemKeypair(testSeed1, { origin, context: 'user1' });
    const encrypted = await mlkemEncrypt('outsider', keypair1.publicKey);

    const outsider = await deriveMLKemKeypair(testSeed1, { origin, context: 'outsider' });
    const error = await rejectionOf(() => mlkemDecrypt(encrypted, outsider.privateKey));
    assertEqual(error.message, 'Public key not found in recipients list', 'Outsider rejected');

    passTest('Outsider rejected');
  });

  await runTest('Key sizes and private key integrity are enforced', async () => {
    const keypair = await deriveMLKemKeypair(testSeed1, { origin, context: 'test' });

    const pkError = await rejectionOf(() => mlkemEncrypt('size', keypair.publicKey.subarray(0, 1568)));
    assertEqual(pkError.message, 'Invalid public key size: 1568 (expected 1600)', 'ML-KEM-only public key rejected');

    const encrypted = await mlkemEncrypt('size', keypair.publicKey);
    const skError = await rejectionOf(() => mlkemDecrypt(encrypted, keypair.privateKey.subarray(0, 3168)));
    assertEqual(skError.message, 'Invalid private key size: 3168 (expected 3200)', 'ML-KEM-only private key rejected');

    const corrupted = new Uint8Array(keypair.privateKey);
    corrupted[1536] ^= 0x01;
    const corruptedError = await rejectionOf(() => mlkemDecrypt(encrypted, corrupted));
    assertEqual(corruptedError.message, 'Invalid ML-KEM private key: embedded public key hash mismatch', 'Corrupted private key rejected');

    passTest('Hybrid key sizes enforced');
  });

  await runTest('IV must be 12 bytes and auth tag 16 bytes', async () => {
    const keypair = await deriveMLKemKeypair(testSeed1, { origin, context: 'test' });

    const badIv = await mlkemEncrypt('iv test', keypair.publicKey);
    badIv.iv = Buffer.alloc(16).toString('base64');
    const ivError = await rejectionOf(() => mlkemDecrypt(badIv, keypair.privateKey));
    assertEqual(ivError.message, 'Invalid IV size: 16 (expected 12)', 'IV size error');

    const shortTag = await mlkemEncrypt('tag test', keypair.publicKey);
    shortTag.authTag = Buffer.from(shortTag.authTag, 'base64').subarray(0, 4).toString('base64');
    const tagError = await rejectionOf(() => mlkemDecrypt(shortTag, keypair.privateKey));
    assertEqual(tagError.message, 'Invalid auth tag size: 4 (expected 16)', 'Auth tag size error');

    passTest('IV and auth tag lengths enforced');
  });

  endTestSuite();
}

// Run tests
runTests().catch(error => {
  console.error('Test execution failed:', error);
  process.exit(1);
});
