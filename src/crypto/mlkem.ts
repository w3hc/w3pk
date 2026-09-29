import { createMlKem1024 } from 'mlkem';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

export interface MLKemKeypair {
  publicKey: Uint8Array;   // 1568 bytes for ML-KEM-1024
  privateKey: Uint8Array;  // 3168 bytes for ML-KEM-1024
}

export interface EncryptedPayload {
  version?: 2;              // Absent for legacy v1 payloads (XOR-wrapped AES key)
  recipients: Array<{
    publicKey: string;      // Base64 recipient public key (1568 bytes)
    ciphertext: string;     // Base64 ML-KEM ciphertext for this recipient
  }>;
  encryptedData: string;    // Base64 AES-encrypted data (shared across all recipients)
  iv: string;               // Base64 IV
  authTag: string;          // Base64 auth tag
}

const KEM_CIPHERTEXT_LENGTH = 1568;
const WRAPPED_KEY_LENGTH = { 1: 32, 2: 40 } as const;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEK_INFO = 'w3pk-mlkem-kek-v2';

/**
 * Securely zero out sensitive data from memory
 */
function zeroize(buffer: Uint8Array): void {
  buffer.fill(0);
}

/**
 * Convert Uint8Array to base64 (browser and Node.js compatible)
 */
function arrayBufferToBase64(buffer: Uint8Array): string {
  // Browser-compatible implementation
  if (typeof btoa !== 'undefined') {
    const binary = Array.from(buffer)
      .map(byte => String.fromCharCode(byte))
      .join('');
    return btoa(binary);
  }

  // Node.js fallback
  return Buffer.from(buffer).toString('base64');
}

/**
 * Convert base64 string to Uint8Array (browser and Node.js compatible)
 */
function base64ToArrayBuffer(base64: string): Uint8Array {
  // Browser-compatible implementation
  if (typeof atob !== 'undefined') {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Node.js fallback
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

/**
 * Derive the AES-KW key-encryption key from an ML-KEM shared secret (v2)
 */
async function deriveKek(sharedSecret: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  const kek = hkdf(
    sha256,
    sharedSecret,
    new Uint8Array(0),
    new TextEncoder().encode(KEK_INFO),
    32
  );
  try {
    return await crypto.subtle.importKey('raw', kek as BufferSource, 'AES-KW', false, [usage]);
  } finally {
    zeroize(kek);
  }
}

/**
 * Recover the AES-GCM data key from a recipient's wrapped key
 * Throws if the wrapped key fails its integrity check (v2 only)
 */
async function unwrapAesKey(
  version: 1 | 2,
  sharedSecret: Uint8Array,
  wrappedKey: Uint8Array
): Promise<CryptoKey> {
  if (version === 2) {
    const kek = await deriveKek(sharedSecret, 'unwrapKey');
    return crypto.subtle.unwrapKey(
      'raw',
      wrappedKey as BufferSource,
      kek,
      'AES-KW',
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
  }

  // Legacy v1: AES key XOR-ed with the raw shared secret, no integrity check
  const aesKey = new Uint8Array(32);
  try {
    for (let i = 0; i < 32; i++) {
      aesKey[i] = wrappedKey[i] ^ sharedSecret[i];
    }
    return await crypto.subtle.importKey('raw', aesKey as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  } finally {
    zeroize(aesKey);
  }
}

/**
 * Derive deterministic ML-KEM-1024 keypair from any private key material
 *
 * Uses HKDF-SHA256 to derive a 64-byte seed from the input key material,
 * then generates a reproducible ML-KEM-1024 keypair.
 *
 * @param privateKey - Private key material (hex string with optional 0x prefix, or Uint8Array)
 * @param context - Context string for domain separation (default: 'mlkem-v1')
 * @returns ML-KEM-1024 keypair (publicKey: 1568 bytes, privateKey: 3168 bytes)
 *
 * @example
 * ```typescript
 * // Derive from Ethereum private key
 * const ethPrivateKey = '0x1234...';
 * const keypair = await deriveMLKemKeypair(ethPrivateKey, 'my-app');
 *
 * // Derive from any 32-byte key
 * const randomKey = crypto.getRandomValues(new Uint8Array(32));
 * const keypair2 = await deriveMLKemKeypair(randomKey);
 * ```
 */
export async function deriveMLKemKeypair(
  privateKey: string | Uint8Array,
  context: string = 'mlkem-v1'
): Promise<MLKemKeypair> {
  const mlkem = await createMlKem1024();

  // Convert to Uint8Array
  let privateKeyBytes: Uint8Array;

  if (typeof privateKey === 'string') {
    // Remove '0x' prefix if present
    const hex = privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;

    // Convert hex to bytes
    if (typeof Buffer !== 'undefined') {
      privateKeyBytes = new Uint8Array(Buffer.from(hex, 'hex'));
    } else {
      // Browser fallback
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
      }
      privateKeyBytes = bytes;
    }
  } else {
    privateKeyBytes = privateKey;
  }

  // Derive 64-byte seed using HKDF-SHA256
  // salt: "mlkem-keypair-v1" (versioned for future upgrades)
  // info: context (for domain separation)
  const seed = hkdf(
    sha256,
    privateKeyBytes,
    new Uint8Array(Buffer.from('mlkem-keypair-v1', 'utf-8')),
    new Uint8Array(Buffer.from(context, 'utf-8')),
    64  // ML-KEM-1024 requires 64-byte seed
  );

  try {
    // Generate deterministic ML-KEM keypair from 64-byte seed
    const [publicKey, privateKeyOut] = mlkem.deriveKeyPair(seed);

    return {
      publicKey,
      privateKey: privateKeyOut,
    };
  } finally {
    // Zero out sensitive seed material
    zeroize(seed);
    zeroize(privateKeyBytes);
  }
}

/**
 * Encrypt data using ML-KEM-1024 + AES-256-GCM for multiple recipients
 *
 * @param plaintext - The data to encrypt
 * @param publicKeys - Array of ML-KEM-1024 public keys (base64 strings or Uint8Arrays, 1568 bytes each)
 * @returns Encrypted payload with per-recipient ciphertexts and shared encrypted data
 */
export async function mlkemEncrypt(
  plaintext: string,
  publicKeys: (string | Uint8Array) | Array<string | Uint8Array>
): Promise<EncryptedPayload> {
  const mlkem = await createMlKem1024();

  // Normalize to array
  const publicKeyArray = Array.isArray(publicKeys) ? publicKeys : [publicKeys];

  if (publicKeyArray.length === 0) {
    throw new Error('At least one public key is required');
  }

  // Generate a random AES key for the data
  const aesKey = new Uint8Array(32); // 256 bits
  crypto.getRandomValues(aesKey);

  try {
    // Generate random IV (96 bits recommended for AES-GCM)
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);

    // Encode plaintext
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    // Import AES key (extractable so it can be wrapped for each recipient)
    const key = await crypto.subtle.importKey(
      'raw',
      aesKey,
      { name: 'AES-GCM' },
      true,
      ['encrypt']
    );

    // Encrypt with AES-256-GCM
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128
      },
      key,
      data
    );

    // Extract encrypted data and auth tag
    const encryptedArray = new Uint8Array(encrypted);
    const tagLength = 16;

    if (encryptedArray.length < tagLength) {
      throw new Error('Encrypted data too short to contain auth tag');
    }

    const encryptedData = encryptedArray.slice(0, -tagLength);
    const authTag = encryptedArray.slice(-tagLength);

    // Encapsulate AES key for each recipient
    const recipients = [];

    for (const publicKey of publicKeyArray) {
      // Convert to Uint8Array if base64 string
      const publicKeyBytes = typeof publicKey === 'string'
        ? base64ToArrayBuffer(publicKey)
        : publicKey;

      // Validate public key size
      if (publicKeyBytes.length !== 1568) {
        throw new Error(`Invalid ML-KEM public key size: ${publicKeyBytes.length} (expected 1568)`);
      }

      // Encapsulate with this recipient's public key
      const [ciphertext, sharedSecret] = mlkem.encap(publicKeyBytes);

      try {
        // Wrap the AES key with AES-KW under a KEK derived from the shared secret
        const kek = await deriveKek(sharedSecret, 'wrapKey');
        const encryptedAesKey = new Uint8Array(
          await crypto.subtle.wrapKey('raw', key, kek, 'AES-KW')
        );

        // Store ciphertext concatenated with wrapped AES key
        const combinedCiphertext = new Uint8Array(ciphertext.length + encryptedAesKey.length);
        combinedCiphertext.set(ciphertext, 0);
        combinedCiphertext.set(encryptedAesKey, ciphertext.length);

        recipients.push({
          publicKey: arrayBufferToBase64(publicKeyBytes),
          ciphertext: arrayBufferToBase64(combinedCiphertext),
        });
      } finally {
        zeroize(sharedSecret);
      }
    }

    return {
      version: 2,
      recipients,
      encryptedData: arrayBufferToBase64(encryptedData),
      iv: arrayBufferToBase64(iv),
      authTag: arrayBufferToBase64(authTag),
    };
  } finally {
    // CRITICAL: Zero out all sensitive key material
    zeroize(aesKey);
  }
}

/**
 * Decrypt data encrypted with mlkemEncrypt()
 *
 * @param payload - The encrypted payload
 * @param privateKey - ML-KEM-1024 private key (base64 string or Uint8Array, 3168 bytes)
 * @param publicKey - Optional: Your public key to find the correct recipient entry (base64 string or Uint8Array, 1568 bytes)
 * @returns Decrypted plaintext
 */
export async function mlkemDecrypt(
  payload: EncryptedPayload,
  privateKey: string | Uint8Array,
  publicKey?: string | Uint8Array
): Promise<string> {
  const mlkem = await createMlKem1024();

  // Convert to Uint8Array if base64 string
  const privateKeyBytes = typeof privateKey === 'string'
    ? base64ToArrayBuffer(privateKey)
    : privateKey;

  // Validate private key size (ML-KEM-1024 private key is 3168 bytes)
  if (privateKeyBytes.length !== 3168) {
    throw new Error(`Invalid ML-KEM private key size: ${privateKeyBytes.length} (expected 3168)`);
  }

  const version = payload.version ?? 1;
  if (version !== 1 && version !== 2) {
    throw new Error(`Unsupported payload version: ${String(version)}`);
  }

  // Parse common payload parts
  const encryptedData = base64ToArrayBuffer(payload.encryptedData);
  const iv = base64ToArrayBuffer(payload.iv);
  const authTag = base64ToArrayBuffer(payload.authTag);

  if (iv.length !== IV_LENGTH) {
    throw new Error(`Invalid IV size: ${iv.length} (expected ${IV_LENGTH})`);
  }
  if (authTag.length !== AUTH_TAG_LENGTH) {
    throw new Error(`Invalid auth tag size: ${authTag.length} (expected ${AUTH_TAG_LENGTH})`);
  }

  const expectedLength = KEM_CIPHERTEXT_LENGTH + WRAPPED_KEY_LENGTH[version];

  // Decapsulate a recipient entry and recover its AES key
  const openRecipient = async (ciphertext: string): Promise<CryptoKey> => {
    const combinedCiphertext = base64ToArrayBuffer(ciphertext);
    if (combinedCiphertext.length !== expectedLength) {
      throw new Error(
        `Invalid combined ciphertext size: ${combinedCiphertext.length} (expected ${expectedLength})`
      );
    }

    const kemCiphertext = combinedCiphertext.slice(0, KEM_CIPHERTEXT_LENGTH);
    const wrappedKey = combinedCiphertext.slice(KEM_CIPHERTEXT_LENGTH);

    const sharedSecret = mlkem.decap(kemCiphertext, privateKeyBytes);
    try {
      return await unwrapAesKey(version, sharedSecret, wrappedKey);
    } finally {
      zeroize(sharedSecret);
    }
  };

  // Reconstruct ciphertext || tag for WebCrypto API
  const encryptedWithTag = new Uint8Array(encryptedData.length + authTag.length);
  encryptedWithTag.set(encryptedData, 0);
  encryptedWithTag.set(authTag, encryptedData.length);

  const decryptWith = async (ciphertext: string): Promise<string> => {
    const key = await openRecipient(ciphertext);
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv as BufferSource,
        tagLength: 128
      },
      key,
      encryptedWithTag as BufferSource
    );
    return new TextDecoder().decode(decrypted);
  };

  if (publicKey) {
    // Use public key to find the correct recipient
    const publicKeyBytes = typeof publicKey === 'string'
      ? base64ToArrayBuffer(publicKey)
      : publicKey;
    const publicKeyBase64 = arrayBufferToBase64(publicKeyBytes);

    const recipientEntry = payload.recipients.find(r => r.publicKey === publicKeyBase64);

    if (!recipientEntry) {
      throw new Error('Public key not found in recipients list');
    }

    return decryptWith(recipientEntry.ciphertext);
  }

  // ML-KEM decapsulation never fails on a wrong key (implicit rejection),
  // so try each recipient until one passes the authenticated checks
  for (const recipient of payload.recipients) {
    try {
      return await decryptWith(recipient.ciphertext);
    } catch {
      continue;
    }
  }

  throw new Error('No matching recipient found for this private key');
}

/**
 * Encrypt data with ML-KEM using derived keypairs from private keys
 *
 * This is a convenience function that derives ML-KEM keypairs from private key material,
 * then encrypts the data for all recipients. The sender's keypair is derived and used
 * as one of the recipients.
 *
 * @param plaintext - The data to encrypt
 * @param senderPrivateKey - Sender's private key (hex string or Uint8Array)
 * @param recipientPublicKeys - Array of recipient ML-KEM public keys (from deriveMLKemKeypair)
 * @param senderContext - Context for sender's key derivation (default: 'mlkem-v1')
 * @returns Encrypted payload with sender + recipients
 *
 * @example
 * ```typescript
 * // Encrypt for yourself + server
 * const serverKeypair = await deriveMLKemKeypair(serverPrivateKey, 'server');
 * const encrypted = await mlkemEncryptWithKey(
 *   'secret data',
 *   myEthPrivateKey,
 *   [serverKeypair.publicKey]
 * );
 * ```
 */
export async function mlkemEncryptWithKey(
  plaintext: string,
  senderPrivateKey: string | Uint8Array,
  recipientPublicKeys: Array<string | Uint8Array>,
  senderContext: string = 'mlkem-v1'
): Promise<EncryptedPayload> {
  // Derive sender's keypair
  const senderKeypair = await deriveMLKemKeypair(senderPrivateKey, senderContext);

  try {
    // Include sender's public key as first recipient
    const allPublicKeys = [senderKeypair.publicKey, ...recipientPublicKeys];

    // Encrypt for all recipients
    return await mlkemEncrypt(plaintext, allPublicKeys);
  } finally {
    // Zero out sender's private key
    zeroize(senderKeypair.privateKey);
  }
}

/**
 * Decrypt data with ML-KEM using a derived keypair from private key
 *
 * This is a convenience function that derives an ML-KEM keypair from private key material,
 * then decrypts the payload.
 *
 * @param payload - The encrypted payload
 * @param privateKey - Private key material (hex string or Uint8Array)
 * @param context - Context for key derivation (default: 'mlkem-v1')
 * @returns Decrypted plaintext
 *
 * @example
 * ```typescript
 * // Decrypt with your Ethereum private key
 * const plaintext = await mlkemDecryptWithKey(
 *   encryptedPayload,
 *   myEthPrivateKey
 * );
 * ```
 */
export async function mlkemDecryptWithKey(
  payload: EncryptedPayload,
  privateKey: string | Uint8Array,
  context: string = 'mlkem-v1'
): Promise<string> {
  // Derive keypair
  const keypair = await deriveMLKemKeypair(privateKey, context);

  try {
    // Decrypt using derived private key
    return await mlkemDecrypt(payload, keypair.privateKey, keypair.publicKey);
  } finally {
    // Zero out private key
    zeroize(keypair.privateKey);
  }
}
