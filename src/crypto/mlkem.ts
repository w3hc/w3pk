import { createMlKem1024 } from 'mlkem';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

export interface MLKemKeypair {
  publicKey: Uint8Array;   // 1568 bytes for ML-KEM-1024
  privateKey: Uint8Array;  // 3168 bytes for ML-KEM-1024
}

export interface EncryptedPayload {
  recipients: Array<{
    publicKey: string;      // Base64 recipient public key (1568 bytes)
    ciphertext: string;     // Base64 ML-KEM ciphertext for this recipient
  }>;
  encryptedData: string;    // Base64 AES-encrypted data (shared across all recipients)
  iv: string;               // Base64 IV
  authTag: string;          // Base64 auth tag
}

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

    // Import AES key
    const key = await crypto.subtle.importKey(
      'raw',
      aesKey,
      { name: 'AES-GCM' },
      false,
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
        // Use shared secret to encrypt the AES key
        // We use the first 32 bytes of shared secret as KEK (Key Encryption Key)
        const kek = sharedSecret.slice(0, 32);

        // XOR encrypt the AES key with the KEK (simple but effective)
        const encryptedAesKey = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
          encryptedAesKey[i] = aesKey[i] ^ kek[i];
        }

        // Store ciphertext concatenated with encrypted AES key
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

  // Parse common payload parts
  const encryptedData = base64ToArrayBuffer(payload.encryptedData);
  const iv = base64ToArrayBuffer(payload.iv);
  const authTag = base64ToArrayBuffer(payload.authTag);

  // Find the recipient entry
  let recipientEntry = null;

  if (publicKey) {
    // Use public key to find the correct recipient
    const publicKeyBytes = typeof publicKey === 'string'
      ? base64ToArrayBuffer(publicKey)
      : publicKey;
    const publicKeyBase64 = arrayBufferToBase64(publicKeyBytes);

    recipientEntry = payload.recipients.find(r => r.publicKey === publicKeyBase64);

    if (!recipientEntry) {
      throw new Error('Public key not found in recipients list');
    }
  } else {
    // Try all recipients until one works
    for (const recipient of payload.recipients) {
      try {
        const ciphertext = base64ToArrayBuffer(recipient.ciphertext);
        const sharedSecret = mlkem.decap(ciphertext, privateKeyBytes);

        // If decap succeeds, we found the right recipient
        recipientEntry = recipient;
        zeroize(sharedSecret); // Clean up test attempt
        break;
      } catch {
        // This recipient is not for us, try next one
        continue;
      }
    }

    if (!recipientEntry) {
      throw new Error('No matching recipient found for this private key');
    }
  }

  // Parse combined ciphertext (ML-KEM ciphertext + encrypted AES key)
  const combinedCiphertext = base64ToArrayBuffer(recipientEntry.ciphertext);

  // ML-KEM-1024 ciphertext is 1568 bytes, encrypted AES key is 32 bytes
  const kemCiphertextLength = 1568;
  const kemCiphertext = combinedCiphertext.slice(0, kemCiphertextLength);
  const encryptedAesKey = combinedCiphertext.slice(kemCiphertextLength);

  // Decapsulate to recover shared secret
  const sharedSecret = mlkem.decap(kemCiphertext, privateKeyBytes);
  let aesKey: Uint8Array | null = null;

  try {
    // Use shared secret to decrypt the AES key
    const kek = sharedSecret.slice(0, 32);

    // XOR decrypt the AES key
    aesKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      aesKey[i] = encryptedAesKey[i] ^ kek[i];
    }

    // Import AES key
    const key = await crypto.subtle.importKey(
      'raw',
      aesKey as BufferSource,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // Reconstruct ciphertext || tag for WebCrypto API
    const combinedLength = encryptedData.length + authTag.length;
    const buffer = new ArrayBuffer(combinedLength);
    const encryptedWithTag = new Uint8Array(buffer);
    encryptedWithTag.set(encryptedData, 0);
    encryptedWithTag.set(authTag, encryptedData.length);

    // Decrypt with AES-256-GCM
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv.buffer as ArrayBuffer,
        tagLength: 128
      },
      key,
      buffer
    );

    // Decode plaintext
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } finally {
    // CRITICAL: Zero out all sensitive key material from memory
    zeroize(sharedSecret);
    if (aesKey) {
      zeroize(aesKey);
    }
  }
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
