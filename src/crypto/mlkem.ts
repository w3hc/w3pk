import { createMlKem1024 } from 'mlkem';
import { x25519 } from '@noble/curves/ed25519.js';
import { extract, expand } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { concatBytes as concat, type CHash } from '@noble/hashes/utils.js';
import { equalBytes } from '@noble/curves/utils.js';
import { normalizeOrigin, DEFAULT_MODE, DEFAULT_TAG } from '../wallet/origin-derivation';
import type { SecurityMode } from '../types';

/**
 * Hybrid KEM keypair: ML-KEM-1024 and X25519, concatenated
 */
export interface MLKemKeypair {
  publicKey: Uint8Array;   // 1600 bytes: ML-KEM-1024 encapsulation key (1568) || X25519 public key (32)
  privateKey: Uint8Array;  // 3200 bytes: ML-KEM-1024 decapsulation key (3168) || X25519 secret key (32)
}

export interface EncryptedPayload {
  version: 3;
  recipients: Array<{
    publicKey: string;      // Base64 recipient hybrid public key (1600 bytes)
    enc: string;            // Base64 HPKE encapsulation: ML-KEM-1024 ciphertext (1568) || X25519 ephemeral public key (32)
    ciphertext: string;     // Base64 HPKE-sealed AES-256 data key (32 + 16-byte tag)
  }>;
  encryptedData: string;    // Base64 AES-256-GCM ciphertext (shared across all recipients)
  iv: string;               // Base64 IV
  authTag: string;          // Base64 auth tag
}

/** Default context string for hybrid keypair derivation */
export const MLKEM_DEFAULT_CONTEXT = 'mlkem-v1';

/**
 * Domain of a hybrid keypair: the origin, mode and tag of the wallet it belongs to,
 * and a free context string
 */
export interface MLKemDerivationOptions {
  origin: string;
  mode?: SecurityMode;
  tag?: string;
  context?: string;
}

const BIP39_SEED_LENGTH = 64;
const SECURITY_MODES: readonly SecurityMode[] = ['STANDARD', 'STRICT', 'YOLO', 'PRIMARY'];

const ML_KEM_PUBLIC_KEY_LENGTH = 1568;
const ML_KEM_PRIVATE_KEY_LENGTH = 3168;
const ML_KEM_CIPHERTEXT_LENGTH = 1568;
// FIPS 203 decapsulation key: dk_PKE (1536) || ek (1568) || H(ek) (32) || z (32)
const ML_KEM_EK_OFFSET = 1536;
const ML_KEM_EK_HASH_OFFSET = ML_KEM_EK_OFFSET + ML_KEM_PUBLIC_KEY_LENGTH;
const X25519_LENGTH = 32;
const PUBLIC_KEY_LENGTH = ML_KEM_PUBLIC_KEY_LENGTH + X25519_LENGTH;
const PRIVATE_KEY_LENGTH = ML_KEM_PRIVATE_KEY_LENGTH + X25519_LENGTH;
const ENC_LENGTH = ML_KEM_CIPHERTEXT_LENGTH + X25519_LENGTH;
const DATA_KEY_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const SEALED_KEY_LENGTH = DATA_KEY_LENGTH + AUTH_TAG_LENGTH;

const encoder = new TextEncoder();

const KEYPAIR_SALT = encoder.encode('w3pk-kem-keypair-v4');
const COMBINER_LABEL = encoder.encode('w3pk-MLKEM1024-X25519-v3');

// Not IANA-registered: only domain-separates the HPKE key schedule
const KEM_ID = 0xfe42;
const KDF_ID_HKDF_SHA256 = 0x0001;
const AEAD_ID_AES_256_GCM = 0x0002;
const HPKE_VERSION_LABEL = encoder.encode('HPKE-v1');
const HPKE_INFO = encoder.encode('w3pk-payload-v3');
const MODE_BASE = 0x00;

function zeroize(buffer: Uint8Array): void {
  buffer.fill(0);
}

function i2osp(value: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = value & 0xff;
    value >>>= 8;
  }
  return out;
}

function hpkeSuiteId(kemId: number, kdfId: number, aeadId: number): Uint8Array {
  return concat(encoder.encode('HPKE'), i2osp(kemId, 2), i2osp(kdfId, 2), i2osp(aeadId, 2));
}

const SUITE_ID = hpkeSuiteId(KEM_ID, KDF_ID_HKDF_SHA256, AEAD_ID_AES_256_GCM);

function arrayBufferToBase64(buffer: Uint8Array): string {
  const binary = Array.from(buffer)
    .map(byte => String.fromCharCode(byte))
    .join('');
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toBytes(key: string | Uint8Array): Uint8Array {
  return typeof key === 'string' ? base64ToArrayBuffer(key) : key;
}

/**
 * Hybrid KEM combiner (UniversalCombiner of draft-irtf-cfrg-hybrid-kems):
 * SHA3-256(ss_M || ss_X || ct_M || ct_X || pk_M || pk_X || label)
 */
function combineSharedSecrets(
  ssM: Uint8Array,
  ssX: Uint8Array,
  ctM: Uint8Array,
  ctX: Uint8Array,
  pkM: Uint8Array,
  pkX: Uint8Array
): Uint8Array {
  const input = concat(ssM, ssX, ctM, ctX, pkM, pkX, COMBINER_LABEL);
  try {
    return sha3_256(input);
  } finally {
    zeroize(input);
  }
}

/**
 * HPKE key schedule, mode_base with the default PSK (RFC 9180, Section 5.1)
 * @internal Exported for the RFC 9180 test vectors
 */
export function hpkeKeySchedule(
  hash: CHash,
  suiteId: Uint8Array,
  sharedSecret: Uint8Array,
  info: Uint8Array,
  nk: number,
  nn: number
): { key: Uint8Array; baseNonce: Uint8Array } {
  const empty = new Uint8Array(0);
  const labeledExtract = (salt: Uint8Array, label: string, ikm: Uint8Array) =>
    extract(hash, concat(HPKE_VERSION_LABEL, suiteId, encoder.encode(label), ikm), salt);
  const labeledExpand = (prk: Uint8Array, label: string, ctx: Uint8Array, length: number) =>
    expand(
      hash,
      prk,
      concat(i2osp(length, 2), HPKE_VERSION_LABEL, suiteId, encoder.encode(label), ctx),
      length
    );

  const pskIdHash = labeledExtract(empty, 'psk_id_hash', empty);
  const infoHash = labeledExtract(empty, 'info_hash', info);
  const context = concat(new Uint8Array([MODE_BASE]), pskIdHash, infoHash);
  const secret = labeledExtract(sharedSecret, 'secret', empty);
  try {
    return {
      key: labeledExpand(secret, 'key', context, nk),
      baseNonce: labeledExpand(secret, 'base_nonce', context, nn),
    };
  } finally {
    zeroize(secret);
  }
}

async function importAesGcmKey(raw: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, false, [usage]);
}

/**
 * Single-shot HPKE Seal/Open (sequence number 0, so the nonce is base_nonce) with AES-256-GCM
 */
async function hpkeAead(
  direction: 'seal' | 'open',
  sharedSecret: Uint8Array,
  input: Uint8Array
): Promise<Uint8Array> {
  const { key, baseNonce } = hpkeKeySchedule(sha256, SUITE_ID, sharedSecret, HPKE_INFO, 32, IV_LENGTH);
  try {
    const params = { name: 'AES-GCM', iv: baseNonce as BufferSource, tagLength: 128 };
    if (direction === 'seal') {
      const aead = await importAesGcmKey(key, 'encrypt');
      return new Uint8Array(await crypto.subtle.encrypt(params, aead, input as BufferSource));
    }
    const aead = await importAesGcmKey(key, 'decrypt');
    return new Uint8Array(await crypto.subtle.decrypt(params, aead, input as BufferSource));
  } finally {
    zeroize(key);
  }
}

function splitPrivateKey(privateKey: Uint8Array) {
  const skM = privateKey.subarray(0, ML_KEM_PRIVATE_KEY_LENGTH);
  const skX = privateKey.subarray(ML_KEM_PRIVATE_KEY_LENGTH);
  const pkM = skM.slice(ML_KEM_EK_OFFSET, ML_KEM_EK_HASH_OFFSET);
  if (!equalBytes(sha3_256(pkM), skM.subarray(ML_KEM_EK_HASH_OFFSET, ML_KEM_EK_HASH_OFFSET + 32))) {
    throw new Error('Invalid ML-KEM private key: embedded public key hash mismatch');
  }
  return { skM, skX, pkM, pkX: x25519.getPublicKey(skX) };
}

function lengthPrefixed(value: string): Uint8Array {
  const bytes = encoder.encode(value);
  return concat(i2osp(bytes.length, 4), bytes);
}

function keypairInfo(
  purpose: string,
  origin: string,
  mode: SecurityMode,
  tag: string,
  context: string
): Uint8Array {
  return concat(...[purpose, origin, mode, tag, context].map(lengthPrefixed));
}

/**
 * Derive a deterministic hybrid keypair (ML-KEM-1024 + X25519) from a BIP-39 seed
 *
 * HKDF-SHA256 extracts a PRK from the 64-byte BIP-39 seed (salt `w3pk-kem-keypair-v4`),
 * then expands a 64-byte ML-KEM-1024 seed and a 32-byte X25519 secret key. Each info is
 * the purpose (`ml-kem-1024` or `x25519`), the normalized origin, the mode, the uppercased
 * tag and the context, each prefixed with its UTF-8 length as a 4-byte big-endian integer.
 *
 * Only hash functions sit between the seed and the KEM keys: no secp256k1 key enters
 * the derivation, so a published signing key reveals nothing about them.
 *
 * @param seed - 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512 of the mnemonic, as in BIP-39)
 * @param options.origin - Origin URL, normalized as for origin-specific addresses
 * @param options.mode - Security mode (default: 'STANDARD')
 * @param options.tag - Tag, uppercased (default: 'MAIN')
 * @param options.context - Context string for domain separation (default: MLKEM_DEFAULT_CONTEXT)
 * @returns Hybrid keypair (publicKey: 1600 bytes, privateKey: 3200 bytes)
 *
 * @example
 * ```typescript
 * import { Mnemonic, getBytes } from 'ethers';
 *
 * const seed = getBytes(Mnemonic.fromPhrase(mnemonic).computeSeed());
 * const keypair = await deriveMLKemKeypair(seed, { origin: 'https://example.com' });
 * ```
 */
export async function deriveMLKemKeypair(
  seed: Uint8Array,
  options: MLKemDerivationOptions
): Promise<MLKemKeypair> {
  if (!(seed instanceof Uint8Array) || seed.length !== BIP39_SEED_LENGTH) {
    throw new Error(`Invalid BIP-39 seed: expected ${BIP39_SEED_LENGTH} bytes`);
  }
  const mode = options.mode || DEFAULT_MODE;
  if (!SECURITY_MODES.includes(mode)) {
    throw new Error(`Unknown security mode: ${String(mode)}`);
  }
  const origin = normalizeOrigin(options.origin);
  const tag = (options.tag || DEFAULT_TAG).toUpperCase();
  const context = options.context || MLKEM_DEFAULT_CONTEXT;

  const mlkem = await createMlKem1024();

  const prk = extract(sha256, seed, KEYPAIR_SALT);
  const seedM = expand(sha256, prk, keypairInfo('ml-kem-1024', origin, mode, tag, context), 64);
  const skX = expand(sha256, prk, keypairInfo('x25519', origin, mode, tag, context), X25519_LENGTH);

  try {
    const [pkM, skM] = mlkem.deriveKeyPair(seedM);
    const pkX = x25519.getPublicKey(skX);
    const keypair = {
      publicKey: concat(pkM, pkX),
      privateKey: concat(skM, skX),
    };
    zeroize(skM);
    return keypair;
  } finally {
    zeroize(prk);
    zeroize(seedM);
    zeroize(skX);
  }
}

/**
 * Encrypt data for one or more recipients (payload v3)
 *
 * The plaintext is encrypted once with AES-256-GCM under a random data key, which is
 * sealed to each recipient with HPKE (RFC 9180, mode_base, HKDF-SHA256, AES-256-GCM)
 * over a hybrid ML-KEM-1024 + X25519 KEM.
 *
 * Payloads have no sender authentication: every recipient learns the shared data key,
 * so any recipient can seal new content for the others. To prove who wrote the content,
 * sign the plaintext, the recipients' public keys and a timestamp with a secp256k1 key
 * (`w3pk.signMessage()`, or an ethers `Wallet`), encrypt the signed message, and have
 * recipients verify the signature after decrypting. Signing the ciphertext doesn't work:
 * anyone can strip the signature and sign it as themselves. See docs/POST_QUANTUM.md.
 *
 * @param plaintext - The data to encrypt
 * @param publicKeys - Hybrid public keys (base64 strings or Uint8Arrays, 1600 bytes each)
 * @returns Encrypted payload with one entry per recipient
 */
export async function mlkemEncrypt(
  plaintext: string,
  publicKeys: (string | Uint8Array) | Array<string | Uint8Array>
): Promise<EncryptedPayload> {
  const mlkem = await createMlKem1024();

  const publicKeyArray = (Array.isArray(publicKeys) ? publicKeys : [publicKeys]).map(toBytes);

  if (publicKeyArray.length === 0) {
    throw new Error('At least one public key is required');
  }
  for (const publicKey of publicKeyArray) {
    if (publicKey.length !== PUBLIC_KEY_LENGTH) {
      throw new Error(`Invalid public key size: ${publicKey.length} (expected ${PUBLIC_KEY_LENGTH})`);
    }
  }

  const dataKey = crypto.getRandomValues(new Uint8Array(DATA_KEY_LENGTH));

  try {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        await importAesGcmKey(dataKey, 'encrypt'),
        encoder.encode(plaintext)
      )
    );

    const recipients: EncryptedPayload['recipients'] = [];

    for (const publicKey of publicKeyArray) {
      const pkM = publicKey.subarray(0, ML_KEM_PUBLIC_KEY_LENGTH);
      const pkX = publicKey.subarray(ML_KEM_PUBLIC_KEY_LENGTH);

      const ephemeral = x25519.utils.randomSecretKey();
      let ssX: Uint8Array | undefined;
      let ssM: Uint8Array | undefined;
      let sharedSecret: Uint8Array | undefined;

      try {
        const ctX = x25519.getPublicKey(ephemeral);
        ssX = x25519.getSharedSecret(ephemeral, pkX);
        let ctM: Uint8Array;
        [ctM, ssM] = mlkem.encap(pkM);
        sharedSecret = combineSharedSecrets(ssM, ssX, ctM, ctX, pkM, pkX);
        recipients.push({
          publicKey: arrayBufferToBase64(publicKey),
          enc: arrayBufferToBase64(concat(ctM, ctX)),
          ciphertext: arrayBufferToBase64(await hpkeAead('seal', sharedSecret, dataKey)),
        });
      } finally {
        zeroize(ephemeral);
        if (ssX) zeroize(ssX);
        if (ssM) zeroize(ssM);
        if (sharedSecret) zeroize(sharedSecret);
      }
    }

    return {
      version: 3,
      recipients,
      encryptedData: arrayBufferToBase64(sealed.slice(0, -AUTH_TAG_LENGTH)),
      iv: arrayBufferToBase64(iv),
      authTag: arrayBufferToBase64(sealed.slice(-AUTH_TAG_LENGTH)),
    };
  } finally {
    zeroize(dataKey);
  }
}

/**
 * Decrypt a v3 payload from mlkemEncrypt()
 *
 * The recipient entry is found by the public key derived from `privateKey`.
 * Payloads of any other version are rejected. Decryption doesn't prove who sent the
 * payload: any recipient can seal new content for the others (see mlkemEncrypt()).
 *
 * @param payload - The encrypted payload
 * @param privateKey - Hybrid private key (base64 string or Uint8Array, 3200 bytes)
 * @returns Decrypted plaintext
 */
export async function mlkemDecrypt(
  payload: EncryptedPayload,
  privateKey: string | Uint8Array
): Promise<string> {
  if (payload.version !== 3) {
    throw new Error(`Unsupported payload version: ${String(payload.version)}`);
  }

  const privateKeyBytes = toBytes(privateKey);
  try {
    return await decryptWithKeyBytes(payload, privateKeyBytes);
  } finally {
    if (typeof privateKey === 'string') {
      zeroize(privateKeyBytes);
    }
  }
}

async function decryptWithKeyBytes(payload: EncryptedPayload, privateKeyBytes: Uint8Array): Promise<string> {
  if (privateKeyBytes.length !== PRIVATE_KEY_LENGTH) {
    throw new Error(`Invalid private key size: ${privateKeyBytes.length} (expected ${PRIVATE_KEY_LENGTH})`);
  }

  const encryptedData = base64ToArrayBuffer(payload.encryptedData);
  const iv = base64ToArrayBuffer(payload.iv);
  const authTag = base64ToArrayBuffer(payload.authTag);

  if (iv.length !== IV_LENGTH) {
    throw new Error(`Invalid IV size: ${iv.length} (expected ${IV_LENGTH})`);
  }
  if (authTag.length !== AUTH_TAG_LENGTH) {
    throw new Error(`Invalid auth tag size: ${authTag.length} (expected ${AUTH_TAG_LENGTH})`);
  }

  const { skM, skX, pkM, pkX } = splitPrivateKey(privateKeyBytes);
  const ownPublicKey = concat(pkM, pkX);

  const recipient = payload.recipients.find(r => equalBytes(base64ToArrayBuffer(r.publicKey), ownPublicKey));
  if (!recipient) {
    throw new Error('Public key not found in recipients list');
  }

  const enc = base64ToArrayBuffer(recipient.enc);
  const sealedKey = base64ToArrayBuffer(recipient.ciphertext);
  if (enc.length !== ENC_LENGTH) {
    throw new Error(`Invalid enc size: ${enc.length} (expected ${ENC_LENGTH})`);
  }
  if (sealedKey.length !== SEALED_KEY_LENGTH) {
    throw new Error(`Invalid sealed key size: ${sealedKey.length} (expected ${SEALED_KEY_LENGTH})`);
  }

  const ctM = enc.subarray(0, ML_KEM_CIPHERTEXT_LENGTH);
  const ctX = enc.subarray(ML_KEM_CIPHERTEXT_LENGTH);

  const mlkem = await createMlKem1024();
  const ssM = mlkem.decap(ctM, skM);
  let ssX: Uint8Array | undefined;
  let sharedSecret: Uint8Array | undefined;
  let dataKey: Uint8Array | undefined;

  try {
    ssX = x25519.getSharedSecret(skX, ctX);
    sharedSecret = combineSharedSecrets(ssM, ssX, ctM, ctX, pkM, pkX);
    dataKey = await hpkeAead('open', sharedSecret, sealedKey);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 },
      await importAesGcmKey(dataKey, 'decrypt'),
      concat(encryptedData, authTag) as BufferSource
    );
    return new TextDecoder().decode(decrypted);
  } finally {
    zeroize(ssM);
    if (ssX) zeroize(ssX);
    if (sharedSecret) zeroize(sharedSecret);
    if (dataKey) zeroize(dataKey);
  }
}

/**
 * Encrypt with a hybrid keypair derived from a BIP-39 seed
 *
 * Derives the sender's keypair and adds its public key as the first recipient,
 * so the sender can decrypt later. The sender's keypair doesn't authenticate the payload:
 * see mlkemEncrypt() on sender authentication.
 *
 * @param plaintext - The data to encrypt
 * @param senderSeed - Sender's 64-byte BIP-39 seed
 * @param recipientPublicKeys - Recipient hybrid public keys (from deriveMLKemKeypair)
 * @param senderOptions - Origin, mode, tag and context of the sender's keypair
 * @returns Encrypted payload with sender + recipients
 */
export async function mlkemEncryptWithKey(
  plaintext: string,
  senderSeed: Uint8Array,
  recipientPublicKeys: Array<string | Uint8Array>,
  senderOptions: MLKemDerivationOptions
): Promise<EncryptedPayload> {
  const senderKeypair = await deriveMLKemKeypair(senderSeed, senderOptions);

  try {
    return await mlkemEncrypt(plaintext, [senderKeypair.publicKey, ...recipientPublicKeys]);
  } finally {
    zeroize(senderKeypair.privateKey);
  }
}

/**
 * Decrypt with a hybrid keypair derived from a BIP-39 seed
 *
 * Decryption doesn't prove who sent the payload (see mlkemEncrypt()).
 *
 * @param payload - The encrypted payload
 * @param seed - 64-byte BIP-39 seed
 * @param options - Origin, mode, tag and context of the keypair (must match encryption)
 * @returns Decrypted plaintext
 */
export async function mlkemDecryptWithKey(
  payload: EncryptedPayload,
  seed: Uint8Array,
  options: MLKemDerivationOptions
): Promise<string> {
  const keypair = await deriveMLKemKeypair(seed, options);

  try {
    return await mlkemDecrypt(payload, keypair.privateKey);
  } finally {
    zeroize(keypair.privateKey);
  }
}
