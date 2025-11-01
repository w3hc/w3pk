/**
 * ERC-5564 Stealth Address Cryptography
 * Standard-compliant implementation for privacy-preserving transactions
 *
 * @see https://eips.ethereum.org/EIPS/eip-5564
 */

import { ethers } from "ethers";
import { CryptoError } from "../core/errors";

/**
 * ERC-5564 Stealth Keys
 * Contains the stealth meta-address and private keys for viewing and spending
 */
export interface StealthKeys {
  /** Stealth meta-address (66 bytes: compressed spending + viewing pubkeys) */
  stealthMetaAddress: string;
  /** Compressed spending public key (33 bytes) */
  spendingPubKey: string;
  /** Compressed viewing public key (33 bytes) */
  viewingPubKey: string;
  /** Viewing private key (32 bytes) */
  viewingKey: string;
  /** Spending private key (32 bytes) */
  spendingKey: string;
}

/**
 * ERC-5564 Stealth Address Generation Result
 */
export interface StealthAddressResult {
  /** The generated stealth address */
  stealthAddress: string;
  /** Ephemeral public key (compressed, 33 bytes) */
  ephemeralPubKey: string;
  /** View tag (1 byte) for efficient scanning */
  viewTag: string;
}

/**
 * ERC-5564 Parse/Check Result
 */
export interface ParseResult {
  /** Whether this announcement is for the user */
  isForUser: boolean;
  /** The stealth address (only if isForUser is true) */
  stealthAddress?: string;
  /** The stealth private key (only if isForUser is true) */
  stealthPrivateKey?: string;
}

/**
 * Derive ERC-5564 compliant stealth keys from w3pk mnemonic using HD paths
 *
 * @param mnemonic - BIP39 mnemonic phrase
 * @returns StealthKeys with compressed public keys and stealth meta-address
 */
export function deriveStealthKeys(mnemonic: string): StealthKeys {
  try {
    // Use specific derivation paths for stealth keys
    const viewingWallet = ethers.HDNodeWallet.fromPhrase(
      mnemonic,
      undefined,
      "m/44'/60'/1'/0/0" // Viewing key path
    );

    const spendingWallet = ethers.HDNodeWallet.fromPhrase(
      mnemonic,
      undefined,
      "m/44'/60'/1'/0/1" // Spending key path
    );

    // Get compressed public keys (ERC-5564 requirement)
    const spendingPubKey = spendingWallet.signingKey.compressedPublicKey;
    const viewingPubKey = viewingWallet.signingKey.compressedPublicKey;

    // ERC-5564 stealth meta-address: 66 bytes (spending + viewing pubkeys)
    const stealthMetaAddress = spendingPubKey + viewingPubKey.slice(2);

    return {
      stealthMetaAddress,
      spendingPubKey,
      viewingPubKey,
      viewingKey: viewingWallet.privateKey,
      spendingKey: spendingWallet.privateKey,
    };
  } catch (error) {
    throw new CryptoError("Failed to derive stealth keys", error);
  }
}

/**
 * ERC-5564: Generate a stealth address using ECDH
 * This is the sender's operation - they generate a one-time stealth address
 * for the recipient without any interaction.
 *
 * Algorithm:
 * 1. Generate random ephemeral private key
 * 2. Parse spending and viewing public keys from stealth meta-address
 * 3. Compute shared secret: s = ephemeral_privkey × viewing_pubkey (ECDH)
 * 4. Hash shared secret: s_h = keccak256(s)
 * 5. Extract view tag: viewTag = s_h[0]
 * 6. Compute stealth pubkey: P_stealth = spending_pubkey + (s_h × G)
 * 7. Derive stealth address from P_stealth
 *
 * @param stealthMetaAddress - 66 bytes (spending + viewing compressed pubkeys)
 * @returns Stealth address, ephemeral pubkey, and view tag
 */
export function generateStealthAddress(
  stealthMetaAddress: string
): StealthAddressResult {
  try {
    // Parse the stealth meta-address (66 bytes = 33 + 33)
    const spendingPubKey = "0x" + stealthMetaAddress.slice(2, 68); // First 33 bytes
    const viewingPubKey = "0x" + stealthMetaAddress.slice(68); // Last 33 bytes

    // Generate ephemeral keypair
    const ephemeralWallet = ethers.Wallet.createRandom();
    const ephemeralPubKey = ephemeralWallet.signingKey.compressedPublicKey;

    // Compute ECDH shared secret: s = ephemeral_privkey × viewing_pubkey
    const sharedSecret = computeSharedSecret(
      ephemeralWallet.privateKey,
      viewingPubKey
    );

    // Hash the shared secret: s_h = keccak256(s)
    const hashedSharedSecret = ethers.keccak256(sharedSecret);

    // Extract view tag (first byte of hashed shared secret)
    const viewTag = "0x" + hashedSharedSecret.slice(2, 4);

    // Compute stealth public key: P_stealth = spending_pubkey + (s_h × G)
    const stealthPubKey = addPublicKeys(
      spendingPubKey,
      multiplyGeneratorByScalar(hashedSharedSecret)
    );

    // Derive stealth address from stealth public key
    const stealthAddress = publicKeyToAddress(stealthPubKey);

    return {
      stealthAddress,
      ephemeralPubKey,
      viewTag,
    };
  } catch (error) {
    throw new CryptoError("Failed to generate stealth address", error);
  }
}

/**
 * ERC-5564: Check if a stealth address belongs to the user (with view tag optimization)
 * This is the recipient's scanning operation.
 *
 * Algorithm:
 * 1. Compute shared secret: s = viewing_privkey × ephemeral_pubkey (ECDH)
 * 2. Hash shared secret: s_h = keccak256(s)
 * 3. Check view tag first (255/256 probability to skip remaining computation)
 * 4. If view tag matches, compute stealth pubkey: P_stealth = spending_pubkey + (s_h × G)
 * 5. Derive address and compare with target
 *
 * @param viewingKey - Recipient's viewing private key
 * @param spendingPubKey - Recipient's spending public key (compressed)
 * @param ephemeralPubKey - Ephemeral public key from announcement
 * @param stealthAddress - The stealth address to check
 * @param viewTag - View tag from announcement (optional, for optimization)
 * @returns ParseResult with stealth address and private key if it belongs to user
 */
export function checkStealthAddress(
  viewingKey: string,
  spendingPubKey: string,
  ephemeralPubKey: string,
  stealthAddress: string,
  viewTag?: string
): ParseResult {
  try {
    // Compute ECDH shared secret: s = viewing_privkey × ephemeral_pubkey
    const sharedSecret = computeSharedSecret(viewingKey, ephemeralPubKey);

    // Hash the shared secret: s_h = keccak256(s)
    const hashedSharedSecret = ethers.keccak256(sharedSecret);

    // View tag optimization: check first byte of hashed shared secret
    if (viewTag) {
      const computedViewTag = "0x" + hashedSharedSecret.slice(2, 4);
      if (computedViewTag.toLowerCase() !== viewTag.toLowerCase()) {
        // View tag mismatch - this announcement is not for us (255/256 probability)
        return { isForUser: false };
      }
    }

    // Compute stealth public key: P_stealth = spending_pubkey + (s_h × G)
    const stealthPubKey = addPublicKeys(
      spendingPubKey,
      multiplyGeneratorByScalar(hashedSharedSecret)
    );

    // Derive stealth address from stealth public key
    const derivedAddress = publicKeyToAddress(stealthPubKey);

    // Check if addresses match
    if (derivedAddress.toLowerCase() !== stealthAddress.toLowerCase()) {
      return { isForUser: false };
    }

    return {
      isForUser: true,
      stealthAddress: derivedAddress,
    };
  } catch (error) {
    return { isForUser: false };
  }
}

/**
 * ERC-5564: Compute the stealth private key for spending
 * This allows the recipient to actually spend funds from the stealth address.
 *
 * Algorithm:
 * privkey_stealth = spending_privkey + s_h (mod n)
 *
 * @param viewingKey - Recipient's viewing private key
 * @param spendingKey - Recipient's spending private key
 * @param ephemeralPubKey - Ephemeral public key from announcement
 * @returns The stealth private key
 */
export function computeStealthPrivateKey(
  viewingKey: string,
  spendingKey: string,
  ephemeralPubKey: string
): string {
  try {
    // Compute ECDH shared secret: s = viewing_privkey × ephemeral_pubkey
    const sharedSecret = computeSharedSecret(viewingKey, ephemeralPubKey);

    // Hash the shared secret: s_h = keccak256(s)
    const hashedSharedSecret = ethers.keccak256(sharedSecret);

    // Compute stealth private key: privkey_stealth = spending_privkey + s_h (mod n)
    const stealthPrivKey = addPrivateKeys(spendingKey, hashedSharedSecret);

    return stealthPrivKey;
  } catch (error) {
    throw new CryptoError("Failed to compute stealth private key", error);
  }
}

// ========================================
// ERC-5564 Cryptographic Primitives
// ========================================

/**
 * Compute ECDH shared secret using SECP256k1
 * s = privkey × pubkey
 */
function computeSharedSecret(privateKey: string, publicKey: string): string {
  try {
    const wallet = new ethers.Wallet(privateKey);
    const signingKey = wallet.signingKey;

    // Perform ECDH: multiply the public key by our private key
    // The result is a point on the curve, we take its x-coordinate
    const sharedPoint = signingKey.computeSharedSecret(publicKey);

    return sharedPoint;
  } catch (error) {
    throw new CryptoError("Failed to compute shared secret", error);
  }
}

/**
 * Multiply the generator point G by a scalar
 * Returns compressed public key
 */
function multiplyGeneratorByScalar(scalar: string): string {
  try {
    const wallet = new ethers.Wallet(scalar);
    return wallet.signingKey.compressedPublicKey;
  } catch (error) {
    throw new CryptoError("Failed to multiply generator by scalar", error);
  }
}

/**
 * Add two public keys using elliptic curve point addition
 * P1 + P2
 */
function addPublicKeys(pubKey1: string, pubKey2: string): string {
  try {
    const key1 = ethers.SigningKey.computePublicKey(pubKey1, false); // Uncompressed
    const key2 = ethers.SigningKey.computePublicKey(pubKey2, false); // Uncompressed

    // Extract x and y coordinates (remove 0x04 prefix)
    const x1 = BigInt("0x" + key1.slice(4, 68));
    const y1 = BigInt("0x" + key1.slice(68));
    const x2 = BigInt("0x" + key2.slice(4, 68));
    const y2 = BigInt("0x" + key2.slice(68));

    // SECP256k1 curve parameters
    const p = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

    // Point addition on elliptic curve
    // If points are the same, use point doubling
    if (x1 === x2 && y1 === y2) {
      // Point doubling: lambda = (3*x1^2) / (2*y1)
      const numerator = (3n * x1 * x1) % p;
      const denominator = (2n * y1) % p;
      const lambda = (numerator * modInverse(denominator, p)) % p;

      const x3 = (lambda * lambda - 2n * x1) % p;
      const y3 = (lambda * (x1 - x3) - y1) % p;

      return compressPublicKey((x3 + p) % p, (y3 + p) % p);
    }

    // Regular point addition: lambda = (y2 - y1) / (x2 - x1)
    const numerator = ((y2 - y1) % p + p) % p;
    const denominator = ((x2 - x1) % p + p) % p;
    const lambda = (numerator * modInverse(denominator, p)) % p;

    const x3 = (lambda * lambda - x1 - x2) % p;
    const y3 = (lambda * (x1 - x3) - y1) % p;

    return compressPublicKey((x3 + p) % p, (y3 + p) % p);
  } catch (error) {
    throw new CryptoError("Failed to add public keys", error);
  }
}

/**
 * Add two private keys modulo the curve order
 * (privkey1 + privkey2) mod n
 */
function addPrivateKeys(privKey1: string, privKey2: string): string {
  try {
    // SECP256k1 curve order
    const n = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    const k1 = BigInt(privKey1);
    const k2 = BigInt(privKey2);

    const sum = (k1 + k2) % n;

    // Convert back to hex with proper padding
    return "0x" + sum.toString(16).padStart(64, "0");
  } catch (error) {
    throw new CryptoError("Failed to add private keys", error);
  }
}

/**
 * Compress a public key (x, y) to compressed format
 */
function compressPublicKey(x: bigint, y: bigint): string {
  const prefix = y % 2n === 0n ? "02" : "03";
  return "0x" + prefix + x.toString(16).padStart(64, "0");
}

/**
 * Compute modular inverse using Extended Euclidean Algorithm
 */
function modInverse(a: bigint, m: bigint): bigint {
  a = ((a % m) + m) % m;
  let [oldR, r] = [a, m];
  let [oldS, s] = [1n, 0n];

  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }

  return ((oldS % m) + m) % m;
}

/**
 * Derive Ethereum address from compressed public key
 */
function publicKeyToAddress(compressedPubKey: string): string {
  try {
    // Decompress the public key first
    const uncompressedPubKey = ethers.SigningKey.computePublicKey(compressedPubKey, false);

    // Take keccak256 of uncompressed public key (without 0x04 prefix)
    const pubKeyHash = ethers.keccak256("0x" + uncompressedPubKey.slice(4));

    // Take last 20 bytes as address
    return ethers.getAddress("0x" + pubKeyHash.slice(-40));
  } catch (error) {
    throw new CryptoError("Failed to derive address from public key", error);
  }
}

