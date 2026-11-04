/**
 * ERC-5564 Stealth Address Cryptography
 * Standard-compliant implementation for privacy-preserving transactions
 *
 * @see https://eips.ethereum.org/EIPS/eip-5564
 */

import { ethers } from "ethers";
import { secp256k1 } from "@noble/curves/secp256k1.js";
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

    // Reduce s_h modulo curve order to ensure it's a valid scalar
    const reducedScalar = reduceScalarModN(hashedSharedSecret);

    // Compute stealth public key: P_stealth = spending_pubkey + (s_h × G)
    const stealthPubKey = computeStealthPublicKey(spendingPubKey, reducedScalar);

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
 * @returns ParseResult with the stealth address if it belongs to the user
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

    // Reduce s_h modulo curve order to ensure it's a valid scalar
    const reducedScalar = reduceScalarModN(hashedSharedSecret);

    // Compute stealth public key: P_stealth = spending_pubkey + (s_h × G)
    const stealthPubKey = computeStealthPublicKey(spendingPubKey, reducedScalar);

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

    // Reduce s_h modulo curve order to ensure it's a valid scalar
    const reducedScalar = reduceScalarModN(hashedSharedSecret);

    // Compute stealth private key: privkey_stealth = spending_privkey + s_h (mod n)
    const stealthPrivKey = addPrivateKeys(spendingKey, reducedScalar);

    return stealthPrivKey;
  } catch (error) {
    throw new CryptoError("Failed to compute stealth private key", error);
  }
}

/**
 * ERC-5564: Check if user can control a stealth address
 * Verifies that the user's keys can derive the correct private key for a stealth address.
 *
 * @param viewingKey - Recipient's viewing private key
 * @param spendingKey - Recipient's spending private key
 * @param spendingPubKey - Recipient's spending public key (compressed)
 * @param ephemeralPubKey - Ephemeral public key from announcement
 * @param stealthAddress - The stealth address to verify control of
 * @param viewTag - View tag from announcement (optional, for optimization)
 * @returns True if the user can control the stealth address
 */
export function canControlStealthAddress(
  viewingKey: string,
  spendingKey: string,
  spendingPubKey: string,
  ephemeralPubKey: string,
  stealthAddress: string,
  viewTag?: string
): boolean {
  try {
    // First, check if this stealth address belongs to the user
    const checkResult = checkStealthAddress(
      viewingKey,
      spendingPubKey,
      ephemeralPubKey,
      stealthAddress,
      viewTag
    );

    if (!checkResult.isForUser) {
      return false;
    }

    // Compute the stealth private key
    const stealthPrivKey = computeStealthPrivateKey(
      viewingKey,
      spendingKey,
      ephemeralPubKey
    );

    // Verify the private key controls the stealth address
    const wallet = new ethers.Wallet(stealthPrivKey);
    const derivedAddress = wallet.address;

    return derivedAddress.toLowerCase() === stealthAddress.toLowerCase();
  } catch (error) {
    return false;
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
 * Compute the stealth public key P_stealth = spending_pubkey + (scalar × G)
 *
 * @throws CryptoError if the sum is the point at infinity
 */
export function computeStealthPublicKey(
  spendingPubKey: string,
  scalar: string
): string {
  const { Point } = secp256k1;
  let point;
  try {
    point = Point.fromHex(spendingPubKey.replace(/^0x/, "")).add(
      Point.BASE.multiply(BigInt(scalar))
    );
  } catch (error) {
    throw new CryptoError("Failed to compute stealth public key", error);
  }
  if (point.is0()) {
    throw new CryptoError("Stealth public key is the point at infinity");
  }
  return "0x" + point.toHex(true);
}

/**
 * Reduce a scalar modulo the secp256k1 curve order
 * Ensures the scalar is in the valid range [1, n-1]
 *
 * @param scalar - The scalar to reduce (as hex string)
 * @returns Reduced scalar in valid range
 * @throws CryptoError if scalar is zero after reduction
 */
function reduceScalarModN(scalar: string): string {
  const reduced = secp256k1.Point.Fn.create(BigInt(scalar));
  if (reduced === 0n) {
    throw new CryptoError("Scalar reduced to zero (invalid)");
  }
  return ethers.toBeHex(reduced, 32);
}

/**
 * Add two private keys modulo the curve order
 * (privkey1 + privkey2) mod n
 *
 * @throws CryptoError if the sum is zero
 */
function addPrivateKeys(privKey1: string, privKey2: string): string {
  const sum = secp256k1.Point.Fn.add(BigInt(privKey1), BigInt(privKey2));
  if (sum === 0n) {
    throw new CryptoError("Stealth private key is zero");
  }
  return ethers.toBeHex(sum, 32);
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

