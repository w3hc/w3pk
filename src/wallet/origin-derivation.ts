import { deriveWalletFromMnemonic } from "./generate";
import { WalletError } from "../core/errors";
import type { SecurityMode } from "../types";
import { keccak256 } from "ethers";

export const DEFAULT_MODE: SecurityMode = "STANDARD";
export const DEFAULT_TAG = "MAIN";

const MAX_INDEX = 0x7fffffff;

/**
 * Normalize origin URL for consistent derivation
 */
export function normalizeOrigin(origin: string): string {
  try {
    const url = new URL(origin);
    let normalized = `${url.protocol}//${url.hostname.toLowerCase()}`;

    const port = url.port;
    if (port &&
        !((url.protocol === 'https:' && port === '443') ||
          (url.protocol === 'http:' && port === '80'))) {
      normalized += `:${port}`;
    }

    return normalized;
  } catch (error) {
    throw new WalletError(
      `Invalid origin URL: ${origin}`,
      error
    );
  }
}

/**
 * Derive deterministic index from origin, mode, and tag using SHA-256
 * Ensures valid BIP32 non-hardened index in range [0, 2^31-1]
 */
export async function deriveIndexFromOriginModeAndTag(
  origin: string,
  mode: SecurityMode = DEFAULT_MODE,
  tag: string = DEFAULT_TAG
): Promise<number> {
  try {
    const normalizedOrigin = normalizeOrigin(origin);
    const combined = `${normalizedOrigin}:${mode}:${tag.toUpperCase()}`;

    const encoder = new TextEncoder();
    const data = encoder.encode(combined);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    const view = new DataView(hashBuffer);
    const uint32 = view.getUint32(0, false);
    const index = uint32 % MAX_INDEX;

    return index;
  } catch (error) {
    throw new WalletError(
      `Failed to derive index from origin "${origin}", mode "${mode}", and tag "${tag}"`,
      error
    );
  }
}

/**
 * Derive origin-specific address with mode and tag support
 *
 * SECURITY:
 * - STANDARD mode: Private key NOT exposed, persistent sessions allowed
 * - STRICT mode: Private key NOT exposed, persistent sessions NOT allowed
 * - YOLO mode: Private key exposed, persistent sessions allowed
 */
export async function getOriginSpecificAddress(
  mnemonic: string,
  origin: string,
  mode?: SecurityMode,
  tag?: string
): Promise<{
  address: string;
  privateKey?: string;
  index: number;
  origin: string;
  mode: SecurityMode;
  tag: string;
}> {
  try {
    const effectiveMode = mode || DEFAULT_MODE;
    const effectiveTag = (tag || DEFAULT_TAG).toUpperCase();
    const normalizedOrigin = normalizeOrigin(origin);
    const index = await deriveIndexFromOriginModeAndTag(normalizedOrigin, effectiveMode, effectiveTag);
    const { address, privateKey } = deriveWalletFromMnemonic(mnemonic, index);

    const result: {
      address: string;
      privateKey?: string;
      index: number;
      origin: string;
      mode: SecurityMode;
      tag: string;
    } = {
      address,
      index,
      origin: normalizedOrigin,
      mode: effectiveMode,
      tag: effectiveTag,
    };

    // YOLO mode exposes private key
    if (effectiveMode === 'YOLO') {
      result.privateKey = privateKey;
    }

    return result;
  } catch (error) {
    throw new WalletError(
      `Failed to derive origin-specific address for "${origin}" with mode "${mode || DEFAULT_MODE}" and tag "${tag || DEFAULT_TAG}"`,
      error
    );
  }
}

/**
 * Get current browser origin
 * @throws Error if not in browser environment
 */
export function getCurrentOrigin(): string {
  if (typeof window === 'undefined' || !window.location) {
    throw new WalletError('getCurrentOrigin() only works in browser environments');
  }

  return window.location.origin;
}

/**
 * Derive Ethereum address from P-256 public key (EIP-7951)
 * Uses the last 20 bytes of keccak256(uncompressed_public_key_without_prefix)
 *
 * @param publicKeySpki - Public key in SPKI format (base64url encoded)
 * @returns Ethereum address (0x-prefixed hex string)
 */
export async function deriveAddressFromP256PublicKey(publicKeySpki: string): Promise<string> {
  try {
    // Decode base64url to ArrayBuffer
    const publicKeyBuffer = base64UrlToArrayBuffer(publicKeySpki);

    // Import the public key
    const publicKey = await crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["verify"]
    );

    // Export as JWK to get x and y coordinates
    const jwk = await crypto.subtle.exportKey("jwk", publicKey);

    if (!jwk.x || !jwk.y) {
      throw new Error("Invalid P-256 public key: missing x or y coordinates");
    }

    // Convert base64url x and y to bytes (each is 32 bytes for P-256)
    const xBytes = base64UrlToArrayBuffer(jwk.x);
    const yBytes = base64UrlToArrayBuffer(jwk.y);

    // Create uncompressed public key: 0x04 || x || y (65 bytes total)
    // For Ethereum address derivation, we skip the 0x04 prefix
    const uncompressedKey = new Uint8Array(64);
    uncompressedKey.set(new Uint8Array(xBytes), 0);
    uncompressedKey.set(new Uint8Array(yBytes), 32);

    // Hash with keccak256
    const hash = keccak256(uncompressedKey);

    // Take last 20 bytes as Ethereum address
    const address = '0x' + hash.slice(-40);

    return address;
  } catch (error) {
    throw new WalletError(
      "Failed to derive address from P-256 public key",
      error
    );
  }
}

/**
 * Helper function to decode base64url to ArrayBuffer
 */
function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const base64Padded = base64 + padding;
  const binaryString = atob(base64Padded);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}
