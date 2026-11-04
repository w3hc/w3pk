import { deriveWalletFromPath } from "./generate";
import { WalletError } from "../core/errors";
import type { SecurityMode } from "../types";
import { keccak256 } from "ethers";
import { base64UrlToArrayBuffer } from "../utils/base64";

export const DEFAULT_MODE: SecurityMode = "STANDARD";
export const DEFAULT_TAG = "MAIN";

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

const HARDENED_MASK = 0x7fffffff;

const MODE_LEVELS: Record<SecurityMode, number> = {
  STANDARD: 0,
  STRICT: 1,
  YOLO: 2,
  PRIMARY: 3,
};

async function sha256(data: BufferSource): Promise<DataView> {
  return new DataView(await crypto.subtle.digest('SHA-256', data));
}

/**
 * Derive the BIP-32 path of an origin, mode and tag:
 * `m/13'/A'/B'/C'/D'/mode'/tag'`, every level hardened.
 *
 * - A..D: SLIP-0013 service identity of the normalized origin with index 0:
 *   the first 16 bytes of SHA-256(LE32(0) || origin), as four little-endian uint32
 * - mode: STANDARD=0', STRICT=1', YOLO=2', PRIMARY=3'
 * - tag: first 4 bytes of SHA-256(uppercased tag), big-endian, low 31 bits
 *
 * The origin levels carry 124 bits of SHA-256, so no tag or mode chosen on one
 * origin reaches another origin's subtree, and with hardened levels a leaked
 * child key reveals nothing about its siblings or parents.
 */
export async function deriveOriginPath(
  origin: string,
  mode: SecurityMode = DEFAULT_MODE,
  tag: string = DEFAULT_TAG
): Promise<string> {
  try {
    if (!Object.prototype.hasOwnProperty.call(MODE_LEVELS, mode)) {
      throw new Error(`Unknown security mode: ${mode}`);
    }

    const encoder = new TextEncoder();
    const uri = encoder.encode(normalizeOrigin(origin));
    const identity = new Uint8Array(4 + uri.length);
    identity.set(uri, 4);

    const originHash = await sha256(identity);
    const originLevels = [0, 4, 8, 12].map(
      (offset) => originHash.getUint32(offset, true) & HARDENED_MASK
    );

    const tagHash = await sha256(encoder.encode(tag.toUpperCase()));
    const tagLevel = tagHash.getUint32(0, false) & HARDENED_MASK;

    const levels = [13, ...originLevels, MODE_LEVELS[mode], tagLevel];
    return `m/${levels.map((level) => `${level}'`).join('/')}`;
  } catch (error) {
    throw new WalletError(
      `Failed to derive path from origin "${origin}", mode "${mode}", and tag "${tag}"`,
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
 *
 * The key is derived at the fully hardened path from `deriveOriginPath`.
 */
export async function getOriginSpecificAddress(
  mnemonic: string,
  origin: string,
  mode?: SecurityMode,
  tag?: string
): Promise<{
  address: string;
  privateKey?: string;
  path: string;
  origin: string;
  mode: SecurityMode;
  tag: string;
}> {
  try {
    const effectiveMode = mode || DEFAULT_MODE;
    const effectiveTag = (tag || DEFAULT_TAG).toUpperCase();
    const normalizedOrigin = normalizeOrigin(origin);
    const path = await deriveOriginPath(normalizedOrigin, effectiveMode, effectiveTag);
    const { address, privateKey } = deriveWalletFromPath(mnemonic, path);

    const result: {
      address: string;
      privateKey?: string;
      path: string;
      origin: string;
      mode: SecurityMode;
      tag: string;
    } = {
      address,
      path,
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

