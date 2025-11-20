/**
 * Origin-specific address derivation with tag support
 * Allows generating different addresses for the same origin using tags
 */

import { deriveWalletFromMnemonic } from "./generate";
import { WalletError } from "../core/errors";

/**
 * Default tag used when no tag is specified
 */
export const DEFAULT_TAG = "MAIN";

/**
 * Maximum BIP32 non-hardened index (2^31 - 1)
 */
const MAX_INDEX = 0x7fffffff;

/**
 * Normalizes an origin URL to ensure consistent derivation
 * - Converts to lowercase
 * - Removes trailing slash
 * - Handles standard ports (443 for https, 80 for http)
 * - Preserves protocol and subdomain
 */
export function normalizeOrigin(origin: string): string {
  try {
    const url = new URL(origin);

    // Normalize: lowercase hostname, remove default ports, no trailing slash
    let normalized = `${url.protocol}//${url.hostname.toLowerCase()}`;

    // Add port if non-standard
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
 * Derives a deterministic index from origin and tag using SHA-256
 *
 * Algorithm:
 * 1. Combine origin and tag as "${origin}:${tag}"
 * 2. SHA-256 hash the combined string
 * 3. Take first 4 bytes of hash
 * 4. Convert to uint32 (big-endian)
 * 5. Modulo 2^31-1 to ensure valid BIP32 non-hardened index
 *
 * @param origin - The origin URL (e.g., "https://example.com")
 * @param tag - The tag to distinguish different addresses (default: "MAIN")
 * @returns A deterministic index in range [0, 2^31-1]
 */
export async function deriveIndexFromOriginAndTag(
  origin: string,
  tag: string = DEFAULT_TAG
): Promise<number> {
  try {
    // Normalize the origin
    const normalizedOrigin = normalizeOrigin(origin);

    // Combine origin and tag
    const combined = `${normalizedOrigin}:${tag.toUpperCase()}`;

    // Hash using SHA-256
    const encoder = new TextEncoder();
    const data = encoder.encode(combined);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    // Convert first 4 bytes to uint32 (big-endian)
    const view = new DataView(hashBuffer);
    const uint32 = view.getUint32(0, false); // false = big-endian

    // Ensure non-hardened index (< 2^31)
    const index = uint32 % MAX_INDEX;

    return index;
  } catch (error) {
    throw new WalletError(
      `Failed to derive index from origin "${origin}" and tag "${tag}"`,
      error
    );
  }
}

/**
 * Derives an origin-specific address from mnemonic with optional tag support
 *
 * SECURITY: Private key is NOT exposed for MAIN tag wallets to protect the primary wallet.
 * Only non-MAIN tagged wallets can access their private keys.
 *
 * @param mnemonic - The BIP39 mnemonic phrase
 * @param origin - The origin URL (e.g., "https://example.com")
 * @param tag - Optional tag to generate different addresses for same origin (default: "MAIN")
 * @returns Wallet with address, optional private key (omitted for MAIN tag), index, origin, and tag
 *
 * @example
 * // Get main address for example.com (privateKey will be undefined)
 * const mainWallet = await getOriginSpecificAddress(mnemonic, "https://example.com");
 *
 * // Get gaming-specific address for example.com (privateKey will be included)
 * const gamingWallet = await getOriginSpecificAddress(mnemonic, "https://example.com", "GAMING");
 *
 * // Get simple-specific address for example.com (privateKey will be included)
 * const simpleWallet = await getOriginSpecificAddress(mnemonic, "https://example.com", "SIMPLE");
 */
export async function getOriginSpecificAddress(
  mnemonic: string,
  origin: string,
  tag?: string
): Promise<{
  address: string;
  privateKey?: string;
  index: number;
  origin: string;
  tag: string;
}> {
  try {
    // Use default tag if not provided, normalize to uppercase
    const effectiveTag = (tag || DEFAULT_TAG).toUpperCase();

    // Normalize origin
    const normalizedOrigin = normalizeOrigin(origin);

    // Derive index from origin and tag
    const index = await deriveIndexFromOriginAndTag(normalizedOrigin, effectiveTag);

    // Derive wallet at the computed index
    const { address, privateKey } = deriveWalletFromMnemonic(mnemonic, index);

    // SECURITY: Only expose private key for non-MAIN tagged wallets
    const result: {
      address: string;
      privateKey?: string;
      index: number;
      origin: string;
      tag: string;
    } = {
      address,
      index,
      origin: normalizedOrigin,
      tag: effectiveTag,
    };

    // Only include privateKey if tag is NOT "MAIN"
    if (effectiveTag !== DEFAULT_TAG) {
      result.privateKey = privateKey;
    }

    return result;
  } catch (error) {
    throw new WalletError(
      `Failed to derive origin-specific address for "${origin}" with tag "${tag || DEFAULT_TAG}"`,
      error
    );
  }
}

/**
 * Gets the current browser origin
 * Only works in browser environments
 *
 * @returns Current origin (e.g., "https://example.com")
 * @throws Error if not in browser environment
 */
export function getCurrentOrigin(): string {
  if (typeof window === 'undefined' || !window.location) {
    throw new WalletError('getCurrentOrigin() only works in browser environments');
  }

  return window.location.origin;
}
