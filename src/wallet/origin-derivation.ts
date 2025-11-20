import { deriveWalletFromMnemonic } from "./generate";
import { WalletError } from "../core/errors";

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
 * Derive deterministic index from origin and tag using SHA-256
 * Ensures valid BIP32 non-hardened index in range [0, 2^31-1]
 */
export async function deriveIndexFromOriginAndTag(
  origin: string,
  tag: string = DEFAULT_TAG
): Promise<number> {
  try {
    const normalizedOrigin = normalizeOrigin(origin);
    const combined = `${normalizedOrigin}:${tag.toUpperCase()}`;

    const encoder = new TextEncoder();
    const data = encoder.encode(combined);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    const view = new DataView(hashBuffer);
    const uint32 = view.getUint32(0, false);
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
 * Derive origin-specific address with tag support
 *
 * SECURITY:
 * - MAIN tag: Private key NOT exposed
 * - Custom tags: Private key included
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
    const effectiveTag = (tag || DEFAULT_TAG).toUpperCase();
    const normalizedOrigin = normalizeOrigin(origin);
    const index = await deriveIndexFromOriginAndTag(normalizedOrigin, effectiveTag);
    const { address, privateKey } = deriveWalletFromMnemonic(mnemonic, index);

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
 * Get current browser origin
 * @throws Error if not in browser environment
 */
export function getCurrentOrigin(): string {
  if (typeof window === 'undefined' || !window.location) {
    throw new WalletError('getCurrentOrigin() only works in browser environments');
  }

  return window.location.origin;
}
