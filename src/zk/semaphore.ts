/**
 * Semaphore v4 identities bound to a passkey or to the wallet seed
 */

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { CryptoError } from "../core/errors";

export interface SemaphoreIdentity {
  /** Poseidon(publicKey), the member value apps add to a Semaphore group */
  commitment: bigint;
  /** Credential the identity is bound to; a new credential gives a new commitment */
  credentialId: string;
}

/** PRF label for Semaphore identities, unreachable from `derivePrfSecret(tag)` */
export const SEMAPHORE_PRF_LABEL = "w3pk-semaphore-v1";

/** HKDF salt for NFT holder identities, derived from the wallet seed */
export const NFT_HOLDER_LABEL = "w3pk-nft-holder-v1";

/**
 * Private key of the Semaphore identity that holds `contractAddress`'s
 * tokens on `origin`: HKDF-SHA256(BIP-39 seed, salt `w3pk-nft-holder-v1`,
 * info `origin:contract`), 32 bytes. One identity per origin and contract,
 * so holder trees of different collections don't share a commitment.
 *
 * @param seed - 64-byte BIP-39 seed
 * @param origin - Normalized origin
 * @param contractAddress - 0x-prefixed 20-byte address, case-insensitive
 */
export function deriveNFTHolderKey(
  seed: Uint8Array,
  origin: string,
  contractAddress: string
): Uint8Array {
  if (!/^0x[0-9a-fA-F]{40}$/.test(contractAddress)) {
    throw new CryptoError(`Invalid contract address: ${contractAddress}`);
  }
  const encoder = new TextEncoder();
  return hkdf(
    sha256,
    seed,
    encoder.encode(NFT_HOLDER_LABEL),
    encoder.encode(`${origin}:${contractAddress.toLowerCase()}`),
    32
  );
}

async function importIdentity(): Promise<typeof import("@semaphore-protocol/identity").Identity> {
  try {
    return (await import("@semaphore-protocol/identity")).Identity;
  } catch (error) {
    throw new CryptoError(
      "Semaphore identities require @semaphore-protocol/identity. Install with: pnpm add @semaphore-protocol/identity",
      error
    );
  }
}

/**
 * Load `@semaphore-protocol/identity` and return a function giving the
 * commitment of `new Identity(privateKey)`. Load it before prompting, so a
 * missing dependency doesn't waste a passkey prompt.
 *
 * The returned function zeroes `privateKey`; copies the library makes stay
 * on the heap until garbage collection.
 */
export async function loadSemaphoreCommitment(): Promise<(privateKey: Uint8Array) => bigint> {
  const Identity = await importIdentity();
  return (privateKey) => {
    try {
      return new Identity(privateKey).commitment;
    } finally {
      privateKey.fill(0);
    }
  };
}

/**
 * Same as `loadSemaphoreCommitment`, giving the identity's `secretScalar`,
 * the private input of Semaphore-style circuits
 */
export async function loadSemaphoreSecretScalar(): Promise<(privateKey: Uint8Array) => bigint> {
  const Identity = await importIdentity();
  return (privateKey) => {
    try {
      return new Identity(privateKey).secretScalar;
    } finally {
      privateKey.fill(0);
    }
  };
}
