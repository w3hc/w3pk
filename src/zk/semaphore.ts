/**
 * Semaphore v4 identities bound to a passkey
 */

import { CryptoError } from "../core/errors";

export interface SemaphoreIdentity {
  /** Poseidon(publicKey), the member value apps add to a Semaphore group */
  commitment: bigint;
  /** Credential the identity is bound to; a new credential gives a new commitment */
  credentialId: string;
}

/** PRF label for Semaphore identities, unreachable from `derivePrfSecret(tag)` */
export const SEMAPHORE_PRF_LABEL = "w3pk-semaphore-v1";

/**
 * Load `@semaphore-protocol/identity` and return a function giving the
 * commitment of `new Identity(privateKey)`. Load it before prompting, so a
 * missing dependency doesn't waste a passkey prompt.
 *
 * The returned function zeroes `privateKey`; copies the library makes stay
 * on the heap until garbage collection.
 */
export async function loadSemaphoreCommitment(): Promise<(privateKey: Uint8Array) => bigint> {
  let Identity: typeof import("@semaphore-protocol/identity").Identity;
  try {
    ({ Identity } = await import("@semaphore-protocol/identity"));
  } catch (error) {
    throw new CryptoError(
      "Semaphore identities require @semaphore-protocol/identity. Install with: pnpm add @semaphore-protocol/identity",
      error
    );
  }
  return (privateKey) => {
    try {
      return new Identity(privateKey).commitment;
    } finally {
      privateKey.fill(0);
    }
  };
}
