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
 * Commitment of the Semaphore v4 identity `new Identity(privateKey)`.
 * Zeroes `privateKey` before returning.
 */
export async function semaphoreCommitment(privateKey: Uint8Array): Promise<bigint> {
  try {
    let Identity: typeof import("@semaphore-protocol/identity").Identity;
    try {
      ({ Identity } = await import("@semaphore-protocol/identity"));
    } catch (error) {
      throw new CryptoError(
        "Semaphore identities require @semaphore-protocol/identity. Install with: pnpm add @semaphore-protocol/identity",
        error
      );
    }
    return new Identity(privateKey).commitment;
  } finally {
    privateKey.fill(0);
  }
}
