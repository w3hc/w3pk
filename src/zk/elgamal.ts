/**
 * Exponential ElGamal over Baby Jubjub
 * Enc(m; r) = (r · B, m · B + r · PK), with B = BABYJUB_BASE8
 */

import { CryptoError } from "../core/errors";
import {
  BABYJUB_BASE8,
  BABYJUB_SUBORDER,
  assertBabyJubPrivateKey,
  assertBabyJubPublicKey,
  babyJubAdd,
  babyJubDiscreteLog,
  babyJubMul,
  babyJubNeg,
  isInBabyJubSubgroup,
  randomBabyJubScalar,
  type BabyJubPoint,
} from "./babyjub";

export interface ElGamalCiphertext {
  /** `r · B` */
  c1: BabyJubPoint;
  /** `m · B + r · PK` */
  c2: BabyJubPoint;
}

function assertCiphertext(ciphertext: ElGamalCiphertext): void {
  if (
    !ciphertext ||
    !isInBabyJubSubgroup(ciphertext.c1) ||
    !isInBabyJubSubgroup(ciphertext.c2)
  ) {
    throw new CryptoError(
      "Invalid ElGamal ciphertext: points must be in the Baby Jubjub prime-order subgroup"
    );
  }
}

function assertRandomness(r: bigint): void {
  if (typeof r !== "bigint" || r < 1n || r >= BABYJUB_SUBORDER) {
    throw new CryptoError("ElGamal randomness must be in [1, l)");
  }
}

/**
 * Encrypt `message` in `[0, l)` to `publicKey`. `r` defaults to a fresh
 * random scalar; pass it when a proof needs it as a witness
 */
export function elgamalEncrypt(
  publicKey: BabyJubPoint,
  message: bigint,
  r: bigint = randomBabyJubScalar()
): ElGamalCiphertext {
  assertBabyJubPublicKey(publicKey);
  if (typeof message !== "bigint" || message < 0n || message >= BABYJUB_SUBORDER) {
    throw new CryptoError("ElGamal message must be in [0, l)");
  }
  assertRandomness(r);
  return {
    c1: babyJubMul(BABYJUB_BASE8, r),
    c2: babyJubAdd(babyJubMul(BABYJUB_BASE8, message), babyJubMul(publicKey, r)),
  };
}

/**
 * Ciphertext of `m1 + m2` under the same key, with randomness `r1 + r2`
 */
export function elgamalAdd(
  a: ElGamalCiphertext,
  b: ElGamalCiphertext
): ElGamalCiphertext {
  assertCiphertext(a);
  assertCiphertext(b);
  return { c1: babyJubAdd(a.c1, b.c1), c2: babyJubAdd(a.c2, b.c2) };
}

/**
 * Same plaintext under fresh randomness: adds an encryption of 0 with `r`
 */
export function elgamalRerandomize(
  publicKey: BabyJubPoint,
  ciphertext: ElGamalCiphertext,
  r: bigint = randomBabyJubScalar()
): ElGamalCiphertext {
  assertCiphertext(ciphertext);
  const zero = elgamalEncrypt(publicKey, 0n, r);
  return {
    c1: babyJubAdd(ciphertext.c1, zero.c1),
    c2: babyJubAdd(ciphertext.c2, zero.c2),
  };
}

/**
 * Recover `m · B = c2 - privateKey · c1`
 */
export function elgamalDecryptToPoint(
  privateKey: bigint,
  ciphertext: ElGamalCiphertext
): BabyJubPoint {
  assertBabyJubPrivateKey(privateKey);
  assertCiphertext(ciphertext);
  return babyJubAdd(ciphertext.c2, babyJubNeg(babyJubMul(ciphertext.c1, privateKey)));
}

/**
 * Decrypt a message known to be in `[0, maxValue]`, such as a tally.
 * Throws when the plaintext is out of range
 */
export function elgamalDecrypt(
  privateKey: bigint,
  ciphertext: ElGamalCiphertext,
  maxValue: number
): bigint {
  const m = babyJubDiscreteLog(elgamalDecryptToPoint(privateKey, ciphertext), maxValue);
  if (m === null) {
    throw new CryptoError(`ElGamal plaintext is not in [0, ${maxValue}]`);
  }
  return m;
}
