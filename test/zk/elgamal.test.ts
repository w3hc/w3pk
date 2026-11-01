/**
 * Exponential ElGamal over Baby Jubjub
 *
 * The fixed vector is cross-checked against circomlibjs's buildBabyjub()
 */

import {
  BABYJUB_BASE8,
  BABYJUB_GENERATOR,
  BABYJUB_IDENTITY,
  BABYJUB_SUBORDER,
  babyJubAdd,
  babyJubMul,
  babyJubPublicKey,
  generateBabyJubKeyPair,
  type BabyJubPoint,
} from "../../src/zk/babyjub";
import {
  elgamalAdd,
  elgamalDecrypt,
  elgamalDecryptToPoint,
  elgamalEncrypt,
  elgamalRerandomize,
  type ElGamalCiphertext,
} from "../../src/zk/elgamal";
import { CryptoError } from "../../src/core/errors";

console.log("\n==================================================");
console.log("🗳️  ElGamal Test");
console.log("==================================================\n");

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    console.log(`  ✅ ${message}`);
    passed++;
  } else {
    console.log(`  ❌ ${message}`);
    failed++;
  }
}

function throwsCrypto(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch (error) {
    return error instanceof CryptoError;
  }
}

function eq(p: BabyJubPoint, q: BabyJubPoint): boolean {
  return p[0] === q[0] && p[1] === q[1];
}

function ctEq(a: ElGamalCiphertext, b: ElGamalCiphertext): boolean {
  return eq(a.c1, b.c1) && eq(a.c2, b.c2);
}

const SK = 123456789n;
const R = 987654321n;
const VECTOR: ElGamalCiphertext = {
  c1: [
    3786052435012899366340248208277520368404678617497448646358239296295828943121n,
    16449606152468185267122726090513598979225798443847928573493676725305587856616n,
  ],
  c2: [
    457189970420488735327737865387086290878096636359751446136526888841897522889n,
    14835370641715383297728459926564563293117908196212518248628858221799030702362n,
  ],
};

async function runTests() {
  console.log("vectors");
  {
    const pk = babyJubPublicKey(SK);
    assert(ctEq(elgamalEncrypt(pk, 42n, R), VECTOR), "Enc(42; r) matches the fixed vector");

    const circomlibjs = await import("circomlibjs");
    const bj = await circomlibjs.buildBabyjub();
    const F = bj.F;
    const toObj = (p: any): BabyJubPoint => [F.toObject(p[0]), F.toObject(p[1])];
    const refPk = bj.mulPointEscalar(bj.Base8, SK);
    const refC1 = bj.mulPointEscalar(bj.Base8, R);
    const refC2 = bj.addPoint(bj.mulPointEscalar(bj.Base8, 42n), bj.mulPointEscalar(refPk, R));
    assert(eq(toObj(refC1), VECTOR.c1) && eq(toObj(refC2), VECTOR.c2), "vector matches circomlibjs");
    assert(elgamalDecrypt(SK, VECTOR, 100) === 42n, "vector decrypts to 42");
  }
  console.log("");

  console.log("round trips");
  {
    const { privateKey, publicKey } = generateBabyJubKeyPair();
    let ok = true;
    for (const m of [0n, 1n, 7n, 1000n]) {
      if (elgamalDecrypt(privateKey, elgamalEncrypt(publicKey, m), 1000) !== m) ok = false;
    }
    assert(ok, "encrypt then decrypt recovers small values");

    const big = BABYJUB_SUBORDER - 1n;
    assert(
      eq(elgamalDecryptToPoint(privateKey, elgamalEncrypt(publicKey, big)), babyJubMul(BABYJUB_BASE8, big)),
      "decryptToPoint recovers m · B for any m"
    );

    const a = elgamalEncrypt(publicKey, 0n);
    const b = elgamalEncrypt(publicKey, 0n);
    assert(!ctEq(a, b), "default randomness differs between encryptions");
  }
  console.log("");

  console.log("homomorphic addition");
  {
    const { privateKey, publicKey } = generateBabyJubKeyPair();
    const votes = [1n, 0n, 1n, 1n, 0n, 1n];
    const tally = votes.map((v) => elgamalEncrypt(publicKey, v)).reduce(elgamalAdd);
    assert(elgamalDecrypt(privateKey, tally, votes.length) === 4n, "sum of encryptions decrypts to the sum");

    const r1 = 11n;
    const r2 = 22n;
    const sum = elgamalAdd(elgamalEncrypt(publicKey, 5n, r1), elgamalEncrypt(publicKey, 6n, r2));
    assert(ctEq(sum, elgamalEncrypt(publicKey, 11n, r1 + r2)), "Enc(m1; r1) + Enc(m2; r2) = Enc(m1 + m2; r1 + r2)");
  }
  console.log("");

  console.log("re-randomization");
  {
    const { privateKey, publicKey } = generateBabyJubKeyPair();
    const ct = elgamalEncrypt(publicKey, 3n, 5n);
    const fresh = elgamalRerandomize(publicKey, ct);
    assert(!eq(fresh.c1, ct.c1) && !eq(fresh.c2, ct.c2), "both components change");
    assert(elgamalDecrypt(privateKey, fresh, 10) === 3n, "plaintext is unchanged");
    assert(ctEq(elgamalRerandomize(publicKey, ct, 7n), elgamalEncrypt(publicKey, 3n, 12n)), "Rerand(Enc(m; r), r') = Enc(m; r + r')");
  }
  console.log("");

  console.log("rejections");
  {
    const { privateKey, publicKey } = generateBabyJubKeyPair();
    const torsion = babyJubMul(BABYJUB_GENERATOR, BABYJUB_SUBORDER);
    const ct = elgamalEncrypt(publicKey, 1n);

    assert(throwsCrypto(() => elgamalEncrypt(torsion, 1n)), "encrypt rejects a low-order public key");
    assert(throwsCrypto(() => elgamalEncrypt(BABYJUB_IDENTITY, 1n)), "encrypt rejects the identity public key");
    assert(throwsCrypto(() => elgamalEncrypt(babyJubAdd(publicKey, torsion), 1n)), "encrypt rejects a key with a torsion component");
    assert(throwsCrypto(() => elgamalEncrypt([1n, 2n], 1n)), "encrypt rejects an off-curve key");
    assert(throwsCrypto(() => elgamalEncrypt(publicKey, -1n)), "encrypt rejects a negative message");
    assert(throwsCrypto(() => elgamalEncrypt(publicKey, BABYJUB_SUBORDER)), "encrypt rejects a message ≥ l");
    assert(throwsCrypto(() => elgamalEncrypt(publicKey, 1n, 0n)), "encrypt rejects r = 0");
    assert(throwsCrypto(() => elgamalEncrypt(publicKey, 1n, BABYJUB_SUBORDER)), "encrypt rejects r ≥ l");

    const tampered = { c1: babyJubAdd(ct.c1, torsion), c2: ct.c2 };
    assert(throwsCrypto(() => elgamalDecrypt(privateKey, tampered, 10)), "decrypt rejects a low-order component");
    assert(throwsCrypto(() => elgamalAdd(ct, tampered)), "add rejects a low-order component");
    assert(throwsCrypto(() => elgamalRerandomize(publicKey, tampered)), "rerandomize rejects a low-order component");
    assert(throwsCrypto(() => elgamalDecrypt(0n, ct, 10)), "decrypt rejects private key 0");
    assert(throwsCrypto(() => elgamalDecrypt(privateKey, elgamalEncrypt(publicKey, 11n), 10)), "decrypt throws above maxValue");
  }
  console.log("");

  console.log("==================================================");
  console.log(`✅ ElGamal Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
  process.exit(0);
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
