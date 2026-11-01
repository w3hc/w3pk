/**
 * Baby Jubjub point arithmetic, packing and keys
 *
 * Vectors come from circomlib's test/babyjub.js and are cross-checked
 * against circomlibjs's buildBabyjub()
 */

import {
  BABYJUB_BASE8,
  BABYJUB_FIELD,
  BABYJUB_GENERATOR,
  BABYJUB_IDENTITY,
  BABYJUB_SUBORDER,
  babyJubAdd,
  babyJubMul,
  babyJubNeg,
  babyJubPublicKey,
  babyJubDiscreteLog,
  deriveBabyJubKeyPair,
  generateBabyJubKeyPair,
  isInBabyJubSubgroup,
  isOnBabyJub,
  isValidBabyJubPublicKey,
  packBabyJubPoint,
  packBabyJubPublicKey,
  unpackBabyJubPoint,
  unpackBabyJubPublicKey,
  type BabyJubPoint,
} from "../../src/zk/babyjub";
import { CryptoError } from "../../src/core/errors";

console.log("\n==================================================");
console.log("🐘 Baby Jubjub Test");
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

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

const P1: BabyJubPoint = [
  17777552123799933955779906779655732241715742912184938656739573121738514868268n,
  2626589144620713026669568689430873010625803728049924121243784502389097019475n,
];
const P2: BabyJubPoint = [
  16540640123574156134436876038791482806971768689494387082833631921987005038935n,
  20819045374670962167435360035096875258406992893633759881276124905556507972311n,
];

async function runTests() {
  console.log("circomlib vectors");
  {
    assert(eq(babyJubAdd(BABYJUB_IDENTITY, BABYJUB_IDENTITY), BABYJUB_IDENTITY), "(0,1) + (0,1) = (0,1)");
    assert(
      eq(babyJubAdd(P1, P1), [
        6890855772600357754907169075114257697580319025794532037257385534741338397365n,
        4338620300185947561074059802482547481416142213883829469920100239455078257889n,
      ]),
      "adds 2 same numbers"
    );
    assert(
      eq(babyJubAdd(P1, P2), [
        7916061937171219682591368294088513039687205273691143098332585753343424131937n,
        14035240266687799601661095864649209771790948434046947201833777492504781204499n,
      ]),
      "adds 2 different numbers"
    );
    assert(isOnBabyJub([0n, 1n]), "(0,1) is a valid point");
    assert(!isOnBabyJub([1n, 0n]), "(1,0) is an invalid point");
    assert(eq(babyJubMul(BABYJUB_GENERATOR, 8n), BABYJUB_BASE8), "Base8 = 8 · Generator");

    const S = 3876493977147089964395646989418653640709890493868463039177063670701706079087n;
    const A: BabyJubPoint = [
      7544364404313686108640297486043592597084907953513982229886192880342666171487n,
      2721089742146723067451923493488918617350881493409568860627491866568993834336n,
    ];
    assert(eq(babyJubMul(BABYJUB_BASE8, S), A), "S · Base8 matches BabyPbk vector");
    assert(eq(babyJubPublicKey(S % BABYJUB_SUBORDER), A), "public key of S mod l matches BabyPbk vector");
    assert(
      hex(packBabyJubPublicKey(A)) ===
        "608530d53749a1d343edfd55ce7f4c5468deca58a2d54ea03aa5d8140c150406",
      "packed public key matches circomlibjs"
    );
    assert(eq(unpackBabyJubPublicKey(packBabyJubPublicKey(A)), A), "public key unpacks");
  }
  console.log("");

  console.log("circomlibjs cross-check");
  {
    const circomlibjs = await import("circomlibjs");
    const bj = await circomlibjs.buildBabyjub();
    const F = bj.F;
    const toObj = (p: any): BabyJubPoint => [F.toObject(p[0]), F.toObject(p[1])];
    const fromObj = (p: BabyJubPoint) => [F.e(p[0]), F.e(p[1])];

    let ok = true;
    let packOk = true;
    for (let i = 0; i < 16; i++) {
      const { privateKey, publicKey } = generateBabyJubKeyPair();
      const ref = bj.mulPointEscalar(bj.Base8, privateKey);
      if (!eq(toObj(ref), publicKey)) ok = false;
      const neg = babyJubNeg(publicKey);
      if (!eq(toObj(bj.addPoint(fromObj(publicKey), fromObj(P1))), babyJubAdd(publicKey, P1))) ok = false;
      for (const p of [publicKey, neg]) {
        const packed = packBabyJubPoint(p);
        if (hex(packed) !== hex(bj.packPoint(fromObj(p)))) packOk = false;
        if (!eq(toObj(bj.unpackPoint(new Uint8Array(packed))), unpackBabyJubPoint(packed))) packOk = false;
      }
    }
    assert(ok, "scalar multiplication and addition match circomlibjs");
    assert(packOk, "pack and unpack match circomlibjs, both signs");
  }
  console.log("");

  console.log("subgroup and low-order points");
  {
    const torsion = babyJubMul(BABYJUB_GENERATOR, BABYJUB_SUBORDER);
    const lowOrder: BabyJubPoint[] = [];
    let t: BabyJubPoint = BABYJUB_IDENTITY;
    for (let i = 0; i < 8; i++) {
      lowOrder.push(t);
      t = babyJubAdd(t, torsion);
    }
    assert(eq(t, BABYJUB_IDENTITY), "torsion point has order 8");
    assert(new Set(lowOrder.map((p) => `${p[0]},${p[1]}`)).size === 8, "8 distinct low-order points");
    assert(lowOrder.every(isOnBabyJub), "low-order points are on the curve");
    assert(
      lowOrder.slice(1).every((p) => !isInBabyJubSubgroup(p)),
      "low-order points are not in the subgroup"
    );
    assert(lowOrder.every((p) => !isValidBabyJubPublicKey(p)), "low-order points and identity are not public keys");
    assert(
      lowOrder.every((p) => throwsCrypto(() => unpackBabyJubPublicKey(packBabyJubPoint(p)))),
      "unpackBabyJubPublicKey rejects low-order points"
    );
    assert(!isInBabyJubSubgroup(BABYJUB_GENERATOR), "Generator (order 8l) is not in the subgroup");
    const mixed = babyJubAdd(BABYJUB_BASE8, torsion);
    assert(isOnBabyJub(mixed) && !isValidBabyJubPublicKey(mixed), "Base8 + torsion is rejected");
    assert(isInBabyJubSubgroup(BABYJUB_BASE8), "Base8 is in the subgroup");
    assert(eq(babyJubMul(BABYJUB_BASE8, BABYJUB_SUBORDER), BABYJUB_IDENTITY), "l · Base8 = identity");
  }
  console.log("");

  console.log("invalid points and encodings");
  {
    assert(!isOnBabyJub([P1[0] + BABYJUB_FIELD, P1[1]]), "non-canonical coordinate is rejected");
    assert(!isOnBabyJub([-1n, 1n]), "negative coordinate is rejected");
    assert(!isOnBabyJub([1n, 2n]), "off-curve point is rejected");
    assert(throwsCrypto(() => babyJubAdd([1n, 2n], P1)), "babyJubAdd rejects off-curve points");
    assert(throwsCrypto(() => babyJubMul(P1, -1n)), "babyJubMul rejects negative scalars");
    assert(throwsCrypto(() => unpackBabyJubPoint(new Uint8Array(31))), "rejects wrong length");

    const nonCanonical = new Uint8Array(32);
    let y = BABYJUB_FIELD + 1n;
    for (let i = 0; i < 32; i++) {
      nonCanonical[i] = Number(y & 0xffn);
      y >>= 8n;
    }
    assert(throwsCrypto(() => unpackBabyJubPoint(nonCanonical)), "rejects y ≥ p");

    let offCurve = 0;
    for (let i = 2n; offCurve === 0 && i < 100n; i++) {
      const b = new Uint8Array(32);
      b[0] = Number(i);
      if (throwsCrypto(() => unpackBabyJubPoint(b))) offCurve++;
    }
    assert(offCurve > 0, "rejects y with no point on the curve");

    const signedZero = packBabyJubPoint(BABYJUB_IDENTITY);
    signedZero[31] |= 0x80;
    assert(throwsCrypto(() => unpackBabyJubPoint(signedZero)), "rejects a sign bit on x = 0");
  }
  console.log("");

  console.log("keys");
  {
    assert(throwsCrypto(() => babyJubPublicKey(0n)), "rejects private key 0");
    assert(throwsCrypto(() => babyJubPublicKey(BABYJUB_SUBORDER)), "rejects private key l");
    const secret = new Uint8Array(32).fill(7);
    const a = deriveBabyJubKeyPair(secret);
    const b = deriveBabyJubKeyPair(secret);
    const c = deriveBabyJubKeyPair(new Uint8Array(32).fill(8));
    assert(a.privateKey === b.privateKey && eq(a.publicKey, b.publicKey), "derivation is deterministic");
    assert(a.privateKey !== c.privateKey, "different secrets give different keys");
    assert(a.privateKey >= 1n && a.privateKey < BABYJUB_SUBORDER, "derived key is in [1, l)");
    assert(isValidBabyJubPublicKey(a.publicKey), "derived public key is valid");
    assert(throwsCrypto(() => deriveBabyJubKeyPair(new Uint8Array(15))), "rejects short secrets");
    const g = generateBabyJubKeyPair();
    assert(eq(unpackBabyJubPublicKey(packBabyJubPublicKey(g.publicKey)), g.publicKey), "random key packs round-trip");
  }
  console.log("");

  console.log("discrete log");
  {
    assert(babyJubDiscreteLog(BABYJUB_IDENTITY, 100) === 0n, "log of identity is 0");
    assert(babyJubDiscreteLog(BABYJUB_BASE8, 0) === null, "log 1 with max 0 is null");
    let ok = true;
    for (const m of [1n, 2n, 99n, 100n, 1000n, 65535n]) {
      if (babyJubDiscreteLog(babyJubMul(BABYJUB_BASE8, m), 65535) !== m) ok = false;
    }
    assert(ok, "recovers values up to the bound");
    assert(babyJubDiscreteLog(babyJubMul(BABYJUB_BASE8, 101n), 100) === null, "returns null above the bound");
    assert(throwsCrypto(() => babyJubDiscreteLog(BABYJUB_BASE8, -1)), "rejects negative bound");
    assert(throwsCrypto(() => babyJubDiscreteLog(BABYJUB_BASE8, 2 ** 32 + 1)), "rejects bound above 2^32");
  }
  console.log("");

  console.log("==================================================");
  console.log(`✅ Baby Jubjub Tests: ${passed} passed, ${failed} failed`);
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
