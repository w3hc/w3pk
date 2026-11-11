/**
 * Shamir's secret sharing over GF(256): constant-time field arithmetic, and
 * shares made before it (pinned in fixtures/shamir-shares.json) still recover
 *
 * NOTE: the mnemonic and password are test values, not real secrets
 */

import { readFileSync } from "node:fs";
import { Web3Passkey } from "../src/index";
import {
  splitSecret,
  combineShareSubsets,
  MAX_SHARE_SUBSETS,
  gfMul,
  gfInv,
  bytesToHex,
  hexToBytes,
} from "../src/recovery/shamir";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  assert,
  assertEqual,
  assertThrows,
} from "./test-utils";

class MemoryStorage {
  private items = new Map<string, string>();
  get length() {
    return this.items.size;
  }
  key(i: number) {
    return [...this.items.keys()][i] ?? null;
  }
  getItem(k: string) {
    return this.items.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.items.set(k, String(v));
  }
  removeItem(k: string) {
    this.items.delete(k);
  }
  clear() {
    this.items.clear();
  }
}

const localStorage = new MemoryStorage();
(globalThis as any).localStorage = localStorage;
(globalThis as any).window = {
  location: { hostname: "localhost", origin: "http://localhost" },
  localStorage,
};

const fixtures = JSON.parse(
  readFileSync(new URL("./fixtures/shamir-shares.json", import.meta.url), "utf8")
);

const SUBSETS = [
  [0, 1, 2],
  [0, 1, 3],
  [0, 2, 4],
  [1, 3, 4],
  [2, 3, 4],
];

const combine = (shares: Uint8Array[], threshold: number) =>
  combineShareSubsets(shares, threshold).next().value as Uint8Array;

async function runTests() {
  startTestSuite("Shamir Secret Sharing Tests");

  await runTest("GF(256) multiply matches FIPS-197 and a log/exp table", async () => {
    assertEqual(gfMul(0x57, 0x13), 0xfe, "{57} • {13} = {fe} (FIPS-197 §4.2)");
    assertEqual(gfMul(0x57, 0x83), 0xc1, "{57} • {83} = {c1}");
    const exp: number[] = [];
    const log: number[] = [];
    for (let i = 0, x = 1; i < 255; i++) {
      exp[i] = x;
      log[x] = i;
      x ^= (x << 1) ^ (x & 0x80 ? 0x11b : 0);
    }
    for (let a = 0; a < 256; a++) {
      for (let b = 0; b < 256; b++) {
        const expected = a && b ? exp[(log[a] + log[b]) % 255] : 0;
        if (gfMul(a, b) !== expected) throw new Error(`${a} • ${b}: ${gfMul(a, b)} != ${expected}`);
      }
    }
    passTest();
  });

  await runTest("GF(256) inverse is a^254", async () => {
    assertEqual(gfInv(0), 0, "0 maps to 0");
    for (let a = 1; a < 256; a++) {
      assert(gfMul(a, gfInv(a)) === 1, `${a} • ${a}^-1 = 1`);
    }
    passTest();
  });

  await runTest("pinned shares recover every byte value", async () => {
    const { threshold, secret, shares } = fixtures.shamir;
    for (const subset of SUBSETS) {
      const recovered = combine(subset.map((i) => hexToBytes(shares[i])), threshold);
      assertEqual(bytesToHex(recovered), secret, `subset ${subset.join(",")}`);
    }
    passTest();
  });

  await runTest("pinned guardian share files restore the wallet", async () => {
    const { password, address, mnemonic, files } = fixtures.guardians;
    for (const subset of SUBSETS) {
      const sdk = new Web3Passkey();
      const result = await sdk.recoverFromGuardians(
        subset.map((i) => JSON.stringify(files[i])),
        password
      );
      assertEqual(result.ethereumAddress, address, `address from ${subset.join(",")}`);
      assertEqual((sdk as any).currentWallet?.mnemonic, mnemonic, `mnemonic from ${subset.join(",")}`);
    }
    passTest();
  });

  await runTest("zero, duplicate or misfit x-coordinates are rejected", async () => {
    const shares = splitSecret(Uint8Array.of(1, 2, 3), 2, 3);
    const zero = Uint8Array.from(shares[0]);
    zero[0] = 0;
    for (const [bad, label] of [
      [[zero, shares[1]], "x-coordinate 0"],
      [[shares[0], shares[0]], "the same share twice"],
      [[shares[1], shares[2], Uint8Array.from(shares[1])], "a duplicate beyond the threshold"],
      [[shares[0], shares[1].slice(0, 3)], "shares of different lengths"],
      [[shares[0].slice(0, 1), shares[1].slice(0, 1)], "shares without data"],
    ] as const) {
      await assertThrows(() => {
        combine(bad as unknown as Uint8Array[], 2);
      }, label);
    }
    await assertThrows(() => {
      combine(shares, 1);
    }, "threshold below 2");
    passTest();
  });

  await runTest("combineShareSubsets tries every subset once, up to the bound", async () => {
    const secret = Uint8Array.of(7, 8, 9);
    const shares = splitSecret(secret, 3, 5);
    const bad = Uint8Array.from(shares[0]);
    bad[1] ^= 1;
    const results = [...combineShareSubsets([bad, ...shares.slice(1)], 3)].map(bytesToHex);
    assertEqual(results.length, 10, "all 10 subsets");
    assertEqual(results.filter((r) => r === bytesToHex(secret)).length, 4, "the 4 subsets without the bad share agree");
    assert(results[0] !== bytesToHex(secret), "the first subset holds the bad share");

    const many = splitSecret(Uint8Array.of(42), 10, 20);
    const forged = Uint8Array.from(many[0]);
    forged[1] ^= 1;
    const fromMany = [...combineShareSubsets([forged, ...many.slice(1)], 10)].map(bytesToHex);
    assertEqual(fromMany.length, MAX_SHARE_SUBSETS, "184756 subsets: stops at the bound");
    assert(fromMany.includes("2a"), "a subset without the first share comes before the bound");
    passTest();
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
