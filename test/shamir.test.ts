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
  combineShares,
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
      const recovered = combineShares(subset.map((i) => hexToBytes(shares[i])), threshold);
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
        combineShares(bad as unknown as Uint8Array[], 2);
      }, label);
    }
    await assertThrows(() => {
      combineShares(shares, 1);
    }, "threshold below 2");
    passTest();
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
