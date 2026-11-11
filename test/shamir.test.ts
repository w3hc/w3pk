/**
 * Shamir's secret sharing over GF(256): shares made before the constant-time
 * arithmetic (pinned in fixtures/shamir-shares.json) still recover
 *
 * NOTE: the mnemonic and password are test values, not real secrets
 */

import { readFileSync } from "node:fs";
import { Web3Passkey } from "../src/index";
import { combineShares, bytesToHex, hexToBytes } from "../src/recovery/shamir";
import { startTestSuite, endTestSuite, runTest, passTest, assertEqual } from "./test-utils";

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

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
