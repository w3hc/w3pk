/**
 * w3pk.zk: the lazy Proxy over ZKProofModule (loaded from w3pk/zk, so run
 * `pnpm build` first)
 */

import { Web3Passkey } from "../../src/index";

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

console.log("\n==================================================");
console.log("🧩 w3pk.zk Proxy Test");
console.log("==================================================\n");

async function runTests() {
  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, message: string) {
    if (condition) {
      passed++;
      console.log(`  ✅ ${message}`);
    } else {
      failed++;
      console.log(`  ❌ ${message}`);
    }
  }

  const w3pk = new Web3Passkey();

  console.log("Test 1: a property resolves to its value");
  assert((await w3pk.zk.isAvailable()) === true, "await w3pk.zk.isAvailable() is true");
  console.log("");

  console.log("Test 2: a method is called on the module");
  const root = await w3pk.zk.computeMerkleRoot("1", [], []);
  assert(typeof root === "string", "computeMerkleRoot resolves to a string");
  console.log("");

  console.log("Test 3: w3pk.zk is not a thenable");
  assert((w3pk.zk as any).then === undefined, "w3pk.zk.then is undefined");
  const timeout = new Promise((resolve) => setTimeout(() => resolve("timeout"), 1000));
  const awaited = await Promise.race([(async () => await w3pk.zk)(), timeout]);
  assert(awaited !== "timeout", "await w3pk.zk settles");
  console.log("");

  console.log("==================================================");
  console.log(`${failed === 0 ? "✅" : "❌"} w3pk.zk Proxy Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
