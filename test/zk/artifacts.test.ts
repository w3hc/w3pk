/**
 * Circuit artifact verification against pinned CIDs
 *
 * Expected CIDs come from `ipfs add --cid-version 1` on the same bytes
 */

import {
  readZkArtifactPins,
  verifyZkArtifacts,
  ZkArtifactMismatchError,
  type ZkArtifactPins,
} from "../../src/zk";
import { Web3PasskeyError } from "../../src/core/errors";

console.log("\n==================================================");
console.log("📌 ZK Artifact Verification Test");
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

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return error;
  }
}

function makeWasm(): Uint8Array {
  const bytes = new Uint8Array(1_000_000);
  for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251;
  return bytes;
}

function makeZkey(): Uint8Array {
  const bytes = new Uint8Array(100_000);
  for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 7) % 256;
  return bytes;
}

const PINS: ZkArtifactPins = {
  wasm: "bafybeibx62obrkybp46hx3ivh53q4rnptgkunpgtwiib5lfelfgt2ekihm",
  zkey: "bafkreietcaylrh2cybw43wqsuq67zvqb25c5cg53l7gruah6urboqqcrk4",
};

async function runTests() {
  console.log("Matching artifacts");
  {
    const wasm = makeWasm();
    const zkey = makeZkey();
    const result = await verifyZkArtifacts({ wasm, zkey }, PINS);
    assert(result.wasm === wasm && result.zkey === zkey, "Uint8Array artifacts pass and come back");

    const fromBuffers = await verifyZkArtifacts(
      { wasm: wasm.slice().buffer, zkey: zkey.slice().buffer },
      PINS
    );
    assert(fromBuffers.wasm.length === wasm.length, "ArrayBuffer artifacts pass");

    const padded = new Uint8Array(zkey.length + 8);
    padded.set(zkey, 4);
    const fromViews = await verifyZkArtifacts(
      { wasm: new DataView(wasm.slice().buffer), zkey: new Int8Array(padded.buffer, 4, zkey.length) },
      PINS
    );
    assert(fromViews.zkey.length === zkey.length, "other ArrayBuffer views pass, honoring their offset");
  }

  console.log("\nModified byte");
  for (const name of ["wasm", "zkey"] as const) {
    const artifacts = { wasm: makeWasm(), zkey: makeZkey() };
    artifacts[name][12_345] ^= 1;
    const error = await rejection(verifyZkArtifacts(artifacts, PINS));
    assert(error instanceof ZkArtifactMismatchError, `a flipped bit in ${name} throws ZkArtifactMismatchError`);
    if (error instanceof ZkArtifactMismatchError) {
      assert(error.code === "ZK_ARTIFACT_MISMATCH", "  code is ZK_ARTIFACT_MISMATCH");
      assert(error.artifact === name, `  artifact is '${name}'`);
      assert(error.expectedCid === PINS[name], "  expectedCid is the pin");
      assert(error.actualCid !== PINS[name] && error.actualCid.startsWith("baf"), "  actualCid is the computed CID");
    }
  }

  console.log("\nSwapped pins");
  {
    const error = await rejection(
      verifyZkArtifacts({ wasm: makeWasm(), zkey: makeZkey() }, { wasm: PINS.zkey, zkey: PINS.wasm })
    );
    assert(error instanceof ZkArtifactMismatchError, "wasm and zkey pins can't be swapped");
  }

  console.log("\nURL sources");
  {
    const originalFetch = globalThis.fetch;
    const served: Record<string, Uint8Array> = {
      "https://cdn.example/circuit.wasm": makeWasm(),
      "https://cdn.example/circuit_final.zkey": makeZkey(),
    };
    globalThis.fetch = (async (input: string) => {
      const body = served[input];
      return body ? new Response(body) : new Response(null, { status: 404, statusText: "Not Found" });
    }) as typeof fetch;
    try {
      const result = await verifyZkArtifacts(
        { wasm: "https://cdn.example/circuit.wasm", zkey: "https://cdn.example/circuit_final.zkey" },
        PINS
      );
      assert(result.wasm.length === 1_000_000 && result.zkey.length === 100_000, "fetched artifacts pass and come back as bytes");

      served["https://cdn.example/circuit_final.zkey"] = new Uint8Array(100_000);
      const swapped = await rejection(
        verifyZkArtifacts(
          { wasm: "https://cdn.example/circuit.wasm", zkey: "https://cdn.example/circuit_final.zkey" },
          PINS
        )
      );
      assert(swapped instanceof ZkArtifactMismatchError, "a swapped zkey on the CDN throws ZkArtifactMismatchError");

      const missing = await rejection(
        verifyZkArtifacts({ wasm: "https://cdn.example/missing.wasm", zkey: makeZkey() }, PINS)
      );
      assert(
        missing instanceof Web3PasskeyError && missing.code === "ZK_ARTIFACT_FETCH_ERROR",
        "a failed fetch throws ZK_ARTIFACT_FETCH_ERROR"
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  }

  console.log("\nRegistry pins");
  {
    const keys: string[] = [];
    const registry = {
      async getCidByVersion(key: string) {
        keys.push(key);
        return ({ "vote-v1.wasm": PINS.wasm, "vote-v1.zkey": PINS.zkey } as Record<string, string>)[key] ?? "";
      },
    };
    const pins = await readZkArtifactPins(registry, { wasm: "vote-v1.wasm", zkey: "vote-v1.zkey" });
    assert(pins.wasm === PINS.wasm && pins.zkey === PINS.zkey, "pins are read with getCidByVersion");
    assert(keys.includes("vote-v1.wasm") && keys.includes("vote-v1.zkey"), "each key is queried");
    const verified = await verifyZkArtifacts({ wasm: makeWasm(), zkey: makeZkey() }, pins);
    assert(verified.wasm.length > 0, "artifacts pass against registry pins");

    const unpinned = await rejection(
      readZkArtifactPins(registry, { wasm: "vote-v1.wasm", zkey: "vote-v2.zkey" })
    );
    assert(
      unpinned instanceof Web3PasskeyError && unpinned.code === "ZK_ARTIFACT_NOT_PINNED",
      "an unregistered key throws ZK_ARTIFACT_NOT_PINNED"
    );
  }

  console.log("\n==================================================");
  console.log(`✅ ZK Artifact Tests: ${passed} passed, ${failed} failed`);
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
