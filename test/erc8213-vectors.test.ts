/**
 * getSigningDigests matches the published ERC-8213 vectors in test/fixtures/erc8213-vectors.json
 */

import assert from "node:assert";
import { readFileSync } from "node:fs";
import { hexlify, toUtf8Bytes } from "ethers";
import { getSigningDigests, type SigningTypedData } from "../src/index";

type Vector =
  | { name: string; sources: string[]; kind: "erc191"; input: { message: string }; expected: { erc191Digest: string } }
  | { name: string; sources: string[]; kind: "calldata"; input: { data: string }; expected: { calldataDigest: string } }
  | {
      name: string;
      sources: string[];
      kind: "eip712";
      input: SigningTypedData;
      expected: { eip712Digest: string; domainHash: string; messageHash: string };
    };

interface Fixture {
  sources: Record<string, { commit: string; urls: string[] }>;
  vectors: Vector[];
}

const fixture: Fixture = JSON.parse(
  readFileSync(new URL("./fixtures/erc8213-vectors.json", import.meta.url), "utf8")
);

const ADDRESS = "0x4675C7e5BaAFBFFbca748158bEcBA61ef3b0a263";

function check(vector: Vector) {
  switch (vector.kind) {
    case "erc191": {
      const { message } = vector.input;
      const hex = hexlify(toUtf8Bytes(message));
      assert.deepStrictEqual(getSigningDigests({ method: "personal_sign", params: [message, ADDRESS] }), vector.expected);
      assert.deepStrictEqual(getSigningDigests({ method: "personal_sign", params: [hex, ADDRESS] }), vector.expected);
      assert.deepStrictEqual(getSigningDigests({ method: "eth_sign", params: [ADDRESS, hex] }), vector.expected);
      return;
    }
    case "calldata":
      assert.strictEqual(
        getSigningDigests({ method: "eth_sendTransaction", params: [{ data: vector.input.data }] }).calldataDigest,
        vector.expected.calldataDigest
      );
      return;
    case "eip712":
      assert.deepStrictEqual(
        getSigningDigests({ method: "eth_signTypedData_v4", params: [ADDRESS, vector.input] }),
        vector.expected
      );
      assert.deepStrictEqual(
        getSigningDigests({ method: "eth_signTypedData_v4", params: [ADDRESS, JSON.stringify(vector.input)] }),
        vector.expected
      );
      return;
  }
}

async function runTests() {
  console.log("\n🔎 Running ERC-8213 Vector Tests...\n");

  console.log("Test 1: the fixture pins every source and covers every kind");
  {
    for (const [id, { commit, urls }] of Object.entries(fixture.sources)) {
      assert.match(commit, /^[0-9a-f]{40}$/, `${id}: commit is not a full SHA`);
      assert.ok(urls.length > 0, `${id}: no URL`);
      for (const url of urls) assert.ok(url.includes(`/blob/${commit}/`), `${id}: ${url} is not pinned to ${commit}`);
    }
    const cited = new Set(fixture.vectors.flatMap((v) => v.sources));
    assert.deepStrictEqual([...cited].sort(), Object.keys(fixture.sources).sort());
    assert.deepStrictEqual(
      [...new Set(fixture.vectors.map((v) => v.kind))].sort(),
      ["calldata", "eip712", "erc191"]
    );
    console.log("✅ Sources are pinned to full SHAs, each is cited, each kind has vectors");
  }

  console.log("\nTest 2: getSigningDigests matches every vector");
  for (const vector of fixture.vectors) {
    check(vector);
    console.log(`✅ ${vector.kind}: ${vector.name} (${vector.sources.join(", ")})`);
  }

  console.log("\n✅ All ERC-8213 vector tests passed!\n");
}

runTests().catch((error) => {
  console.error("❌ Test failed:", error);
  process.exit(1);
});
