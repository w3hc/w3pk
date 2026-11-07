/**
 * contracts/test/fixtures/erc1271.json matches what the SDK signs today, so
 * the forge tests verify the current encoding
 */

import assert from "node:assert";
import { readFileSync } from "node:fs";
import { FIXTURES_PATH, generateFixtures } from "../scripts/gen-erc1271-fixtures";

async function runTests() {
  console.log("\n🧪 ERC-1271 fixtures test\n");
  assert.strictEqual(
    readFileSync(FIXTURES_PATH, "utf8"),
    await generateFixtures(),
    "out of date: run pnpm tsx scripts/gen-erc1271-fixtures.ts"
  );
  console.log("✅ contracts/test/fixtures/erc1271.json is up to date\n");
}

runTests().catch((error) => {
  console.error("❌ Test failed:", error);
  process.exit(1);
});
