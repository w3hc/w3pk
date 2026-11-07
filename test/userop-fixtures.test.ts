/**
 * contracts/test/fixtures/userop.json matches what the SDK sends today, so
 * the forge tests run the current UserOperation encoding
 */

import assert from "node:assert";
import { readFileSync } from "node:fs";
import { FIXTURES_PATH, generateFixtures } from "../scripts/gen-userop-fixtures";

async function runTests() {
  console.log("\n🧪 UserOperation fixtures test\n");
  assert.strictEqual(
    readFileSync(FIXTURES_PATH, "utf8"),
    await generateFixtures(),
    "out of date: run pnpm tsx scripts/gen-userop-fixtures.ts"
  );
  console.log("✅ contracts/test/fixtures/userop.json is up to date\n");
}

runTests().catch((error) => {
  console.error("❌ Test failed:", error);
  process.exit(1);
});
