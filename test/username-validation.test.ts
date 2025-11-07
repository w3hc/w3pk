/**
 * Username Validation Tests
 *
 * Tests the updated username validation rules that now support:
 * - Alphanumeric characters (a-z, A-Z, 0-9)
 * - Underscores (_)
 * - Hyphens (-)
 * - Must start and end with alphanumeric character
 * - Length: 3-50 characters
 */

import { validateUsername, assertUsername } from "../src/utils/validation";

interface TestCase {
  username: string;
  expected: boolean;
  reason: string;
}

const testCases: TestCase[] = [
  // Valid usernames
  { username: "alice", expected: true, reason: "Simple lowercase" },
  { username: "Bob", expected: true, reason: "Capitalized" },
  { username: "user123", expected: true, reason: "Alphanumeric" },
  { username: "user_name", expected: true, reason: "With underscore" },
  { username: "user-name", expected: true, reason: "With hyphen (NEW)" },
  { username: "my-user_123", expected: true, reason: "Mixed: hyphen + underscore + numbers" },
  { username: "test-user-9", expected: true, reason: "Multiple hyphens + number" },
  { username: "a1b", expected: true, reason: "3 characters minimum" },
  { username: "user_test-name_123", expected: true, reason: "Complex valid username" },
  { username: "John-Doe", expected: true, reason: "Name-like format with hyphen" },
  { username: "web3-user", expected: true, reason: "Common web3 format" },
  { username: "a".repeat(50), expected: true, reason: "50 characters (max)" },

  // Invalid usernames - Length
  { username: "ab", expected: false, reason: "Too short (2 chars)" },
  { username: "a".repeat(51), expected: false, reason: "Too long (51 chars)" },

  // Invalid usernames - Starting/ending with special chars
  { username: "-username", expected: false, reason: "Starts with hyphen" },
  { username: "username-", expected: false, reason: "Ends with hyphen" },
  { username: "_username", expected: false, reason: "Starts with underscore" },
  { username: "username_", expected: false, reason: "Ends with underscore" },
  { username: "-user-", expected: false, reason: "Starts and ends with hyphen" },

  // Invalid usernames - Forbidden characters
  { username: "user name", expected: false, reason: "Contains space" },
  { username: "user@name", expected: false, reason: "Contains @" },
  { username: "user.name", expected: false, reason: "Contains period" },
  { username: "user!name", expected: false, reason: "Contains exclamation" },
  { username: "user#name", expected: false, reason: "Contains hashtag" },
  { username: "user$name", expected: false, reason: "Contains dollar sign" },
  { username: "user%name", expected: false, reason: "Contains percent" },
  { username: "user*name", expected: false, reason: "Contains asterisk" },

  // Edge cases
  { username: "", expected: false, reason: "Empty string" },
  { username: "   ", expected: false, reason: "Only spaces" },
  { username: "123", expected: true, reason: "Only numbers (valid)" },
  { username: "a-b", expected: true, reason: "Minimal with hyphen" },
  { username: "a_b", expected: true, reason: "Minimal with underscore" },
];

console.log("==================================================");
console.log("🧪 Username Validation Tests");
console.log("==================================================\n");

let passed = 0;
let failed = 0;

for (const testCase of testCases) {
  const result = validateUsername(testCase.username);
  const passedTest = result === testCase.expected;

  if (passedTest) {
    console.log(`✅ "${testCase.username}" - ${testCase.reason}`);
    passed++;
  } else {
    console.log(`❌ "${testCase.username}" - ${testCase.reason}`);
    console.log(`   Expected: ${testCase.expected}, Got: ${result}`);
    failed++;
  }
}

// Test assertUsername throws correctly
console.log("\n--- Testing assertUsername() ---");
try {
  assertUsername("valid-user");
  console.log("✅ assertUsername accepts valid username");
} catch (error) {
  console.log("❌ assertUsername rejected valid username");
  failed++;
}

try {
  assertUsername("-invalid");
  console.log("❌ assertUsername accepted invalid username");
  failed++;
} catch (error) {
  console.log("✅ assertUsername throws for invalid username");
  console.log(`   Error: ${(error as Error).message}`);
}

console.log("\n==================================================");
if (failed === 0) {
  console.log(`✅ All tests passed! (${passed}/${testCases.length + 2})`);
} else {
  console.log(`❌ ${failed} test(s) failed, ${passed} passed`);
}
console.log("==================================================\n");

if (failed > 0) {
  process.exit(1);
}
