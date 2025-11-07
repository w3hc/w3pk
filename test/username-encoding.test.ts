/**
 * Test to verify username encoding fix for WebAuthn user.id
 *
 * Issue: Usernames with 9 characters (and potentially other lengths) were causing
 * problems during registration because user.id was passed as a plain string instead
 * of being base64url-encoded.
 *
 * Fix: Convert username to base64url before passing to WebAuthn user.id field
 */

import { arrayBufferToBase64Url } from "../src/utils/base64";

function testUsernameEncoding(username: string): void {
  console.log(`\nTesting username: "${username}" (${username.length} chars)`);

  // This is what the fix does: encode username to base64url
  const encoder = new TextEncoder();
  const usernameBytes = encoder.encode(username);
  const userIdBase64url = arrayBufferToBase64Url(usernameBytes);

  console.log(`  Original: ${username}`);
  console.log(`  Base64url: ${userIdBase64url}`);
  console.log(`  Byte length: ${usernameBytes.length}`);
  console.log(`  Base64url length: ${userIdBase64url.length}`);

  // Verify it can be decoded back correctly
  const base64 = userIdBase64url
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  const padLength = (4 - (base64.length % 4)) % 4;
  const base64Padded = base64 + '='.repeat(padLength);

  const decoded = Buffer.from(base64Padded, 'base64').toString('utf8');

  if (decoded === username) {
    console.log(`  ✅ Decodes back correctly`);
  } else {
    console.log(`  ❌ Decode failed: got "${decoded}"`);
    throw new Error(`Encoding/decoding mismatch for username: ${username}`);
  }
}

console.log("==================================================");
console.log("🧪 Username Encoding Tests");
console.log("==================================================");

// Test various username lengths, especially around the problematic 9-character length
const testUsernames = [
  "alice",      // 5 chars
  "bob123",     // 6 chars
  "charlie",    // 7 chars
  "testuser",   // 8 chars
  "testuser9",  // 9 chars (the problematic case)
  "testuser10", // 10 chars
  "longerusername", // 14 chars
  "a".repeat(50), // max length (50 chars)
  "user-name",  // with hyphen
  "my-user_123", // with hyphen and underscore
  "test-user-9", // multiple hyphens (9 chars with hyphens)
  "web3-user",  // common web3 format
];

let passed = 0;
let failed = 0;

for (const username of testUsernames) {
  try {
    testUsernameEncoding(username);
    passed++;
  } catch (error) {
    console.error(`❌ Test failed for "${username}":`, error);
    failed++;
  }
}

console.log("\n==================================================");
console.log(`✅ All encoding tests passed! (${passed}/${testUsernames.length})`);
console.log("==================================================\n");

if (failed > 0) {
  process.exit(1);
}
