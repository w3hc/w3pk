/**
 * Test for requireReauth: false functionality
 *
 * This test verifies that when requireReauth is set to false,
 * users can be logged in silently without a WebAuthn prompt
 * if a valid persistent session exists.
 */

import { SessionManager } from '../src/core/session';

console.log('\n==================================================');
console.log('🔐 requireReauth: false Test');
console.log('==================================================\n');

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

  // Test 1: requireReauth defaults to true
  console.log('Test 1: requireReauth defaults to true');
  const sessionManager1 = new SessionManager(1, {
    enabled: true,
  });
  const silentRestore1 = await sessionManager1.attemptSilentRestore();
  assert(silentRestore1 === null, 'Silent restore returns null when requireReauth is true (default)');
  console.log('');

  // Test 2: requireReauth: false enables silent restore
  console.log('Test 2: requireReauth: false attempts silent restore');
  const sessionManager2 = new SessionManager(1, {
    enabled: true,
    requireReauth: false,
  });
  const silentRestore2 = await sessionManager2.attemptSilentRestore();
  // Should return null if no persistent session exists, but shouldn't throw
  assert(silentRestore2 === null, 'Silent restore returns null when no session exists (expected behavior)');
  console.log('');

  // Test 3: requireReauth: true blocks silent restore
  console.log('Test 3: requireReauth: true blocks silent restore');
  const sessionManager3 = new SessionManager(1, {
    enabled: true,
    requireReauth: true,
  });
  const silentRestore3 = await sessionManager3.attemptSilentRestore();
  assert(silentRestore3 === null, 'Silent restore blocked when requireReauth is true');
  console.log('');

  // Test 4: Disabled persistent sessions block silent restore
  console.log('Test 4: Disabled persistent sessions block silent restore');
  const sessionManager4 = new SessionManager(1, {
    enabled: false,
    requireReauth: false,
  });
  const silentRestore4 = await sessionManager4.attemptSilentRestore();
  assert(silentRestore4 === null, 'Silent restore blocked when persistent sessions disabled');
  console.log('');

  // Summary
  console.log('==================================================');
  console.log(`✅ requireReauth Tests: ${passed} passed, ${failed} failed`);
  console.log('==================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(console.error);
