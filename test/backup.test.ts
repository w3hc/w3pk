/**
 * Backup System Tests
 * Tests for encrypted backups and backup management
 *
 * NOTE: This file contains TEST FIXTURES only - not real secrets!
 * Test mnemonic: "abandon abandon..." is the standard BIP39 test vector
 * Test passwords: All passwords are clearly marked with "Test" and "NotReal"
 */

import { BackupManager } from '../src/backup/manager';
import {
  validatePasswordStrength,
  deriveAddressChecksum,
} from '../src/backup/encryption';
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  logDetail,
  assert,
  assertEqual,
  assertTruthy,
} from './test-utils';

async function runTests() {
  startTestSuite('Backup System Tests');

  // Test 1: Password Validation
  await runTest('Password Strength Validation', async () => {
    const weakPassword = validatePasswordStrength('password');
    assert(!weakPassword.valid, 'Weak password should be rejected');
    assert(weakPassword.score < 50, 'Weak password score should be low');

    const strongPassword = validatePasswordStrength('TestStrongPass123!NotReal');
    assert(strongPassword.valid, 'Strong password should be valid');
    assert(strongPassword.score >= 50, 'Strong password score should be high');

    passTest('Password validation working correctly');
  });

  // Test 2: Address Checksum
  await runTest('Address Checksum Generation', async () => {
    const address1 = '0x1234567890123456789012345678901234567890';
    const address2 = '0x1234567890123456789012345678901234567890';
    const address3 = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd';

    const checksum1 = await deriveAddressChecksum(address1);
    const checksum2 = await deriveAddressChecksum(address2);
    const checksum3 = await deriveAddressChecksum(address3);

    assertEqual(checksum1, checksum2, 'Same address should have same checksum');
    assert(checksum1 !== checksum3, 'Different addresses should have different checksums');
    assertEqual(checksum1.length, 16, 'Checksum should be 16 characters');

    passTest('Address checksum generation working correctly');
  });

  // Test 3: Backup Manager Status
  await runTest('Backup Manager Status', async () => {
    const backupManager = new BackupManager();
    const testAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';

    const status = await backupManager.getBackupStatus(testAddress);

    assertTruthy(status.passkeySync, 'Should have passkey sync status');
    assertTruthy(status.recoveryPhrase, 'Should have recovery phrase status');
    assertTruthy(status.securityScore, 'Should have security score');
    assert(typeof status.securityScore.total === 'number', 'Score should be number');
    assertTruthy(status.securityScore.level, 'Should have security level');

    passTest(`Backup status: ${status.securityScore.total}/70 (${status.securityScore.level})`);
  });

  // Test 4: Security Score Calculation
  await runTest('Security Score Calculation', async () => {
    const backupManager = new BackupManager();
    const testAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';

    const status = await backupManager.getBackupStatus(testAddress);

    assert(status.securityScore.total >= 0, 'Score should be >= 0');
    assert(status.securityScore.total <= 70, 'Score should be <= 70');
    assertTruthy(status.securityScore.breakdown, 'Should have score breakdown');
    assertTruthy(status.securityScore.nextMilestone, 'Should have next milestone');

    const validLevels = ['vulnerable', 'protected', 'secured', 'fort-knox'];
    assert(validLevels.includes(status.securityScore.level), 'Should have valid level');

    passTest('Security score calculation working correctly');
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
