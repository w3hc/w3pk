/**
 * Backup System Tests
 * Tests for encrypted backups, QR codes, and backup management
 *
 * NOTE: This file contains TEST FIXTURES only - not real secrets!
 * Test mnemonic: "abandon abandon..." is the standard BIP39 test vector
 * Test passwords: All passwords are clearly marked with "Test" and "NotReal"
 */

import { Wallet } from 'ethers';
import { BackupManager } from '../src/backup';
import { QRBackupCreator } from '../src/backup/qr-backup';
import {
  validatePasswordStrength,
  encryptWithPassword,
  decryptWithPassword,
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
  assertThrows,
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

  // Test 2: Encryption/Decryption
  await runTest('Encryption and Decryption', async () => {
    const testData = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const password = 'TestPassword123!NotReal';
    const salt = new Uint8Array(32);
    crypto.getRandomValues(salt);

    const encrypted = await encryptWithPassword(testData, password, salt);
    assertTruthy(encrypted.encrypted, 'Encryption should return encrypted data');
    assertTruthy(encrypted.salt, 'Encryption should return salt');
    assertTruthy(encrypted.iv, 'Encryption should return IV');
    assertEqual(encrypted.iterations, 310000, 'Should use 310k iterations');

    const decrypted = await decryptWithPassword(
      encrypted.encrypted,
      password,
      encrypted.salt,
      encrypted.iv,
      encrypted.iterations
    );

    assertEqual(decrypted, testData, 'Decrypted data should match original');
    passTest('Encryption/decryption working correctly');
  });

  // Test 3: Wrong Password Decryption
  await runTest('Wrong Password Decryption', async () => {
    const testData = 'secret mnemonic phrase';
    const password = 'TestCorrect123!NotReal';
    const wrongPassword = 'TestWrong456!NotReal';
    const salt = new Uint8Array(32);
    crypto.getRandomValues(salt);

    const encrypted = await encryptWithPassword(testData, password, salt);

    await assertThrows(async () => {
      await decryptWithPassword(
        encrypted.encrypted,
        wrongPassword,
        encrypted.salt,
        encrypted.iv,
        encrypted.iterations
      );
    }, 'Should throw error with wrong password');

    passTest('Wrong password correctly rejected');
  });

  // Test 4: Address Checksum
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

  // Test 5: QR Backup Creation (Encrypted)
  await runTest('QR Backup Creation (Encrypted)', async () => {
    try {
      const qrCreator = new QRBackupCreator();
      const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      const testAddress = '0x1234567890123456789012345678901234567890';
      const password = 'TestQRCode123!NotReal';

      const { qrCodeDataURL, rawData, instructions } = await qrCreator.createQRBackup(
        testMnemonic,
        testAddress,
        { password, errorCorrection: 'H' }
      );

      // qrCodeDataURL might be empty string if qrcode library is not installed
      if (qrCodeDataURL && qrCodeDataURL.startsWith('data:image/')) {
        passTest('QR code image generated');
      }
      assertTruthy(rawData, 'Should return raw data');
      assertTruthy(instructions, 'Should return instructions');

      const parsed = JSON.parse(rawData);
      assertEqual(parsed.version, 1, 'Should have version');
      assertEqual(parsed.type, 'encrypted', 'Should be encrypted');
      assertTruthy(parsed.data, 'Should have encrypted data');
      assertTruthy(parsed.salt, 'Should have salt');
      assertTruthy(parsed.checksum, 'Should have checksum');

      passTest('QR backup creation working correctly');
    } catch (error) {
      if (error instanceof Error && (error.message.includes('qrcode') || error.message.includes('Cannot find module'))) {
        skipTest('qrcode library not installed (optional)');
      } else {
        throw error;
      }
    }
  });

  // Test 6: QR Backup Creation (Plain)
  await runTest('QR Backup Creation (Plain)', async () => {
    const qrCreator = new QRBackupCreator();
    const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const testAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';

    const { rawData } = await qrCreator.createQRBackup(
      testMnemonic,
      testAddress
    );

    const parsed = JSON.parse(rawData);
    assertEqual(parsed.type, 'plain', 'Should be plain type');
    assertEqual(parsed.data, testMnemonic, 'Should contain mnemonic');

    passTest('QR plain backup working correctly');
  });

  // Test 7: QR Backup Restoration
  await runTest('QR Backup Restoration', async () => {
    const qrCreator = new QRBackupCreator();
    const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    // Derive the actual address from the mnemonic
    const wallet = Wallet.fromPhrase(testMnemonic);
    const testAddress = wallet.address;

    const password = 'TestQRRestore123!NotReal';

    // Create encrypted QR backup
    const { rawData } = await qrCreator.createQRBackup(
      testMnemonic,
      testAddress,
      { password }
    );

    // Restore from QR
    const { mnemonic, ethereumAddress } = await qrCreator.restoreFromQR(
      rawData,
      password
    );

    assertEqual(mnemonic, testMnemonic, 'Restored mnemonic should match');
    assertEqual(ethereumAddress.toLowerCase(), testAddress.toLowerCase(), 'Address should match');

    passTest('QR backup restoration working correctly');
  });

  // Test 8: Backup Manager Status
  await runTest('Backup Manager Status', async () => {
    const backupManager = new BackupManager();
    const testAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';

    const status = await backupManager.getBackupStatus(testAddress);

    assertTruthy(status.passkeySync, 'Should have passkey sync status');
    assertTruthy(status.recoveryPhrase, 'Should have recovery phrase status');
    assertTruthy(status.securityScore, 'Should have security score');
    assert(typeof status.securityScore.total === 'number', 'Score should be number');
    assertTruthy(status.securityScore.level, 'Should have security level');

    passTest(`Backup status: ${status.securityScore.total}/100 (${status.securityScore.level})`);
  });

  // Test 9: Security Score Calculation
  await runTest('Security Score Calculation', async () => {
    const backupManager = new BackupManager();
    const testAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';

    const status = await backupManager.getBackupStatus(testAddress);

    assert(status.securityScore.total >= 0, 'Score should be >= 0');
    assert(status.securityScore.total <= 100, 'Score should be <= 100');
    assertTruthy(status.securityScore.breakdown, 'Should have score breakdown');
    assertTruthy(status.securityScore.nextMilestone, 'Should have next milestone');

    const validLevels = ['vulnerable', 'protected', 'secured', 'fort-knox'];
    assert(validLevels.includes(status.securityScore.level), 'Should have valid level');

    passTest('Security score calculation working correctly');
  });

  endTestSuite();
}

runTests().catch(console.error);
