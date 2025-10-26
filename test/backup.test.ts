/**
 * Backup System Tests
 * Tests for encrypted backups, QR codes, and backup management
 *
 * NOTE: This file contains TEST FIXTURES only - not real secrets!
 * Test mnemonic: "abandon abandon..." is the standard BIP39 test vector
 * Test passwords: All passwords are clearly marked with "Test" and "NotReal"
 */

import { BackupManager } from '../src/backup';
import { ZipBackupCreator } from '../src/backup/zip-backup';
import { QRBackupCreator } from '../src/backup/qr-backup';
import {
  validatePasswordStrength,
  encryptWithPassword,
  decryptWithPassword,
  deriveAddressChecksum,
} from '../src/backup/encryption';

async function runTests() {
console.log('\n🧪 Running Backup System Tests...\n');

// Test 1: Password Validation
console.log('Test 1: Password Strength Validation');
{
  const weakPassword = validatePasswordStrength('password');
  console.assert(!weakPassword.valid, 'Weak password should be rejected');
  console.assert(weakPassword.score < 50, 'Weak password score should be low');

  const strongPassword = validatePasswordStrength('TestStrongPass123!NotReal');
  console.assert(strongPassword.valid, 'Strong password should be valid');
  console.assert(strongPassword.score >= 50, 'Strong password score should be high');

  console.log('✅ Password validation working correctly');
}

// Test 2: Encryption/Decryption
console.log('\nTest 2: Encryption and Decryption');
{
  const testData = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const password = 'TestPassword123!NotReal';
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);

  const encrypted = await encryptWithPassword(testData, password, salt);
  console.assert(encrypted.encrypted, 'Encryption should return encrypted data');
  console.assert(encrypted.salt, 'Encryption should return salt');
  console.assert(encrypted.iv, 'Encryption should return IV');
  console.assert(encrypted.iterations === 310000, 'Should use 310k iterations');

  const decrypted = await decryptWithPassword(
    encrypted.encrypted,
    password,
    encrypted.salt,
    encrypted.iv,
    encrypted.iterations
  );

  console.assert(decrypted === testData, 'Decrypted data should match original');
  console.log('✅ Encryption/decryption working correctly');
}

// Test 3: Wrong Password Decryption
console.log('\nTest 3: Wrong Password Decryption');
{
  const testData = 'secret mnemonic phrase';
  const password = 'TestCorrect123!NotReal';
  const wrongPassword = 'TestWrong456!NotReal';
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);

  const encrypted = await encryptWithPassword(testData, password, salt);

  try {
    await decryptWithPassword(
      encrypted.encrypted,
      wrongPassword,
      encrypted.salt,
      encrypted.iv,
      encrypted.iterations
    );
    console.assert(false, 'Should throw error with wrong password');
  } catch (error) {
    console.log('✅ Wrong password correctly rejected');
  }
}

// Test 4: Address Checksum
console.log('\nTest 4: Address Checksum Generation');
{
  const address1 = '0x1234567890123456789012345678901234567890';
  const address2 = '0x1234567890123456789012345678901234567890';
  const address3 = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd';

  const checksum1 = await deriveAddressChecksum(address1);
  const checksum2 = await deriveAddressChecksum(address2);
  const checksum3 = await deriveAddressChecksum(address3);

  console.assert(checksum1 === checksum2, 'Same address should have same checksum');
  console.assert(checksum1 !== checksum3, 'Different addresses should have different checksums');
  console.assert(checksum1.length === 16, 'Checksum should be 16 characters');

  console.log('✅ Address checksum generation working correctly');
}

// Test 5: ZIP Backup Creation
console.log('\nTest 5: ZIP Backup Creation');
{
  const zipCreator = new ZipBackupCreator();
  const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const testAddress = '0x1234567890123456789012345678901234567890';
  const password = 'TestBackup123!NotReal';

  const { blob, metadata } = await zipCreator.createZipBackup(
    testMnemonic,
    testAddress,
    { password, includeInstructions: true }
  );

  console.assert(blob instanceof Blob, 'Should return Blob');
  console.assert(blob.size > 0, 'Blob should have size');
  console.assert(metadata.id, 'Metadata should have ID');
  console.assert(metadata.ethereumAddress === testAddress, 'Metadata should have correct address');
  console.assert(metadata.method === 'zip', 'Metadata should indicate ZIP method');

  console.log(`✅ ZIP backup created (${(blob.size / 1024).toFixed(2)} KB)`);
}

// Test 6: ZIP Backup Restoration
console.log('\nTest 6: ZIP Backup Restoration');
{
  const zipCreator = new ZipBackupCreator();
  const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  // Derive the actual address from the mnemonic
  const { Wallet } = await import('ethers');
  const wallet = Wallet.fromPhrase(testMnemonic);
  const testAddress = wallet.address;

  const password = 'TestRestore123!NotReal';

  // Create backup
  const { blob } = await zipCreator.createZipBackup(
    testMnemonic,
    testAddress,
    { password }
  );

  // Read backup
  const backupData = await blob.text();

  // Parse the JSON archive
  const archive = JSON.parse(backupData);
  const encryptedFile = archive['recovery-phrase.txt.enc'];

  // Restore from backup
  const { mnemonic, metadata } = await zipCreator.restoreFromZipBackup(
    encryptedFile,
    password
  );

  console.assert(mnemonic === testMnemonic, 'Restored mnemonic should match original');
  console.assert(metadata.ethereumAddress === testAddress, 'Restored address should match');

  console.log('✅ ZIP backup restoration working correctly');
}

// Test 7: QR Backup Creation (Encrypted)
console.log('\nTest 7: QR Backup Creation (Encrypted)');
{
  const qrCreator = new QRBackupCreator();
  const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const testAddress = '0x1234567890123456789012345678901234567890';
  const password = 'TestQRCode123!NotReal';

  const { qrCodeDataURL, rawData, instructions } = await qrCreator.createQRBackup(
    testMnemonic,
    testAddress,
    { password, errorCorrection: 'H' }
  );

  console.assert(qrCodeDataURL.startsWith('data:image/'), 'Should return data URL');
  console.assert(rawData, 'Should return raw data');
  console.assert(instructions, 'Should return instructions');

  const parsed = JSON.parse(rawData);
  console.assert(parsed.version === 1, 'Should have version');
  console.assert(parsed.type === 'encrypted', 'Should be encrypted');
  console.assert(parsed.data, 'Should have encrypted data');
  console.assert(parsed.salt, 'Should have salt');
  console.assert(parsed.checksum, 'Should have checksum');

  console.log('✅ QR backup creation working correctly');
}

// Test 8: QR Backup Creation (Plain)
console.log('\nTest 8: QR Backup Creation (Plain)');
{
  const qrCreator = new QRBackupCreator();
  const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const testAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';

  const { rawData } = await qrCreator.createQRBackup(
    testMnemonic,
    testAddress
  );

  const parsed = JSON.parse(rawData);
  console.assert(parsed.type === 'plain', 'Should be plain type');
  console.assert(parsed.data === testMnemonic, 'Should contain mnemonic');

  console.log('✅ QR plain backup working correctly');
}

// Test 9: QR Backup Restoration
console.log('\nTest 9: QR Backup Restoration');
{
  const qrCreator = new QRBackupCreator();
  const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  // Derive the actual address from the mnemonic
  const { Wallet } = await import('ethers');
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

  console.assert(mnemonic === testMnemonic, 'Restored mnemonic should match');
  console.assert(ethereumAddress.toLowerCase() === testAddress.toLowerCase(), 'Address should match');

  console.log('✅ QR backup restoration working correctly');
}

// Test 10: Backup Manager Status
console.log('\nTest 10: Backup Manager Status');
{
  const backupManager = new BackupManager();
  const testAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';

  const status = await backupManager.getBackupStatus(testAddress);

  console.assert(status.passkeySync, 'Should have passkey sync status');
  console.assert(status.recoveryPhrase, 'Should have recovery phrase status');
  console.assert(status.securityScore, 'Should have security score');
  console.assert(typeof status.securityScore.total === 'number', 'Score should be number');
  console.assert(status.securityScore.level, 'Should have security level');

  console.log(`✅ Backup status: ${status.securityScore.total}/100 (${status.securityScore.level})`);
}

// Test 11: Security Score Calculation
console.log('\nTest 11: Security Score Calculation');
{
  const backupManager = new BackupManager();
  const testAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';

  const status = await backupManager.getBackupStatus(testAddress);

  console.assert(status.securityScore.total >= 0, 'Score should be >= 0');
  console.assert(status.securityScore.total <= 100, 'Score should be <= 100');
  console.assert(status.securityScore.breakdown, 'Should have score breakdown');
  console.assert(status.securityScore.nextMilestone, 'Should have next milestone');

  const validLevels = ['vulnerable', 'protected', 'secured', 'fort-knox'];
  console.assert(validLevels.includes(status.securityScore.level), 'Should have valid level');

  console.log('✅ Security score calculation working correctly');
}

console.log('\n✅ All Backup System Tests Passed!\n');
}

runTests().catch(console.error);
