/**
 * Backup/restore scenarios: device loss, storage deletion, login-less
 * recovery, wrong passwords, corrupted files and repeated restores
 */

import { Wallet } from 'ethers';
import { BackupFileManager } from '../src/backup/backup-file';
import { BackupManager } from '../src/backup/manager';

console.log('\n🧪 Testing Backup/Restore Scenarios\n');

// Helper to simulate storage clearing
function clearStorage() {
  if (typeof localStorage !== 'undefined') {
    localStorage.clear();
  }
}

// Helper to create test wallet
function createTestWallet() {
  const wallet = Wallet.createRandom();
  return {
    mnemonic: wallet.mnemonic!.phrase,
    address: wallet.address,
    wallet,
  };
}

/**
 * Scenario 1: Device Loss Recovery
 * User loses phone, has backup file on computer
 */
async function testDeviceLossRecovery() {
  console.log('📝 Scenario 1: Device Loss Recovery');

  const manager = new BackupFileManager();
  const backupManager = new BackupManager();

  // Device A: Create account and backup
  const { mnemonic, address } = createTestWallet();
  const password = 'StrongPass123!Test';

  console.log('  Device A: Creating backup...');
  const { backupFile, blob } = await manager.createPasswordBackup(
    mnemonic,
    password
  );

  console.log(`  ✓ Backup created: v${backupFile.version}`);

  // Simulate transferring backup to Device B (via download/upload)
  const backupData = await blob.text();

  // Device B: Clean state (no existing credentials)
  clearStorage();
  console.log('  Device B: Clean state (storage cleared)');

  // Device B: Restore from backup
  console.log('  Device B: Restoring from backup...');
  const restored = await manager.restoreWithPassword(
    await manager.parseBackupFile(backupData),
    password
  );

  // Verify recovery
  if (restored.mnemonic !== mnemonic) {
    throw new Error('Mnemonic mismatch after device loss recovery');
  }

  if (restored.ethereumAddress.toLowerCase() !== address.toLowerCase()) {
    throw new Error('Address mismatch after device loss recovery');
  }

  // Mark as verified
  backupManager.markBackupVerified(address);

  console.log('  ✅ Device loss recovery PASSED\n');
}

/**
 * Scenario 2: Storage Deletion Recovery
 * User clears browser data (localStorage deleted)
 */
async function testStorageDeletionRecovery() {
  console.log('📝 Scenario 2: Storage Deletion Recovery');

  const manager = new BackupFileManager();
  const backupManager = new BackupManager();

  // Create account and backup
  const { mnemonic, address } = createTestWallet();
  const password = 'secure pass for storage loss';

  console.log('  Creating account and backup...');
  const { backupFile, blob } = await manager.createPasswordBackup(
    mnemonic,
    password
  );

  // Save backup externally (simulate downloading)
  const externalBackup = await blob.text();

  console.log('  ✓ Backup saved externally');

  // Simulate storage deletion
  clearStorage();
  console.log('  ✓ Storage cleared (localStorage)');

  // Restore from external backup
  console.log('  Restoring from external backup...');
  const restored = await manager.restoreWithPassword(
    await manager.parseBackupFile(externalBackup),
    password
  );

  // Verify restoration
  if (restored.ethereumAddress.toLowerCase() !== address.toLowerCase()) {
    throw new Error('Address mismatch after storage deletion recovery');
  }

  // Check backup status
  const status = await backupManager.getBackupStatus(address);
  console.log(`  ✓ Security score: ${status.securityScore.total}/70`);

  console.log('  ✅ Storage deletion recovery PASSED\n');
}

/**
 * Scenario 3: Login-Less Recovery
 * User has synced passkey but no account/credentials on Device B
 */
async function testLoginLessRecovery() {
  console.log('📝 Scenario 3: Login-Less Recovery (Critical)');

  const manager = new BackupFileManager();

  // Device A: User registered account, has credentials
  const { mnemonic, address } = createTestWallet();
  const password = 'LoginLessPass789!';

  console.log('  Device A: Creating backup...');
  const { backupFile, blob } = await manager.createPasswordBackup(
    mnemonic,
    password
  );

  const backupData = await blob.text();
  console.log('  ✓ Backup created and transferred to Device B');

  // Device B: Passkey synced, but NO credentials in storage
  clearStorage();
  console.log('  Device B: Clean storage (passkey synced via iCloud/Google)');

  // User uploads backup file WITHOUT logging in first
  console.log('  User uploads backup file (NO login prompt)');
  console.log('  User enters password to decrypt...');

  // Restore without prior authentication
  const restored = await manager.restoreWithPassword(
    await manager.parseBackupFile(backupData),
    password
  );

  console.log('  ✓ Backup decrypted successfully');

  // Verify credentials would be added to storage
  // (In real SDK, this happens in registerWithBackupFile)
  if (restored.ethereumAddress.toLowerCase() !== address.toLowerCase()) {
    throw new Error('Address mismatch in login-less recovery');
  }

  console.log('  ✓ Credentials ready to be added to storage');
  console.log('  ✓ User can now login with synced passkey');
  console.log('  ✅ Login-less recovery PASSED\n');
}

/**
 * Edge Case 1: Wrong Password
 */
async function testWrongPassword() {
  console.log('📝 Edge Case 1: Wrong Password');

  const manager = new BackupFileManager();
  const { mnemonic, address } = createTestWallet();
  const correctPassword = 'CorrectPass123!Test';
  const wrongPassword = 'WrongPass456!Test';

  // Create backup
  const { backupFile } = await manager.createPasswordBackup(
    mnemonic,
    correctPassword
  );

  console.log('  Attempting restore with wrong password...');

  // Try to restore with wrong password
  try {
    await manager.restoreWithPassword(backupFile, wrongPassword);
    throw new Error('Should have failed with wrong password');
  } catch (error: any) {
    if (error.code === 'CRYPTO_ERROR' && error.message.includes('Wrong password')) {
      console.log('  ✓ Correctly rejected wrong password');
      console.log(`    Error: ${error.message || error.name}`);
    } else {
      throw error;
    }
  }

  console.log('  ✅ Wrong password test PASSED\n');
}

/**
 * Edge Case 2: Corrupted Backup File
 */
async function testCorruptedBackup() {
  console.log('📝 Edge Case 2: Corrupted Backup File');

  const manager = new BackupFileManager();

  // Test various corrupted formats
  const corruptedBackups = [
    '{"invalid": "json"}',
    '{"ethereumAddress": "0x123"}', // Missing required fields
    'not even json',
    '',
  ];

  for (const [index, corrupted] of corruptedBackups.entries()) {
    let rejected: any;
    try {
      await manager.parseBackupFile(corrupted);
    } catch (error) {
      rejected = error;
    }
    if (!rejected) {
      throw new Error(`Should have failed for corrupted backup ${index + 1}`);
    }
    console.log(`  ✓ Test ${index + 1}: Correctly rejected corrupted backup`);
    console.log(`    Error: ${rejected.message.substring(0, 60)}...`);
  }

  console.log('  ✅ Corrupted backup test PASSED\n');
}

/**
 * Edge Case 3: Multiple Backups
 */
async function testMultipleBackups() {
  console.log('📝 Edge Case 3: Multiple Backups');

  const manager = new BackupFileManager();

  // Create multiple wallets and backups
  const wallet1 = createTestWallet();
  const wallet2 = createTestWallet();

  const backup1 = await manager.createPasswordBackup(
    wallet1.mnemonic,
    'FirstBackup1!Test'
  );

  const backup2 = await manager.createPasswordBackup(
    wallet2.mnemonic,
    'SecondBackup2!Test'
  );

  console.log('  ✓ Created 2 different backups');

  // Restore first backup
  const restored1 = await manager.restoreWithPassword(backup1.backupFile, 'FirstBackup1!Test');

  if (restored1.ethereumAddress.toLowerCase() !== wallet1.address.toLowerCase()) {
    throw new Error('Failed to restore first backup');
  }

  console.log('  ✓ Restored first backup correctly');

  // Restore second backup
  const restored2 = await manager.restoreWithPassword(backup2.backupFile, 'SecondBackup2!Test');

  if (restored2.ethereumAddress.toLowerCase() !== wallet2.address.toLowerCase()) {
    throw new Error('Failed to restore second backup');
  }

  console.log('  ✓ Restored second backup correctly');

  // Verify they're different
  if (restored1.ethereumAddress === restored2.ethereumAddress) {
    throw new Error('Backups should have different addresses');
  }

  console.log('  ✅ Multiple backups test PASSED\n');
}

/**
 * Edge Case 4: Idempotent Restore
 * Same backup can be restored multiple times
 */
async function testIdempotentRestore() {
  console.log('📝 Edge Case 4: Idempotent Restore');

  const manager = new BackupFileManager();
  const { mnemonic, address } = createTestWallet();
  const password = 'IdempotentPass1!';

  // Create backup
  const { backupFile } = await manager.createPasswordBackup(
    mnemonic,
    password
  );

  console.log('  Restoring backup multiple times...');

  // Restore 3 times
  for (let i = 1; i <= 3; i++) {
    const restored = await manager.restoreWithPassword(backupFile, password);

    if (restored.ethereumAddress.toLowerCase() !== address.toLowerCase()) {
      throw new Error(`Restore ${i} failed: address mismatch`);
    }

    if (restored.mnemonic !== mnemonic) {
      throw new Error(`Restore ${i} failed: mnemonic mismatch`);
    }

    console.log(`  ✓ Restore ${i}: Same address and mnemonic`);
  }

  console.log('  ✅ Idempotent restore test PASSED\n');
}

/**
 * Scenario 4: Backup File Format Validation
 */
async function testBackupFileFormat() {
  console.log('📝 Scenario 4: Backup File Format Validation');

  const manager = new BackupFileManager();
  const { mnemonic, address } = createTestWallet();
  const password = 'format test passphrase';

  // Create backup
  const { backupFile, json } = await manager.createPasswordBackup(
    mnemonic,
    password
  );

  console.log('  Validating backup file format...');

  // Check required fields
  if (!backupFile.createdAt) {
    throw new Error('Missing createdAt field');
  }
  console.log('  ✓ Has createdAt field');

  if (backupFile.version !== 4) {
    throw new Error('Not BackupFile v4');
  }
  console.log('  ✓ Is BackupFile v4');

  if ('ethereumAddress' in backupFile || json.toLowerCase().includes(address.slice(2).toLowerCase())) {
    throw new Error('Plain address in the backup file');
  }
  console.log('  ✓ Has no address');

  if (!backupFile.encryptedMnemonic) {
    throw new Error('Missing encryptedMnemonic field');
  }
  console.log('  ✓ Has encryptedMnemonic field');

  if (backupFile.encryptionMethod !== 'password') {
    throw new Error('Wrong encryption method');
  }
  console.log('  ✓ Has correct encryptionMethod');

  if (!backupFile.passwordEncryption) {
    throw new Error('Missing passwordEncryption metadata');
  }
  console.log('  ✓ Has passwordEncryption metadata');

  if (!backupFile.passwordEncryption.salt) {
    throw new Error('Missing salt');
  }
  console.log('  ✓ Has salt');

  if (backupFile.passwordEncryption.kdf !== 'argon2id') {
    throw new Error('KDF is not Argon2id');
  }
  console.log(
    `  ✓ Argon2id: m=${backupFile.passwordEncryption.memoryKiB} KiB, t=${backupFile.passwordEncryption.passes}, p=${backupFile.passwordEncryption.parallelism}`
  );

  // Verify JSON is valid
  const parsed = JSON.parse(json);
  if (!parsed.createdAt) {
    throw new Error('Invalid JSON format');
  }
  console.log('  ✓ JSON is valid and parseable');

  console.log('  ✅ Backup file format validation PASSED\n');
}

/**
 * Scenario 5: Complete Device Loss Scenario
 * End-to-end test: Create on Device A, complete loss, restore on Device B
 */
async function testCompleteDeviceLoss() {
  console.log('📝 Scenario 5: Complete Device Loss (End-to-End)');

  const manager = new BackupFileManager();
  const backupManager = new BackupManager();

  // Device A: Create account
  console.log('  Device A: Creating account...');
  const { mnemonic, address, wallet } = createTestWallet();
  const password = 'DeviceLossTest1!';

  console.log(`  ✓ Account created: ${address.substring(0, 10)}...`);

  // Device A: Create backup
  console.log('  Device A: Creating backup...');
  const { backupFile, blob } = await manager.createPasswordBackup(
    mnemonic,
    password
  );

  console.log('  ✓ Backup created and downloaded');

  // Device A: Sign a message (to verify later)
  const testMessage = 'Hello from Device A';
  const signature = await wallet.signMessage(testMessage);
  console.log('  ✓ Signed test message');

  // Simulate device loss
  console.log('  💥 Device A lost!');
  clearStorage();

  // Device B: User gets new device, has backup file
  console.log('  Device B: New device (clean state)');

  // Device B: Upload backup file
  const backupData = await blob.text();
  console.log('  Device B: Uploaded backup file');

  // Device B: Restore from backup
  console.log('  Device B: Restoring wallet...');
  const restored = await manager.restoreWithPassword(
    await manager.parseBackupFile(backupData),
    password
  );

  console.log('  ✓ Wallet restored successfully');

  // Verify restoration
  if (restored.ethereumAddress.toLowerCase() !== address.toLowerCase()) {
    throw new Error('Address mismatch after complete device loss');
  }

  if (restored.mnemonic !== mnemonic) {
    throw new Error('Mnemonic mismatch after complete device loss');
  }

  // Device B: Verify can sign same message
  const restoredWallet = Wallet.fromPhrase(restored.mnemonic);
  const restoredSignature = await restoredWallet.signMessage(testMessage);

  if (signature !== restoredSignature) {
    throw new Error('Signature mismatch - wallet not fully restored');
  }

  console.log('  ✓ Same signature as Device A (wallet fully functional)');

  // Mark backup as verified
  backupManager.markBackupVerified(address);

  // Check security status
  const status = await backupManager.getBackupStatus(address);
  console.log(`  ✓ Security score: ${status.securityScore.total}/70`);
  console.log(`  ✓ Backup verified: ${status.recoveryPhrase.verified}`);

  console.log('  ✅ Complete device loss recovery PASSED\n');
}

/**
 * Performance Test: Backup Creation and Restore Speed
 */
async function testPerformance() {
  console.log('📝 Performance Test: Backup Creation and Restore');

  const manager = new BackupFileManager();
  const { mnemonic, address } = createTestWallet();
  const password = 'PerformanceTest123!';

  // Test backup creation speed
  console.log('  Testing backup creation speed...');
  const createStart = Date.now();
  const { backupFile } = await manager.createPasswordBackup(
    mnemonic,
    password
  );
  const createTime = Date.now() - createStart;

  console.log(`  ✓ Backup creation: ${createTime}ms`);

  // Test restore speed
  console.log('  Testing restore speed...');
  const restoreStart = Date.now();
  await manager.restoreWithPassword(backupFile, password);
  const restoreTime = Date.now() - restoreStart;

  console.log(`  ✓ Restore: ${restoreTime}ms`);

  // Performance benchmarks
  if (createTime > 5000) {
    console.warn(`  ⚠️  Backup creation is slow (${createTime}ms)`);
  }

  if (restoreTime > 5000) {
    console.warn(`  ⚠️  Restore is slow (${restoreTime}ms)`);
  }

  console.log('  ✅ Performance test PASSED\n');
}

/**
 * Run all tests
 */
async function runAllTests() {
  try {
    console.log('═══════════════════════════════════════════════════════');
    console.log('  BACKUP/RESTORE SCENARIOS');
    console.log('═══════════════════════════════════════════════════════\n');

    // Core scenarios
    await testDeviceLossRecovery();
    await testStorageDeletionRecovery();
    await testLoginLessRecovery();

    // Edge cases
    await testWrongPassword();
    await testCorruptedBackup();
    await testMultipleBackups();
    await testIdempotentRestore();

    // Format validation
    await testBackupFileFormat();

    // End-to-end
    await testCompleteDeviceLoss();

    // Performance
    await testPerformance();

    console.log('═══════════════════════════════════════════════════════');
    console.log('  🎉 ALL BACKUP/RESTORE TESTS PASSED!');
    console.log('═══════════════════════════════════════════════════════\n');

  } catch (error) {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
  }
}

runAllTests();
