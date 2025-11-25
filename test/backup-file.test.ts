/**
 * Test suite for new simplified backup file system
 */

import { Wallet } from 'ethers';
import { BackupFileManager } from '../src/backup/backup-file';
import { SocialRecovery } from '../src/recovery/backup-based-recovery';

console.log('\n🧪 Testing Simplified Backup File System\n');

async function testPasswordBackup() {
  console.log('📝 Test 1: Create and restore password-protected backup');

  const manager = new BackupFileManager();

  // Create a test wallet
  const wallet = Wallet.createRandom();
  const mnemonic = wallet.mnemonic!.phrase;
  const address = wallet.address;

  console.log(`  ✓ Created test wallet: ${address.substring(0, 10)}...`);

  // Create password backup
  const password = 'TestPassword123!SecureBackup';
  const { backupFile, json } = await manager.createPasswordBackup(
    mnemonic,
    address,
    password
  );

  console.log(`  ✓ Created password backup`);
  console.log(`    - Version: ${backupFile.version}`);
  console.log(`    - Created: ${backupFile.createdAt}`);
  console.log(`    - Address: ${backupFile.ethereumAddress.substring(0, 10)}...`);
  console.log(`    - Encryption: ${backupFile.encryptionMethod}`);

  // Restore from backup (using same password)
  const restored = await manager.restoreWithPassword(backupFile, password);

  console.log(`  ✓ Restored from backup`);
  console.log(`    - Address: ${restored.ethereumAddress.substring(0, 10)}...`);

  // Verify
  if (restored.mnemonic !== mnemonic) {
    throw new Error('Mnemonic mismatch!');
  }

  if (restored.ethereumAddress.toLowerCase() !== address.toLowerCase()) {
    throw new Error('Address mismatch!');
  }

  console.log('  ✅ Password backup test PASSED\n');
}

async function testSocialRecovery() {
  console.log('📝 Test 2: Social recovery with guardian shares');

  const manager = new BackupFileManager();
  const recovery = new SocialRecovery();

  // Create a test wallet
  const wallet = Wallet.createRandom();
  const mnemonic = wallet.mnemonic!.phrase;
  const address = wallet.address;

  console.log(`  ✓ Created test wallet: ${address.substring(0, 10)}...`);

  // Create password backup
  const password = 'TestPassword123!SecureBackup';
  const { backupFile } = await manager.createPasswordBackup(mnemonic, address, password);

  // Set up 3-of-5 social recovery
  const guardians = [
    { name: 'Alice', email: 'alice@example.com' },
    { name: 'Bob', email: 'bob@example.com' },
    { name: 'Charlie', email: 'charlie@example.com' },
    { name: 'David', email: 'david@example.com' },
    { name: 'Eve', email: 'eve@example.com' },
  ];

  const setup = await recovery.splitAmongGuardians(
    backupFile,
    guardians,
    3 // threshold
  );

  console.log(`  ✓ Split backup among ${guardians.length} guardians (3-of-5)`);
  console.log(`    - Threshold: ${setup.threshold}`);
  console.log(`    - Total shares: ${setup.totalShares}`);

  // Simulate recovery with 3 shares (Alice, Bob, Charlie)
  const sharesForRecovery = [
    setup.guardianShares[0], // Alice
    setup.guardianShares[1], // Bob
    setup.guardianShares[2], // Charlie
  ];

  console.log(`  ✓ Collecting shares from: ${sharesForRecovery.map(s => s.guardianName).join(', ')}`);

  // Recover backup file
  const recoveredBackup = await recovery.recoverFromShares(sharesForRecovery);

  console.log(`  ✓ Recovered backup file`);
  console.log(`    - Address: ${recoveredBackup.ethereumAddress.substring(0, 10)}...`);

  // Verify the backup is correct
  if (recoveredBackup.ethereumAddress !== backupFile.ethereumAddress) {
    throw new Error('Recovered backup address mismatch!');
  }

  console.log('  ✅ Social recovery test PASSED\n');
}

async function testGuardianInvitation() {
  console.log('📝 Test 3: Guardian invitation generation');

  const recovery = new SocialRecovery();

  // Create a test share
  const testShare = {
    guardianId: 'test-123',
    guardianName: 'Alice',
    shareData: 'abcdef1234567890',
    shareIndex: 1,
    createdAt: new Date().toISOString(),
    walletAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7',
  };

  // Generate invitation
  const invitation = await recovery.createGuardianInvitation(
    testShare,
    'You are a trusted guardian for my crypto wallet.'
  );

  console.log(`  ✓ Generated guardian invitation`);
  console.log(`    - Has document: ${invitation.shareDocument.length > 0}`);
  console.log(`    - Has JSON: ${invitation.shareJson.length > 0}`);
  console.log(`    - Has QR code: ${invitation.qrCodeDataURL ? 'Yes' : 'No (optional dependency missing)'}`);

  // Test parsing the invitation
  const parsed = recovery.parseGuardianShare(invitation.shareJson);

  if (parsed.guardianName !== testShare.guardianName) {
    throw new Error('Guardian name mismatch!');
  }

  if (parsed.shareData !== testShare.shareData) {
    throw new Error('Share data mismatch!');
  }

  console.log(`  ✓ Successfully parsed guardian share`);
  console.log('  ✅ Guardian invitation test PASSED\n');
}

async function testDownloadableBackup() {
  console.log('📝 Test 4: Downloadable backup creation');

  const manager = new BackupFileManager();

  // Create a test wallet
  const wallet = Wallet.createRandom();
  const mnemonic = wallet.mnemonic!.phrase;
  const address = wallet.address;

  // Create backup
  const password = 'TestPassword123!SecureBackup';
  const { backupFile } = await manager.createPasswordBackup(mnemonic, address, password);

  // Create downloadable version
  const download = manager.createDownloadableBackup(backupFile);

  console.log(`  ✓ Created downloadable backup`);
  console.log(`    - Filename: ${download.filename}`);
  console.log(`    - Blob type: ${download.blob.type}`);
  console.log(`    - Blob size: ${download.blob.size} bytes`);

  // Verify we can parse it back
  const text = await download.blob.text();
  const parsed = await manager.parseBackupFile(text);

  if (parsed.ethereumAddress !== address) {
    throw new Error('Downloaded backup address mismatch!');
  }

  console.log('  ✅ Downloadable backup test PASSED\n');
}

async function runTests() {
  try {
    await testPasswordBackup();
    await testSocialRecovery();
    await testGuardianInvitation();
    await testDownloadableBackup();

    console.log('🎉 All tests passed!\n');
  } catch (error) {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
  }
}

runTests();
