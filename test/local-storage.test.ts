/**
 * Tests for the localStorage wallet and backup stores
 *
 * The encrypted wallet and backup metadata live next to the credential
 * metadata, so browser eviction removes all of them or none.
 */

import './setup';
import { LocalStorageWalletStorage } from '../src/wallet/storage';
import { BackupStorage } from '../src/backup/storage';
import type { EncryptedWalletData } from '../src/wallet/types';
import type { BackupMetadata } from '../src/backup/types';

console.log('\n==================================================');
console.log('🚀 localStorage Store Tests');
console.log('==================================================\n');

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

function memoryStorage(): Storage {
  const items = new Map<string, string>();
  return {
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => { items.set(key, value); },
    removeItem: (key) => { items.delete(key); },
    clear: () => { items.clear(); },
    get length() { return items.size; },
    key: (index) => Array.from(items.keys())[index] ?? null,
  };
}

const address = '0x1234567890123456789012345678901234567890';
const otherAddress = '0x0000000000000000000000000000000000000001';

async function runWalletTests() {
  const backing = memoryStorage();
  const storage = new LocalStorageWalletStorage(backing);
  const wallet: EncryptedWalletData = {
    ethereumAddress: address,
    encryptedMnemonic: 'ciphertext',
    credentialId: 'credential-id',
    createdAt: new Date().toISOString(),
  };

  console.log('Test 1: Store and retrieve a wallet');
  await storage.store(wallet);
  assert(backing.getItem(`w3pk_wallet_${address}`) !== null, 'Wallet is stored under w3pk_wallet_<address>');
  const retrieved = await storage.retrieve(address);
  assert(retrieved?.encryptedMnemonic === 'ciphertext', 'Encrypted mnemonic matches');
  assert(retrieved?.credentialId === 'credential-id', 'Credential ID matches');
  assert((await storage.retrieve(otherAddress)) === null, 'Unknown address returns null');
  console.log('');

  console.log('Test 2: Delete and clear');
  await storage.store({ ...wallet, ethereumAddress: otherAddress });
  await storage.delete(otherAddress);
  assert((await storage.retrieve(otherAddress)) === null, 'Deleted wallet is gone');
  assert((await storage.retrieve(address)) !== null, 'Other wallet survives delete');

  backing.setItem('w3pk_credential_index', '[]');
  await storage.clear();
  assert((await storage.retrieve(address)) === null, 'clear removes wallets');
  assert(backing.getItem('w3pk_credential_index') === '[]', 'clear keeps credential metadata');
  console.log('');

  console.log('Test 3: Defaults to window.localStorage');
  const defaultStorage = new LocalStorageWalletStorage();
  await defaultStorage.store(wallet);
  assert(
    (globalThis as any).window.localStorage.getItem(`w3pk_wallet_${address}`) !== null,
    'Wallet lands in window.localStorage'
  );
  await defaultStorage.clear();
  console.log('');
}

async function runBackupTests() {
  const backing = memoryStorage();
  const storage = new BackupStorage(backing);
  const backup = (id: string, ethereumAddress: string, method: 'qr' | 'file'): BackupMetadata => ({
    id,
    ethereumAddress,
    method,
    createdAt: new Date().toISOString(),
    addressChecksum: 'checksum',
  });

  console.log('Test 4: Store and query backup metadata');
  await storage.storeBackupMetadata(backup('a', address, 'file'));
  await storage.storeBackupMetadata(backup('b', address, 'qr'));
  await storage.storeBackupMetadata(backup('c', otherAddress, 'file'));
  assert(backing.getItem('w3pk_backups') !== null, 'Backups are stored under w3pk_backups');
  assert((await storage.getBackupsByAddress(address)).length === 2, 'Backups filter by address');
  assert((await storage.getBackupById('c'))?.ethereumAddress === otherAddress, 'Backup found by id');
  assert((await storage.getBackupById('missing')) === null, 'Unknown id returns null');
  assert((await storage.getBackupCountByMethod('file')) === 2, 'Backups count by method');
  console.log('');

  console.log('Test 5: Overwrite and delete backup metadata');
  await storage.storeBackupMetadata(backup('a', address, 'qr'));
  assert((await storage.getBackupCountByMethod('qr')) === 2, 'Same id replaces the record');
  await storage.deleteBackup('a');
  assert((await storage.getBackupById('a')) === null, 'Deleted backup is gone');
  assert((await storage.getBackupsByAddress(address)).length === 1, 'Other backups survive');
  console.log('');
}

async function runTests() {
  await runWalletTests();
  await runBackupTests();

  console.log('==================================================');
  console.log(`✅ localStorage Store Tests: ${passed} passed, ${failed} failed`);
  console.log('==================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error('Test run crashed:', error);
  process.exit(1);
});
