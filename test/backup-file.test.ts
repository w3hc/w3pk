/**
 * BackupFile v4: password (Argon2id) and PRF round trips, no address in
 * the file, Argon2id parameters, version checks and social recovery
 */

import { Wallet } from 'ethers';
import { BackupFileManager, backupAdditionalData, validateBackupFile } from '../src/backup/backup-file';
import {
  ARGON2ID_MAX_PARAMS,
  ARGON2ID_PARAMS,
  deriveKeyFromPasswordArgon2id,
} from '../src/backup/encryption';
import { encryptData } from '../src/wallet/crypto';
import { SocialRecovery } from '../src/recovery/backup-based-recovery';
import { CryptoError, UnsupportedBackupVersionError, WeakPasswordError } from '../src/core/errors';
import type { BackupFile } from '../src/backup/types';
import { startTestSuite, endTestSuite, runTest, passTest, assert, assertEqual } from './test-utils';

const manager = new BackupFileManager();
const PASSWORD = 'TestStrongPass123!NotReal';

function newWallet() {
  const wallet = Wallet.createRandom();
  return { mnemonic: wallet.mnemonic!.phrase, address: wallet.address };
}

async function capture(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
  } catch (error) {
    return error;
  }
  return undefined;
}

async function passwordFile(
  mnemonic: string,
  params: { memoryKiB: number; passes: number; parallelism: number }
): Promise<BackupFile> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKeyFromPasswordArgon2id(PASSWORD, salt, params);
  const metadata = {
    version: 4 as const,
    createdAt: new Date().toISOString(),
    encryptionMethod: 'password' as const,
    passwordEncryption: { kdf: 'argon2id' as const, salt: btoa(String.fromCharCode(...salt)), ...params },
  };
  return { ...metadata, encryptedMnemonic: await encryptData(mnemonic, key, backupAdditionalData(metadata)) };
}

function assertNoAddress(json: string, address: string, label: string) {
  const hex = address.slice(2).toLowerCase();
  assert(!json.toLowerCase().includes(hex), `${label}: no address in the file`);
  const parsed = JSON.parse(json);
  assert(!('ethereumAddress' in parsed), `${label}: no ethereumAddress field`);
  assert(!('addressChecksum' in parsed), `${label}: no addressChecksum field`);
}

async function runTests() {
  startTestSuite('BackupFile v4 Tests');

  await runTest('Password backup round trip', async () => {
    const { mnemonic, address } = newWallet();
    const { backupFile, json } = await manager.createPasswordBackup(mnemonic, PASSWORD);

    assertEqual(backupFile.version, 4, 'version is 4');
    assertEqual(backupFile.encryptionMethod, 'password', 'method is password');
    assertNoAddress(json, address, 'password');
    assert(!json.includes(mnemonic.split(' ')[0] + ' '), 'mnemonic is not in clear');

    const restored = await manager.restoreWithPassword(await manager.parseBackupFile(json), PASSWORD);
    assertEqual(restored.mnemonic, mnemonic, 'mnemonic restored');
    assertEqual(restored.ethereumAddress, address, 'address derived from the mnemonic');
    passTest('password file round-trips');
  });

  await runTest('Password backup refuses a weak password with the feedback', async () => {
    const { mnemonic } = newWallet();
    for (const weak of ['', 'a', 'Sh0rt!Passw0rd', 'PasswordPassword', 'xy'.repeat(128) + 'z']) {
      const error = await capture(() => manager.createPasswordBackup(mnemonic, weak));
      assert(error instanceof WeakPasswordError, `"${weak}": WeakPasswordError`);
      assertEqual((error as WeakPasswordError).code, 'WEAK_PASSWORD', `"${weak}": code`);
      assert((error as WeakPasswordError).feedback.length > 0, `"${weak}": carries the feedback`);
    }
    const missing = await capture(() => manager.createPasswordBackup(mnemonic, undefined as unknown as string));
    assert(missing instanceof WeakPasswordError, 'missing password: WeakPasswordError');
    const notString = await capture(() => manager.createPasswordBackup(mnemonic, 123456789012345678 as unknown as string));
    assert(notString instanceof WeakPasswordError, 'non-string password: WeakPasswordError');
    const short = (await capture(() => manager.createPasswordBackup(mnemonic, 'a'))) as WeakPasswordError;
    assert(short.feedback.includes('Password must be at least 15 characters'), 'feedback names the length');
    assert(short.message.includes('at least 15 characters'), 'message carries the feedback');
    passTest('weak passwords refused');
  });

  await runTest('Password backup uses the documented Argon2id parameters', async () => {
    const { mnemonic } = newWallet();
    const { backupFile } = await manager.createPasswordBackup(mnemonic, PASSWORD);
    const kdf = backupFile.passwordEncryption!;

    assertEqual(kdf.kdf, 'argon2id', 'kdf is argon2id');
    assertEqual(kdf.memoryKiB, 65536, 'memory is 64 MiB');
    assertEqual(kdf.passes, 3, '3 passes');
    assertEqual(kdf.parallelism, 4, '4 lanes');
    assertEqual(ARGON2ID_PARAMS.memoryKiB, 65536, 'ARGON2ID_PARAMS.memoryKiB');
    assert(
      ARGON2ID_PARAMS.memoryKiB <= ARGON2ID_MAX_PARAMS.memoryKiB &&
        ARGON2ID_PARAMS.passes <= ARGON2ID_MAX_PARAMS.passes &&
        ARGON2ID_PARAMS.parallelism <= ARGON2ID_MAX_PARAMS.parallelism,
      'new backups are within the restore bounds'
    );
    assertEqual(atob(kdf.salt).length, 16, '16-byte salt');

    const other = await manager.createPasswordBackup(mnemonic, PASSWORD);
    assert(other.backupFile.passwordEncryption!.salt !== kdf.salt, 'salt is random per file');

    const start = performance.now();
    await deriveKeyFromPasswordArgon2id(PASSWORD, new Uint8Array(16));
    const ms = performance.now() - start;
    assert(ms < 5000, 'derivation finishes in under 5 s');
    passTest(`Argon2id m=65536 KiB t=3 p=4: ${ms.toFixed(0)} ms`);
  });

  await runTest('Backup made with the v0.11.0 parameters still restores', async () => {
    const { mnemonic, address } = newWallet();
    const json = JSON.stringify(
      await passwordFile(mnemonic, { memoryKiB: 19456, passes: 2, parallelism: 1 })
    );

    const restored = await manager.restoreWithPassword(await manager.parseBackupFile(json), PASSWORD);
    assertEqual(restored.mnemonic, mnemonic, 'mnemonic restored');
    assertEqual(restored.ethereumAddress, address, 'address restored');
    passTest('19 MiB, 2 passes, 1 lane');
  });

  await runTest('Restore reads the Argon2id parameters from the file', async () => {
    const { mnemonic, address } = newWallet();
    const file = await passwordFile(mnemonic, { memoryKiB: 1024, passes: 3, parallelism: 2 });

    const restored = await manager.restoreWithPassword(validateBackupFile(file), PASSWORD);
    assertEqual(restored.ethereumAddress, address, 'restores with the file parameters');

    const tooBig = {
      ...file,
      passwordEncryption: { ...file.passwordEncryption!, memoryKiB: ARGON2ID_MAX_PARAMS.memoryKiB + 1 },
    };
    assert((await capture(() => manager.parseBackupFile(JSON.stringify(tooBig)))) instanceof Error, 'memory over the bound is rejected');
    const shortSalt = { ...file, passwordEncryption: { ...file.passwordEncryption!, salt: 'AAAAAAAAAAA=' } };
    assert((await capture(() => manager.parseBackupFile(JSON.stringify(shortSalt)))) instanceof Error, 'salt under 16 bytes is rejected');
    const lowMemory = { ...file, passwordEncryption: { ...file.passwordEncryption!, memoryKiB: 8, parallelism: 4 } };
    assert((await capture(() => manager.restoreWithPassword(lowMemory, PASSWORD))) instanceof Error, 'memory under 8*p is rejected, also without parseBackupFile');
    const noKdf = { ...file, passwordEncryption: { ...file.passwordEncryption!, kdf: 'pbkdf2' } };
    assert((await capture(() => manager.parseBackupFile(JSON.stringify(noKdf)))) instanceof Error, 'another kdf is rejected');
    passTest('parameters come from the file, within bounds');
  });

  await runTest('Password is NFC-normalized', async () => {
    const { mnemonic } = newWallet();
    const nfc = 'un caf\u00e9 bien serr\u00e9';
    const nfd = 'un cafe\u0301 bien serre\u0301';
    const { backupFile } = await manager.createPasswordBackup(mnemonic, nfc);
    const restored = await manager.restoreWithPassword(backupFile, nfd);
    assertEqual(restored.mnemonic, mnemonic, 'NFD input restores an NFC password');
    const fromNfd = await manager.createPasswordBackup(mnemonic, nfd);
    const restoredNfc = await manager.restoreWithPassword(fromNfd.backupFile, nfc);
    assertEqual(restoredNfc.mnemonic, mnemonic, 'NFC input restores an NFD password');
    passTest('NFC and NFD spellings match');
  });

  await runTest('Wrong password or altered file throws CryptoError', async () => {
    const { mnemonic } = newWallet();
    const { backupFile } = await manager.createPasswordBackup(mnemonic, PASSWORD);

    const wrong = await capture(() => manager.restoreWithPassword(backupFile, 'wrong-password'));
    assert(wrong instanceof CryptoError, 'wrong password: CryptoError');

    const bytes = atob(backupFile.encryptedMnemonic);
    const flipped = bytes.slice(0, 20) + String.fromCharCode(bytes.charCodeAt(20) ^ 1) + bytes.slice(21);
    const altered = await capture(() =>
      manager.restoreWithPassword({ ...backupFile, encryptedMnemonic: btoa(flipped) }, PASSWORD)
    );
    assert(altered instanceof CryptoError, 'altered ciphertext: CryptoError');
    passTest('rejected');
  });

  await runTest('PRF backup round trip', async () => {
    const { mnemonic, address } = newWallet();
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));
    const prfSalt = 'c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ';
    const { json } = await manager.createPrfBackup(
      mnemonic,
      { id: 'credential-id', publicKey: 'public-key' },
      'alice',
      prfSalt,
      prfOutput
    );
    assertNoAddress(json, address, 'prf');

    const backupFile = await manager.parseBackupFile(json);
    assertEqual(backupFile.version, 4, 'version is 4');
    const restored = await manager.restoreWithPrf(backupFile, prfOutput);
    assertEqual(restored.mnemonic, mnemonic, 'mnemonic restored');
    assertEqual(restored.ethereumAddress, address, 'address derived from the mnemonic');
    passTest('prf file round-trips');
  });

  await runTest('Files that are not v4 throw UnsupportedBackupVersionError', async () => {
    const v2 = {
      createdAt: new Date().toISOString(),
      ethereumAddress: '0x0000000000000000000000000000000000000001',
      encryptedMnemonic: 'AAAA',
      encryptionMethod: 'password',
      passwordEncryption: { salt: 'AAAA', iv: 'AAAA', iterations: 310000 },
      addressChecksum: 'AAAAAAAAAAAAAAAA',
    };
    const error = await capture(() => manager.parseBackupFile(JSON.stringify(v2)));
    assert(error instanceof UnsupportedBackupVersionError, 'v2: UnsupportedBackupVersionError');
    assertEqual((error as UnsupportedBackupVersionError).code, 'BACKUP_VERSION_UNSUPPORTED', 'code');

    assert((error as Error).message.includes('v0.10.6'), 'password v2: names the v0.10.6 tool');

    const prfError = await capture(() =>
      manager.parseBackupFile(JSON.stringify({ ...v2, encryptionMethod: 'prf' }))
    );
    assert((prfError as Error).message.includes('exportForSync()'), 'prf v2: asks for a new export');

    const v2error = await capture(() => manager.parseBackupFile(JSON.stringify({ ...v2, version: 2 })));
    assert(
      v2error instanceof UnsupportedBackupVersionError && v2error.version === 2,
      'version 2: carries the version'
    );
    passTest('rejected with a typed error');
  });

  await runTest('v3 files are rejected and point to the tool that reads them', async () => {
    const { backupFile } = await manager.createPasswordBackup(newWallet().mnemonic, PASSWORD);
    const v3 = { ...backupFile, version: 3 };
    const error = await capture(() => manager.parseBackupFile(JSON.stringify(v3)));
    assert(error instanceof UnsupportedBackupVersionError && error.version === 3, 'password v3: UnsupportedBackupVersionError');
    assert(
      (error as Error).message.includes('b14c32c658cc740aff78a1bbdb1cdb75c3b15a87/standalone/extract-mnemonic.html'),
      'password v3: names the last tool that reads v3'
    );
    const restoreError = await capture(() => manager.restoreWithPassword(v3 as unknown as BackupFile, PASSWORD));
    assert(restoreError instanceof UnsupportedBackupVersionError, 'restoreWithPassword refuses v3 too');

    const prf = await capture(() =>
      manager.parseBackupFile(JSON.stringify({ ...v3, encryptionMethod: 'prf' }))
    );
    assert((prf as Error).message.includes('exportForSync()'), 'prf v3: asks for a new export');
    passTest('rejected');
  });

  await runTest('Editing any metadata field makes the restore fail', async () => {
    const { mnemonic } = newWallet();
    const credential = { id: 'credential-id', publicKey: 'public-key' };
    const { backupFile } = await manager.createPasswordBackup(mnemonic, PASSWORD, credential, 'alice');
    const kdf = backupFile.passwordEncryption!;
    const otherSalt = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));

    const passwordEdits: [string, BackupFile][] = [
      ['createdAt', { ...backupFile, createdAt: new Date(0).toISOString() }],
      ['credential.id', { ...backupFile, credential: { ...credential, id: 'other-id' } }],
      ['credential.publicKey', { ...backupFile, credential: { ...credential, publicKey: 'other-key' } }],
      ['credential removed', { ...backupFile, credential: undefined }],
      ['username', { ...backupFile, username: 'mallory' }],
      ['username removed', { ...backupFile, username: undefined }],
      ['salt', { ...backupFile, passwordEncryption: { ...kdf, salt: otherSalt } }],
      ['memoryKiB', { ...backupFile, passwordEncryption: { ...kdf, memoryKiB: 32768 } }],
      ['passes', { ...backupFile, passwordEncryption: { ...kdf, passes: 2 } }],
      ['parallelism', { ...backupFile, passwordEncryption: { ...kdf, parallelism: 2 } }],
    ];
    for (const [field, edited] of passwordEdits) {
      const json = JSON.stringify(edited);
      const error = await capture(async () =>
        manager.restoreWithPassword(await manager.parseBackupFile(json), PASSWORD)
      );
      assert(error instanceof CryptoError, `password ${field}: CryptoError`);
    }

    const extra = await capture(() =>
      manager.parseBackupFile(JSON.stringify({ ...backupFile, ethereumAddress: '0x01' }))
    );
    assert(extra instanceof Error && /unknown fields/.test(extra.message), 'an unknown field is rejected');
    const extraKdf = await capture(() =>
      manager.parseBackupFile(JSON.stringify({ ...backupFile, passwordEncryption: { ...kdf, iv: 'AAAA' } }))
    );
    assert(extraKdf instanceof Error, 'an unknown Argon2id field is rejected');

    const prfOutput = crypto.getRandomValues(new Uint8Array(32));
    const prfSalt = 'c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ';
    const prf = (await manager.createPrfBackup(mnemonic, credential, 'alice', prfSalt, prfOutput)).backupFile;
    const prfEdits: [string, BackupFile][] = [
      ['createdAt', { ...prf, createdAt: new Date(0).toISOString() }],
      ['credential.id', { ...prf, credential: { ...credential, id: 'other-id' } }],
      ['credential.publicKey', { ...prf, credential: { ...credential, publicKey: 'other-key' } }],
      ['username', { ...prf, username: 'mallory' }],
      ['prfSalt', { ...prf, prfSalt: prfSalt.slice(0, -1) + 'A' }],
    ];
    for (const [field, edited] of prfEdits) {
      const error = await capture(async () =>
        manager.restoreWithPrf(await manager.parseBackupFile(JSON.stringify(edited)), prfOutput)
      );
      assert(error instanceof CryptoError, `prf ${field}: CryptoError`);
    }
    assertEqual((await manager.restoreWithPrf(prf, prfOutput)).mnemonic, mnemonic, 'the unedited PRF file restores');
    passTest(`${passwordEdits.length} password and ${prfEdits.length} PRF edits refused`);
  });

  await runTest('The additional data is the documented encoding', async () => {
    const aad = backupAdditionalData({
      version: 4,
      createdAt: 'T',
      encryptionMethod: 'prf',
      credential: { id: 'i', publicKey: 'pk' },
      prfSalt: 's',
      username: 'é',
    });
    const hex = Array.from(aad, (b) => b.toString(16).padStart(2, '0')).join('');
    const str = (text: string) => {
      const bytes = new TextEncoder().encode(text);
      return '01' + bytes.length.toString(16).padStart(8, '0') + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    };
    const expected =
      str('w3pk-backup-v4') + '0100000004' + str('T') + str('prf') +
      '00'.repeat(5) + str('i') + str('pk') + str('s') + str('é');
    assertEqual(hex, expected, 'fixed order, length-prefixed, absent fields as 0x00');
    passTest(`${aad.length} bytes`);
  });

  await runTest('Social recovery splits and rebuilds a v4 file', async () => {
    const { mnemonic, address } = newWallet();
    const recovery = new SocialRecovery();
    const { backupFile } = await manager.createPasswordBackup(mnemonic, PASSWORD);
    const guardians = ['Alice', 'Bob', 'Charlie', 'David', 'Eve'].map((name) => ({ name }));

    const setup = await recovery.splitAmongGuardians(backupFile, guardians, 3, address);
    assert(setup.guardianShares.every((s) => s.walletAddress === address), 'shares carry the address');

    for (const count of [3, 4, 5]) {
      const rebuilt = await recovery.recoverFromShares(setup.guardianShares.slice(0, count));
      assertEqual(rebuilt.version, 4, `${count} shares: v4 file`);
      const restored = await manager.restoreWithPassword(rebuilt, PASSWORD);
      assertEqual(restored.ethereumAddress, address, `${count} shares: restores the wallet`);
    }

    const verified = await recovery.verifyRecovery(setup.guardianShares.slice(1, 4));
    assert(verified.canRecover && verified.recoveredAddress === address, 'verifyRecovery');

    const { version: _, ...v2 } = backupFile;
    const v2setup = await recovery.splitAmongGuardians(v2 as BackupFile, guardians, 3, address);
    const v2error = await capture(() => recovery.recoverFromShares(v2setup.guardianShares.slice(0, 3)));
    assert(v2error instanceof UnsupportedBackupVersionError, 'shares of a v2 file: UnsupportedBackupVersionError');
    passTest('3, 4 and 5 shares restore');
  });

  await runTest('Downloadable backup filename has no address', async () => {
    const { mnemonic, address } = newWallet();
    const { backupFile } = await manager.createPasswordBackup(mnemonic, PASSWORD);
    const download = manager.createDownloadableBackup(backupFile);

    assert(!download.filename.toLowerCase().includes(address.slice(2, 8).toLowerCase()), 'no address in the filename');
    assertEqual((await manager.parseBackupFile(await download.blob.text())).version, 4, 'parses back');
    passTest(download.filename);
  });

  endTestSuite();
}

runTests();
