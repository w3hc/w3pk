/**
 * standalone/extract-mnemonic.html decrypts BackupFile v3 password files
 * offline: runs the page's inlined Argon2id and decrypt scripts against
 * files made by the SDK. They run through new Function rather than node:vm,
 * whose global lookups make the Argon2id loop about 20 times slower.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Wallet } from 'ethers';
import { BackupFileManager } from '../src/backup/backup-file';
import { startTestSuite, endTestSuite, runTest, passTest, assert, assertEqual } from './test-utils';

const html = readFileSync(join(__dirname, '..', 'standalone', 'extract-mnemonic.html'), 'utf8');
const PASSWORD = 'café-TestPassword123!NotReal';

function inlineScript(id: string): string {
  const match = html.match(new RegExp(`<script id="${id}">([\\s\\S]*?)</script>`));
  if (!match) throw new Error(`no inline script #${id}`);
  return match[1];
}

type PageDecrypt = (backup: unknown, password: string) => Promise<string>;

function pageContext(): PageDecrypt {
  return new Function(
    `${inlineScript('argon2id')}\n${inlineScript('w3pk-decrypt')}\nreturn decryptPasswordBackup;`
  )();
}

function pageDecrypt(decrypt: PageDecrypt, backup: unknown, password: string): Promise<string> {
  return decrypt(JSON.parse(JSON.stringify(backup)), password);
}

async function capture(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
  } catch (error) {
    return error;
  }
  return undefined;
}

function messageOf(error: unknown): string {
  return String((error as { message?: string } | undefined)?.message ?? '');
}

async function runTests() {
  startTestSuite('Standalone Extractor Tests');

  await runTest('Argon2id is inlined, with no CDN', async () => {
    assert(html.includes('<!-- argon2id:start -->') && html.includes('<!-- argon2id:end -->'), 'markers present');
    assert(!/<script[^>]+src=[^>]*(noble|argon2)/i.test(html), 'Argon2id is not loaded from a URL');
    assert(inlineScript('argon2id').includes('nobleArgon2'), 'bundle defines nobleArgon2');
    passTest(`bundle ${inlineScript('argon2id').length} bytes`);
  });

  await runTest('Decrypts a v3 password backup made by the SDK', async () => {
    const wallet = Wallet.createRandom();
    const { backupFile } = await new BackupFileManager().createPasswordBackup(
      wallet.mnemonic!.phrase,
      PASSWORD
    );
    const context = pageContext();

    const start = performance.now();
    const mnemonic = await pageDecrypt(context, backupFile, PASSWORD.normalize('NFD'));
    const ms = performance.now() - start;
    assertEqual(mnemonic, wallet.mnemonic!.phrase, 'page decrypts the mnemonic');

    const wrong = await capture(() => pageDecrypt(context, backupFile, 'wrong-password'));
    assert(/Wrong password/.test(messageOf(wrong)), 'wrong password is rejected');
    passTest(`decrypted in ${ms.toFixed(0)} ms`);
  });

  await runTest('Rejects v2 files and unbounded parameters', async () => {
    const context = pageContext();
    const v2 = {
      ethereumAddress: '0x0000000000000000000000000000000000000001',
      encryptedMnemonic: 'AAAA',
      encryptionMethod: 'password',
      passwordEncryption: { salt: 'AAAA', iv: 'AAAA', iterations: 310000 },
    };
    const v2error = await capture(() => pageDecrypt(context, v2, PASSWORD));
    assert(
      messageOf(v2error).includes('v0.10.6/standalone/extract-mnemonic.html'),
      'v2 file points to the v0.10.6 tool'
    );

    const { backupFile } = await new BackupFileManager().createPasswordBackup(
      Wallet.createRandom().mnemonic!.phrase,
      PASSWORD
    );
    const huge = {
      ...backupFile,
      passwordEncryption: { ...backupFile.passwordEncryption!, memoryKiB: 4194304 },
    };
    const hugeError = await capture(() => pageDecrypt(context, huge, PASSWORD));
    assert(/Argon2id/.test(messageOf(hugeError)), 'memory over the bound is rejected');
    passTest('rejected');
  });

  endTestSuite();
}

runTests();
