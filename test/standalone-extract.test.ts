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
import { deriveOriginPath, getOriginSpecificAddress } from '../src/wallet/origin-derivation';
import { deriveWalletFromPath } from '../src/wallet/generate';
import type { SecurityMode } from '../src/types';
import { startTestSuite, endTestSuite, runTest, passTest, assert, assertEqual } from './test-utils';

const html = readFileSync(join(__dirname, '..', 'standalone', 'extract-mnemonic.html'), 'utf8');
const PASSWORD = 'café-TestStrongPass123!NotReal';

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

type PageDerive = {
  deriveOriginPath: (origin: string, mode?: string, tag?: string) => Promise<string>;
  deriveWalletFromPath: (mnemonic: string, path: string) => { address: string; privateKey: string };
};

function deriveContext(): PageDerive {
  return new Function(
    `${inlineScript('derive')}\n${inlineScript('w3pk-derive')}\nreturn { deriveOriginPath, deriveWalletFromPath };`
  )();
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
      passwordEncryption: { ...backupFile.passwordEncryption!, memoryKiB: 65537 },
    };
    const hugeError = await capture(() => pageDecrypt(context, huge, PASSWORD));
    assert(/Argon2id/.test(messageOf(hugeError)), 'memory over the bound is rejected');
    passTest('rejected');
  });

  await runTest('Loads nothing from the network and no ethers', async () => {
    assert(
      html.includes(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">`),
      'CSP blocks every request'
    );
    assert(html.indexOf('Content-Security-Policy') < html.indexOf('<script'), 'CSP comes before the first script');
    assert(!/<script[^>]+\bsrc=/i.test(html), 'no <script src>');
    assert(!/<link\b/i.test(html), 'no <link>');
    assert(!/<img\b/i.test(html), 'no <img>');
    assert(!/\b(fetch|XMLHttpRequest|WebSocket|EventSource|importScripts)\s*\(/.test(html), 'no request API calls');
    assert(!/ethers/i.test(html), 'no ethers reference');
    assert(html.includes('<!-- derive:start -->') && html.includes('<!-- derive:end -->'), 'derive markers present');
    passTest(`derive bundle ${inlineScript('derive').length} bytes`);
  });

  await runTest('Derives the same origin wallets and registration address as the SDK', async () => {
    const page = deriveContext();
    const cases: [string, SecurityMode, string][] = [
      ['https://example.com', 'STANDARD', 'MAIN'],
      ['https://Example.com:443/path?q=1', 'STRICT', 'main'],
      ['http://localhost:3000', 'YOLO', 'GAMING'],
      ['https://app.example.org:8443', 'YOLO', 'trading'],
      ['https://example.com', 'PRIMARY', 'MAIN'],
    ];
    const mnemonics = [
      'test test test test test test test test test test test junk',
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art',
    ];

    for (const mnemonic of mnemonics) {
      for (const [origin, mode, tag] of cases) {
        const path = await page.deriveOriginPath(origin, mode, tag);
        assertEqual(path, await deriveOriginPath(origin, mode, tag), `path for ${origin} ${mode} ${tag}`);
        const sdk = await getOriginSpecificAddress(mnemonic, origin, mode, tag);
        assertEqual(path, sdk.path, `path matches getOriginSpecificAddress for ${origin} ${mode} ${tag}`);
        const wallet = page.deriveWalletFromPath(mnemonic, path);
        assertEqual(wallet.privateKey, deriveWalletFromPath(mnemonic, path).privateKey, `key at ${path}`);
        assertEqual(wallet.address, sdk.address, `address for ${origin} ${mode} ${tag}`);
      }

      for (const path of ["m/44'/60'/0'/0/0", "m/44'/60'/0'/0/7"]) {
        const wallet = page.deriveWalletFromPath(mnemonic, path);
        const sdk = deriveWalletFromPath(mnemonic, path);
        assertEqual(wallet.address, sdk.address, `address at ${path}`);
        assertEqual(wallet.privateKey, sdk.privateKey, `key at ${path}`);
      }
    }

    assertEqual(
      page.deriveWalletFromPath(mnemonics[0], "m/44'/60'/0'/0/0").address,
      '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      'known registration address'
    );
    passTest(`${cases.length * mnemonics.length} origin wallets match`);
  });

  await runTest('Rejects malformed paths and unknown modes', async () => {
    const page = deriveContext();
    const mnemonic = 'test test test test test test test test test test test junk';
    for (const path of ['', 'm', "m/44'/x", "44'/60'", 'm/2147483648', "m/2147483648'"]) {
      const error = await capture(async () => page.deriveWalletFromPath(mnemonic, path));
      assert(/Invalid derivation path/.test(messageOf(error)), `rejects ${JSON.stringify(path)}`);
    }
    const modeError = await capture(() => page.deriveOriginPath('https://example.com', 'ADMIN', 'MAIN'));
    assert(/Unknown security mode/.test(messageOf(modeError)), 'rejects an unknown mode');
    passTest('rejected');
  });

  endTestSuite();
}

runTests();
