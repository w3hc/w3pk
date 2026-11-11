/**
 * Build Hash Tests
 * Tests for IPFS hash computation utilities
 */

import assert from 'node:assert';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import {
  getCurrentBuildHash,
  getPackageVersion,
  getW3pkBuildHash,
  readTarFiles,
  verifyBuildHash,
} from '../src/utils/build-hash';

console.log('\n🧪 Testing Build Hash Utilities...\n');

// Test the base32 encoding
function testBase32Encode() {
  console.log('Testing base32 encoding...');

  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';

  function base32Encode(data: Uint8Array): string {
    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < data.length; i++) {
      value = (value << 8) | data[i];
      bits += 8;

      while (bits >= 5) {
        output += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      output += alphabet[(value << (5 - bits)) & 31];
    }

    return output;
  }

  // Test with known values
  const testData = new Uint8Array([0x01, 0x02, 0x03]);
  const encoded = base32Encode(testData);
  console.log(`  ✓ Encoded test data: ${encoded}`);
}

// Test IPFS hash format
async function testIPFSHashFormat() {
  console.log('\nTesting IPFS hash format...');

  const testData = new TextEncoder().encode('Hello, IPFS!');
  const hashBuffer = await crypto.subtle.digest('SHA-256', testData);
  const hashArray = new Uint8Array(hashBuffer);

  // Create multihash
  const multihash = new Uint8Array(34);
  multihash[0] = 0x12; // SHA-256 identifier
  multihash[1] = 0x20; // Length (32 bytes)
  multihash.set(hashArray, 2);

  console.log('  ✓ Multihash format created');
  console.log(`    - Type: ${multihash[0]} (SHA-256)`);
  console.log(`    - Length: ${multihash[1]} bytes`);
  console.log(`    - Hash preview: ${Array.from(hashArray.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('')}...`);

  // Create CIDv1
  const cidBytes = new Uint8Array(36);
  cidBytes[0] = 0x01; // CIDv1
  cidBytes[1] = 0x70; // dag-pb codec
  cidBytes.set(multihash, 2);

  console.log('  ✓ CIDv1 format created');
  console.log(`    - Version: ${cidBytes[0]}`);
  console.log(`    - Codec: ${cidBytes[1]} (dag-pb)`);
}

// Test hash consistency
async function testHashConsistency() {
  console.log('\nTesting hash consistency...');

  const testData = new TextEncoder().encode('Test data for consistency check');

  // Compute hash twice
  const hash1 = await crypto.subtle.digest('SHA-256', testData);
  const hash2 = await crypto.subtle.digest('SHA-256', testData);

  const array1 = new Uint8Array(hash1);
  const array2 = new Uint8Array(hash2);

  let matches = true;
  for (let i = 0; i < array1.length; i++) {
    if (array1[i] !== array2[i]) {
      matches = false;
      break;
    }
  }

  if (matches) {
    console.log('  ✓ Hash is consistent across multiple computations');
  } else {
    console.log('  ✗ Hash inconsistency detected!');
  }
}

function testPackageVersion() {
  console.log('\nTesting package version...');

  const { version } = JSON.parse(
    readFileSync(new URL('../package.json', import.meta.url), 'utf8')
  );
  assert.strictEqual(getPackageVersion(), version);
  console.log(`  ✓ Package version: ${version}`);

  for (const file of ['index.js', 'index.mjs']) {
    const url = new URL(`../dist/${file}`, import.meta.url);
    if (!existsSync(url)) {
      console.log(`  - Skipped dist/${file} check: run pnpm build first`);
      continue;
    }
    const bundle = readFileSync(url, 'utf8');
    assert.ok(bundle.includes(`"${version}"`), `dist/${file} holds the version`);
    assert.ok(!bundle.includes('devDependencies'), `dist/${file} holds no devDependencies`);
    console.log(`  ✓ dist/${file} inlines only the version`);
  }
}

function tarEntry(name: string, data: Uint8Array, type = '0'): Uint8Array {
  const header = new Uint8Array(512);
  const write = (offset: number, value: string) => header.set(new TextEncoder().encode(value), offset);
  write(0, name);
  write(100, '0000644\0');
  write(124, data.length.toString(8).padStart(11, '0') + '\0');
  write(156, type);
  write(257, 'ustar\0');
  write(263, '00');
  const body = new Uint8Array(Math.ceil(data.length / 512) * 512);
  body.set(data);
  const entry = new Uint8Array(512 + body.length);
  entry.set(header);
  entry.set(body, 512);
  return entry;
}

function tarArchive(entries: Uint8Array[]): Uint8Array {
  return new Uint8Array(Buffer.concat([...entries, new Uint8Array(1024)]));
}

const buildFiles = {
  'index.js': new TextEncoder().encode('module.exports = 1;\n'),
  'index.mjs': new TextEncoder().encode('export default 1;\n'),
  'index.d.ts': new TextEncoder().encode('declare const x: 1;\nexport default x;\n'),
};

function testReadTarFiles() {
  console.log('\nTesting tar extraction...');

  const tar = tarArchive([
    tarEntry('package/dist', new Uint8Array(0), '5'),
    tarEntry('package/dist/index.mjs', buildFiles['index.mjs']),
    tarEntry('package/dist/index.js', buildFiles['index.js']),
    tarEntry('package/README.md', new Uint8Array(700)),
  ]);
  const [js, mjs] = readTarFiles(tar, ['package/dist/index.js', 'package/dist/index.mjs']);
  assert.deepStrictEqual(js, buildFiles['index.js']);
  assert.deepStrictEqual(mjs, buildFiles['index.mjs']);
  assert.throws(() => readTarFiles(tar, ['package/dist/index.d.ts']), /not found/);
  assert.throws(() => readTarFiles(tar.subarray(0, 600), ['package/dist/index.mjs']), /Malformed/);
  console.log('  ✓ Reads files in the requested order and rejects missing or truncated entries');
}

async function testNpmRegistrySource() {
  console.log('\nTesting the npm registry source...');

  const version = getPackageVersion();
  const tarballUrl = `https://registry.npmjs.org/w3pk/-/w3pk-${version}.tgz`;
  const tarball = gzipSync(
    tarArchive(
      Object.entries(buildFiles).map(([file, data]) => tarEntry(`package/dist/${file}`, data))
    )
  );
  const integrity = `sha512-${createHash('sha512').update(tarball).digest('base64')}`;

  const realFetch = globalThis.fetch;
  const requested: string[] = [];
  const serve = (dist: unknown, body: Uint8Array = tarball) => {
    requested.length = 0;
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = String(input);
      requested.push(url);
      if (url === `https://registry.npmjs.org/w3pk/${version}`) {
        return new Response(JSON.stringify({ dist }));
      }
      if (url === tarballUrl) return new Response(body);
      if (url.startsWith('https://dist.example/')) {
        return new Response(buildFiles[url.slice('https://dist.example/'.length) as keyof typeof buildFiles]);
      }
      return new Response(null, { status: 404, statusText: 'Not Found' });
    }) as typeof fetch;
  };

  try {
    serve({});
    const expected = await getW3pkBuildHash('https://dist.example');

    serve({ tarball: tarballUrl, integrity });
    assert.strictEqual(await getCurrentBuildHash(), expected);
    assert.ok(requested.every((url) => url.startsWith('https://registry.npmjs.org/')));
    assert.strictEqual(await verifyBuildHash(expected), true);
    assert.strictEqual(await verifyBuildHash('bafy-other'), false);
    console.log('  ✓ Hashes dist/index.js, index.mjs and index.d.ts of the registry tarball');

    const tampered = new Uint8Array(tarball);
    tampered[tampered.length - 1] ^= 1;
    serve({ tarball: tarballUrl, integrity }, tampered);
    await assert.rejects(getCurrentBuildHash(), /does not match its npm registry integrity/);
    console.log('  ✓ Rejects a tarball that does not match dist.integrity');

    serve({ tarball: 'https://cdn.example/w3pk.tgz', integrity });
    await assert.rejects(getCurrentBuildHash(), /Unexpected tarball URL/);
    serve({ tarball: tarballUrl, integrity: 'sha1-abc' });
    await assert.rejects(getCurrentBuildHash(), /Missing SHA-512 integrity/);
    console.log('  ✓ Rejects a foreign tarball URL or a missing SHA-512 integrity');
  } finally {
    globalThis.fetch = realFetch;
  }
}

// Run all tests
async function runTests() {
  try {
    testBase32Encode();
    await testIPFSHashFormat();
    await testHashConsistency();
    testPackageVersion();
    testReadTarFiles();
    await testNpmRegistrySource();

    console.log('\n✅ All build hash tests passed!\n');
    console.log('💡 To compute the actual build hash, run:');
    console.log('   pnpm build:hash\n');
  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
}

runTests();
