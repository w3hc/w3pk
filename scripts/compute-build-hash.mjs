/**
 * Script to compute the IPFS hash of the w3pk build
 * This can be run after building to verify reproducibility
 */

import fs from 'fs';
import path from 'path';
import { importer } from 'ipfs-unixfs-importer';
import { MemoryBlockstore } from 'blockstore-core';

/**
 * Computes the IPFS CIDv1 hash of data using UnixFS format
 */
async function computeIPFSHash(data, name = 'build') {
  // Create a memory blockstore (no actual storage)
  const blockstore = new MemoryBlockstore();

  // Convert data to async iterable
  const fileIterable = async function* () {
    yield {
      path: name,
      content: data,
    };
  };

  // Import and get CID
  const entries = importer(fileIterable(), blockstore, {
    cidVersion: 1,
    rawLeaves: true,
    wrapWithDirectory: false,
  });

  // Get the first (and only) entry
  for await (const entry of entries) {
    return entry.cid.toString();
  }

  throw new Error('Failed to generate CID');
}

/**
 * Main function
 */
async function main() {
  const distPath = path.join(process.cwd(), 'dist');

  // Check if dist exists
  if (!fs.existsSync(distPath)) {
    console.error('❌ Error: dist/ directory not found. Please run `pnpm build` first.');
    process.exit(1);
  }

  // Read the main build files
  const files = [
    'index.js',
    'index.mjs',
    'index.d.ts',
  ];

  console.log('📦 Computing IPFS hash of w3pk build...\n');

  const chunks = [];
  for (const file of files) {
    const filePath = path.join(distPath, file);
    if (!fs.existsSync(filePath)) {
      console.error(`❌ Error: ${file} not found in dist/`);
      process.exit(1);
    }
    const content = fs.readFileSync(filePath);
    chunks.push(content);
    console.log(`   ✓ ${file} (${content.length} bytes)`);
  }

  // Concatenate all files
  const buildData = Buffer.concat(chunks);
  console.log(`\n📊 Total size: ${buildData.length} bytes`);

  // Compute hash
  const ipfsHash = await computeIPFSHash(buildData, 'w3pk-build');

  console.log('\n🔐 IPFS Build Hash (CIDv1):');
  console.log(`   ${ipfsHash}`);

  // Read package.json for version
  const packageJson = JSON.parse(
    fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf-8')
  );

  console.log(`\n📌 Version: ${packageJson.version}`);
  console.log('\n✅ Hash computation complete!');
  console.log('\n💡 Users can verify this hash in their apps:');
  console.log(`   import { getCurrentBuildHash } from 'w3pk/utils/build-hash';`);
  console.log(`   const hash = await getCurrentBuildHash();`);

  // Optionally save to file
  const hashFilePath = path.join(distPath, 'BUILD_HASH.txt');
  fs.writeFileSync(hashFilePath, `${ipfsHash}\n`);
  console.log(`\n💾 Hash saved to: dist/BUILD_HASH.txt`);
}

main().catch((error) => {
  console.error('❌ Error:', error);
  process.exit(1);
});
