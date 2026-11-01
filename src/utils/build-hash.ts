/**
 * Build Hash Utilities
 * Computes IPFS CIDv1 hash of the w3pk build output using official IPFS libraries
 */

import { computeIpfsCid } from './ipfs-cid';

/**
 * Fetches and concatenates the main build files for hashing
 * This includes the core library files that users would verify
 */
async function fetchBuildFiles(baseUrl: string): Promise<Uint8Array> {
  const files = [
    'index.js',
    'index.mjs',
    'index.d.ts',
  ];

  const chunks: Uint8Array[] = [];
  let totalLength = 0;

  for (const file of files) {
    const url = `${baseUrl}/${file}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to fetch ${file}: ${response.statusText}`);
    }
    const arrayBuffer = await response.arrayBuffer();
    const chunk = new Uint8Array(arrayBuffer);
    chunks.push(chunk);
    totalLength += chunk.length;
  }

  // Concatenate all chunks
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return result;
}

/**
 * Computes the IPFS hash of the w3pk package build
 * @param distUrl URL to the dist folder (e.g., from CDN or local server)
 * @returns IPFS CIDv1 hash string
 *
 * @example
 * ```typescript
 * // From a CDN
 * const hash = await getW3pkBuildHash('https://unpkg.com/w3pk@0.7.6/dist');
 * console.log('Build hash:', hash);
 *
 * // From local development
 * const hash = await getW3pkBuildHash('http://localhost:3000/dist');
 * ```
 */
export async function getW3pkBuildHash(distUrl: string): Promise<string> {
  const buildData = await fetchBuildFiles(distUrl);
  return computeIpfsCid(buildData);
}

/**
 * Gets the current package version from package.json
 */
export function getPackageVersion(): string {
  // Import version directly from package.json
  // This will be resolved at build time by the bundler
  try {
    // @ts-ignore - package.json import may not have types
    return require('../../package.json').version;
  } catch {
    throw new Error('Failed to read package version');
  }
}

/**
 * Computes build hash for the current w3pk version from unpkg CDN
 * @returns IPFS CIDv1 hash of the build
 *
 * @example
 * ```typescript
 * const hash = await getCurrentBuildHash();
 * console.log('Current w3pk build hash:', hash);
 * ```
 */
export async function getCurrentBuildHash(): Promise<string> {
  const version = getPackageVersion();
  return getW3pkBuildHash(`https://unpkg.com/w3pk@${version}/dist`);
}

/**
 * Verifies if a given hash matches the current build
 * @param expectedHash The hash to verify against
 * @returns true if hashes match, false otherwise
 *
 * @example
 * ```typescript
 * const isValid = await verifyBuildHash('bafybeih...');
 * if (isValid) {
 *   console.log('Build integrity verified!');
 * }
 * ```
 */
export async function verifyBuildHash(expectedHash: string): Promise<boolean> {
  const actualHash = await getCurrentBuildHash();
  return actualHash === expectedHash;
}
