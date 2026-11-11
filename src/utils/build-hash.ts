/**
 * Build Hash Utilities
 * Computes IPFS CIDv1 hash of the w3pk build output using official IPFS libraries
 */

import { sha512 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { version } from '../../package.json';
import { computeIpfsCid } from './ipfs-cid';

const NPM_REGISTRY = 'https://registry.npmjs.org';
const BUILD_FILES = ['index.js', 'index.mjs', 'index.d.ts'];

async function fetchBytes(url: string, label: string): Promise<Uint8Array> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch ${label}: ${response.status} ${response.statusText}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Fetches and concatenates the main build files for hashing
 * This includes the core library files that users would verify
 */
async function fetchBuildFiles(baseUrl: string): Promise<Uint8Array> {
  const chunks = await Promise.all(
    BUILD_FILES.map((file) => fetchBytes(`${baseUrl}/${file}`, file))
  );
  return concatBytes(...chunks);
}

/**
 * Fetches the w3pk tarball of `version` from the npm registry and checks it
 * against the registry's `dist.integrity` (SHA-512)
 */
async function fetchNpmTarball(version: string): Promise<Uint8Array> {
  const response = await fetch(`${NPM_REGISTRY}/w3pk/${version}`);
  if (!response.ok) {
    throw new Error(
      `Failed to fetch w3pk@${version} from the npm registry: ${response.status} ${response.statusText}`
    );
  }
  const { dist } = (await response.json()) as { dist?: { tarball?: string; integrity?: string } };

  const tarballUrl = `${NPM_REGISTRY}/w3pk/-/w3pk-${version}.tgz`;
  if (dist?.tarball !== tarballUrl) {
    throw new Error(`Unexpected tarball URL for w3pk@${version}: ${dist?.tarball}`);
  }
  const integrity = /^sha512-([A-Za-z0-9+/]{86}==)$/.exec(dist.integrity ?? '');
  if (!integrity) {
    throw new Error(`Missing SHA-512 integrity for w3pk@${version}`);
  }

  const tarball = await fetchBytes(tarballUrl, `w3pk-${version}.tgz`);
  if (btoa(String.fromCharCode(...sha512(tarball))) !== integrity[1]) {
    throw new Error(`w3pk-${version}.tgz does not match its npm registry integrity`);
  }
  return tarball;
}

async function gunzip(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Reads regular files from a ustar archive, in the order of `paths`
 */
export function readTarFiles(tar: Uint8Array, paths: string[]): Uint8Array[] {
  const decoder = new TextDecoder();
  const field = (start: number, length: number) =>
    decoder.decode(tar.subarray(start, start + length)).replace(/\0[\s\S]*$/, '');

  const files = new Map<string, Uint8Array>();
  let offset = 0;
  for (;;) {
    if (offset + 512 > tar.length) throw new Error('Malformed tar archive');
    if (tar[offset] === 0) break;
    const size = parseInt(field(offset + 124, 12).trim(), 8);
    const start = offset + 512;
    if (!Number.isSafeInteger(size) || size < 0 || start + size > tar.length) {
      throw new Error('Malformed tar archive');
    }
    const type = tar[offset + 156];
    if (type === 0x30 || type === 0) {
      const name = field(offset, 100);
      const prefix = field(offset + 345, 155);
      files.set(prefix ? `${prefix}/${name}` : name, tar.subarray(start, start + size));
    }
    offset = start + Math.ceil(size / 512) * 512;
  }

  return paths.map((path) => {
    const file = files.get(path);
    if (!file) throw new Error(`${path} not found in tar archive`);
    return file;
  });
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
  return version;
}

/**
 * Computes the build hash of the installed w3pk version as published on the
 * npm registry (the published package, not the running code)
 *
 * The tarball is fetched from registry.npmjs.org, checked against the
 * registry's `dist.integrity`, and its `dist/index.js`, `dist/index.mjs` and
 * `dist/index.d.ts` are hashed. No CDN is involved.
 *
 * @returns IPFS CIDv1 hash of the build
 *
 * @example
 * ```typescript
 * const hash = await getCurrentBuildHash();
 * console.log('Current w3pk build hash:', hash);
 * ```
 */
export async function getCurrentBuildHash(): Promise<string> {
  const tar = await gunzip(await fetchNpmTarball(getPackageVersion()));
  const files = readTarFiles(tar, BUILD_FILES.map((file) => `package/dist/${file}`));
  return computeIpfsCid(concatBytes(...files));
}

/**
 * Verifies if a given hash matches the build published on the npm registry
 * for the installed version
 *
 * This hashes the files of the npm tarball, not the code actually running:
 * a bundled, modified or injected copy is not checked, and compromised
 * running code can return any result. Hash the files you ship at build time
 * to check those.
 *
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
