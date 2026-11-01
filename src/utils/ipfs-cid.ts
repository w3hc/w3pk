import type { WritableStorage } from "ipfs-unixfs-importer";

/** Keeps no blocks, so hashing a large file holds a single copy of it */
const discardBlocks: WritableStorage = { put: (cid) => cid };

/**
 * Computes the IPFS CIDv1 of a file as `ipfs add --cid-version 1` does:
 * UnixFS, raw leaves, 256 KiB fixed-size chunks, balanced layout
 */
export async function computeIpfsCid(data: Uint8Array): Promise<string> {
  // Lazy load (ESM-only optional dependency)
  const { importBytes } = await import("ipfs-unixfs-importer");
  const { cid } = await importBytes(data, discardBlocks, {
    cidVersion: 1,
    rawLeaves: true,
    wrapWithDirectory: false,
  });
  return cid.toString();
}
