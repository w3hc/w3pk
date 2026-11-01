/**
 * Computes the IPFS CIDv1 of a file as `ipfs add --cid-version 1` does:
 * UnixFS, raw leaves, 256 KiB fixed-size chunks, balanced layout
 */
export async function computeIpfsCid(data: Uint8Array): Promise<string> {
  // Lazy load IPFS libraries (they are ESM-only and optional dependencies)
  const { importer } = await import("ipfs-unixfs-importer");
  const { MemoryBlockstore } = await import("blockstore-core");

  const entries = importer({ content: data }, new MemoryBlockstore(), {
    cidVersion: 1,
    rawLeaves: true,
    wrapWithDirectory: false,
  });

  for await (const entry of entries) {
    return entry.cid.toString();
  }

  throw new Error("Failed to generate CID");
}
