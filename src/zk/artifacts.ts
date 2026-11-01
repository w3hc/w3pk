/**
 * Circuit artifact verification against CIDs pinned onchain
 */

import {
  Web3PasskeyError,
  ZkArtifactMismatchError,
  type ZkArtifactName,
} from "../core/errors";
import { computeIpfsCid } from "../utils/ipfs-cid";

/** Artifact bytes, or a URL to fetch them from */
export type ZkArtifactSource = ArrayBufferView | ArrayBuffer | string;

export type ZkArtifactSources = Record<ZkArtifactName, ZkArtifactSource>;

/**
 * IPFS CIDv1 strings in base32, as `ipfs add --cid-version 1` prints them,
 * compared as exact strings
 */
export type ZkArtifactPins = Record<ZkArtifactName, string>;

export type ZkArtifactBytes = Record<ZkArtifactName, Uint8Array>;

/**
 * Any contract with the build registry's `getCidByVersion(string)`,
 * such as an ethers `Contract`
 */
export interface ZkArtifactRegistry {
  getCidByVersion(key: string): Promise<string>;
}

const ARTIFACTS: ZkArtifactName[] = ["wasm", "zkey"];

async function loadArtifact(
  name: ZkArtifactName,
  source: ZkArtifactSource
): Promise<Uint8Array> {
  if (source instanceof Uint8Array) return source;
  if (typeof source !== "string") {
    return ArrayBuffer.isView(source)
      ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
      : new Uint8Array(source);
  }

  let response: Response;
  try {
    response = await fetch(source);
  } catch (error) {
    throw new Web3PasskeyError(
      `Failed to fetch the ${name} artifact from ${source}`,
      "ZK_ARTIFACT_FETCH_ERROR",
      error
    );
  }
  if (!response.ok) {
    throw new Web3PasskeyError(
      `Failed to fetch the ${name} artifact from ${source}: ${response.status} ${response.statusText}`,
      "ZK_ARTIFACT_FETCH_ERROR"
    );
  }
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Reads the pinned CIDs of a circuit's artifacts from a registry with the
 * build registry's interface, under the given keys
 *
 * @throws Web3PasskeyError `ZK_ARTIFACT_NOT_PINNED` if a key has no CID
 */
export async function readZkArtifactPins(
  registry: ZkArtifactRegistry,
  keys: Record<ZkArtifactName, string>
): Promise<ZkArtifactPins> {
  const [wasm, zkey] = await Promise.all(
    ARTIFACTS.map(async (name) => {
      const cid = await registry.getCidByVersion(keys[name]);
      if (!cid) {
        throw new Web3PasskeyError(
          `No CID is pinned for the ${name} artifact under '${keys[name]}'`,
          "ZK_ARTIFACT_NOT_PINNED"
        );
      }
      return cid;
    })
  );
  return { wasm, zkey };
}

/**
 * Computes the IPFS CIDs of a circuit's `.wasm` and `.zkey` and checks them
 * against the pinned CIDs. Prove with the returned bytes, not by fetching
 * the URLs again, so the checked artifacts are the ones used.
 *
 * @throws ZkArtifactMismatchError if an artifact's CID differs from its pin
 */
export async function verifyZkArtifacts(
  artifacts: ZkArtifactSources,
  pins: ZkArtifactPins
): Promise<ZkArtifactBytes> {
  const [wasm, zkey] = await Promise.all(
    ARTIFACTS.map(async (name) => {
      const bytes = await loadArtifact(name, artifacts[name]);
      const cid = await computeIpfsCid(bytes);
      if (cid !== pins[name]) {
        throw new ZkArtifactMismatchError(name, pins[name], cid);
      }
      return bytes;
    })
  );
  return { wasm, zkey };
}
