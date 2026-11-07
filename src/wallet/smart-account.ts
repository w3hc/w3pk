import { AbiCoder, getCreate2Address, hexlify, keccak256, toUtf8Bytes } from "ethers";
import { WalletError } from "../core/errors";
import { base64UrlToArrayBuffer } from "../utils/base64";
import { DEFAULT_TAG } from "./origin-derivation";

/** `W3pkAccountFactory`, at the same address on every chain */
export const W3PK_ACCOUNT_FACTORY = "0xe341d909A1D7dEeec787796b8d305c064aEB5181";

/** keccak256 of the ERC-1167 clone init code of the `W3pkAccount` implementation */
export const W3PK_ACCOUNT_INIT_CODE_HASH =
  "0x25e8fe200bdf4198a104e71276a83130d745fc9bf71ce23b1e3690729bc6d0c6";

export interface SmartAccountConfig {
  factoryAddress?: string;
  initCodeHash?: string;
}

/**
 * x and y coordinates of a P-256 public key, as 0x-prefixed 32-byte hex
 *
 * @param publicKeySpki - Public key in SPKI format (base64url encoded)
 */
export async function getP256Coordinates(
  publicKeySpki: string
): Promise<{ qx: string; qy: string }> {
  const key = await crypto.subtle.importKey(
    "spki",
    base64UrlToArrayBuffer(publicKeySpki),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (!jwk.x || !jwk.y) {
    throw new WalletError("Invalid P-256 public key: missing x or y coordinates");
  }
  return {
    qx: hexlify(new Uint8Array(base64UrlToArrayBuffer(jwk.x))),
    qy: hexlify(new Uint8Array(base64UrlToArrayBuffer(jwk.y))),
  };
}

/**
 * CREATE2 salt of the smart account, as `W3pkAccountFactory.salt` computes it:
 * `keccak256(abi.encode(qx, qy, keccak256(bytes(tag))))`
 */
export function getSmartAccountSalt(qx: string, qy: string, tag: string = DEFAULT_TAG): string {
  return keccak256(
    AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32"],
      [qx, qy, keccak256(toUtf8Bytes(tag))]
    )
  );
}

/**
 * Counterfactual address of the passkey's P-256 smart account for a tag,
 * deployed or not. Computed offchain, with no RPC call.
 *
 * @param publicKeySpki - Public key in SPKI format (base64url encoded)
 * @param tag - Account tag (default: "MAIN")
 * @param config - Factory address and init code hash overrides
 * @returns Checksummed address
 */
export async function getSmartAccountAddress(
  publicKeySpki: string,
  tag: string = DEFAULT_TAG,
  config: SmartAccountConfig = {}
): Promise<string> {
  const { qx, qy } = await getP256Coordinates(publicKeySpki);
  return getCreate2Address(
    config.factoryAddress ?? W3PK_ACCOUNT_FACTORY,
    getSmartAccountSalt(qx, qy, tag),
    config.initCodeHash ?? W3PK_ACCOUNT_INIT_CODE_HASH
  );
}
