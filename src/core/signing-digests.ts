import {
  TypedDataEncoder,
  concat,
  getAddress,
  getBigInt,
  getBytes,
  hashMessage,
  keccak256,
  toBeHex,
  type BigNumberish,
  type TypedDataDomain,
  type TypedDataField,
} from "ethers";
import { WalletError } from "./errors";

/** Transaction object of `eth_sendTransaction` */
export interface SigningTransaction {
  to?: string | null;
  value?: BigNumberish;
  data?: string;
  [key: string]: unknown;
}

/** Typed data of `eth_signTypedData_v4` */
export interface SigningTypedData {
  domain: TypedDataDomain;
  types: Record<string, Array<TypedDataField>>;
  primaryType: string;
  message: Record<string, unknown>;
}

/** A signing request, as its EIP-1193 `request()` arguments */
export type SigningRequest =
  | { method: "eth_sendTransaction"; params: readonly [SigningTransaction, ...unknown[]] }
  | { method: "personal_sign"; params: readonly [string, ...unknown[]] }
  | { method: "eth_sign"; params: readonly [string, string, ...unknown[]] }
  | { method: "eth_signTypedData_v4"; params: readonly [string, string | SigningTypedData, ...unknown[]] };

/** ERC-8213 digests of a transaction */
export interface TransactionDigests {
  /** "Calldata Digest": `keccak256(uint256(len(data)) ‖ data)` */
  calldataDigest: string;
  /** Checksummed recipient, `null` for a contract creation; not covered by the Calldata Digest */
  to: string | null;
  /** Wei sent, `0n` when absent; not covered by the Calldata Digest */
  value: bigint;
}

/** ERC-8213 digests of EIP-712 typed data */
export interface TypedDataDigests {
  /** "EIP-712 Digest": `keccak256(0x1901 ‖ domainHash ‖ messageHash)` */
  eip712Digest: string;
  /** "Domain Hash": `hashStruct(eip712Domain)` */
  domainHash: string;
  /** "Message Hash": `hashStruct(message)` for `primaryType` */
  messageHash: string;
}

/** ERC-8213 digest of an ERC-191 message */
export interface MessageDigests {
  /** "ERC-191 Digest": `keccak256("\x19Ethereum Signed Message:\n" ‖ len(message) ‖ message)` */
  erc191Digest: string;
}

interface SigningDigestsByMethod {
  eth_sendTransaction: TransactionDigests;
  personal_sign: MessageDigests;
  eth_sign: MessageDigests;
  eth_signTypedData_v4: TypedDataDigests;
}

export type SigningDigests<R extends SigningRequest = SigningRequest> = SigningDigestsByMethod[R["method"]];

/** Returns true if a value is 0x-prefixed hex encoding whole bytes */
const isHex = (value: unknown): value is string =>
  typeof value === "string" && /^0x(?:[0-9a-fA-F]{2})*$/.test(value);

function calldataDigests(tx: SigningTransaction): TransactionDigests {
  const data = getBytes(tx.data ?? "0x");
  return {
    calldataDigest: keccak256(concat([toBeHex(data.length, 32), data])),
    to: tx.to == null ? null : getAddress(tx.to),
    value: getBigInt(tx.value ?? 0),
  };
}

/** The ERC-191 message of `personal_sign` or `eth_sign` data: `0x` hex as bytes, any other string as UTF-8 */
export const erc191Message = (data: string): string | Uint8Array => (isHex(data) ? getBytes(data) : data);

function erc191Digests(data: string): MessageDigests {
  return { erc191Digest: hashMessage(erc191Message(data)) };
}

/** `primaryType` and the types it references, without `EIP712Domain` */
function reachableTypes(types: SigningTypedData["types"], primaryType: string): SigningTypedData["types"] {
  const reached: SigningTypedData["types"] = {};
  const visit = (type: string) => {
    const name = type.replace(/(\[\d*\])+$/, "");
    if (name === "EIP712Domain" || reached[name] || !types[name]) return;
    reached[name] = types[name];
    for (const field of types[name]) visit(field.type);
  };
  visit(primaryType);
  if (!reached[primaryType]) {
    throw new WalletError(`EIP-712: primaryType ${primaryType} is not in types`);
  }
  return reached;
}

/**
 * A copy of typed data as it is signed: `types` without `EIP712Domain`, so that ethers, which
 * infers the primary type, hashes `primaryType`
 *
 * Throws on types `primaryType` doesn't reach, which includes a root above `primaryType`, and on a
 * domain that `types.EIP712Domain` doesn't declare as is.
 */
export function signableTypedData(typedData: string | SigningTypedData): SigningTypedData {
  const { domain, types, primaryType, message }: SigningTypedData =
    typeof typedData === "string" ? JSON.parse(typedData) : structuredClone(typedData);
  if (!domain || !types || typeof primaryType !== "string" || !message) {
    throw new WalletError("EIP-712: typed data needs domain, types, primaryType and message");
  }
  if (
    types.EIP712Domain &&
    TypedDataEncoder.hashStruct("EIP712Domain", { EIP712Domain: types.EIP712Domain }, domain) !==
      TypedDataEncoder.hashDomain(domain)
  ) {
    throw new WalletError("EIP-712: domain does not match types.EIP712Domain");
  }
  const reached = reachableTypes(types, primaryType);
  const unused = Object.keys(types).filter((name) => name !== "EIP712Domain" && !reached[name]);
  if (unused.length > 0) {
    throw new WalletError(`EIP-712: types not reached from primaryType ${primaryType}: ${unused.join(", ")}`);
  }
  return { domain, types: reached, primaryType, message };
}

function typedDataDigests(typedData: string | SigningTypedData): TypedDataDigests {
  const { domain, types, primaryType, message } = signableTypedData(typedData);
  const domainHash = TypedDataEncoder.hashDomain(domain);
  const messageHash = TypedDataEncoder.hashStruct(primaryType, types, message);
  return {
    eip712Digest: keccak256(concat(["0x1901", domainHash, messageHash])),
    domainHash,
    messageHash,
  };
}

/**
 * ERC-8213 digests of a signing request, for the user to check on a second tool before signing
 *
 * - `eth_sendTransaction`: Calldata Digest, plus `to` and `value`, which the digest does not cover
 * - `eth_signTypedData_v4`: EIP-712 Digest, Domain Hash and Message Hash; throws on types that
 *   `primaryType` doesn't reach, as the root type is the one signed
 * - `personal_sign`, `eth_sign`: ERC-191 Digest; `0x` hex is decoded to bytes, any other string is UTF-8
 *
 * Empty or missing calldata still has a Calldata Digest (`keccak256` of 32 zero bytes). The digests
 * depend on the request only, never on the security mode: in `PRIMARY`, they are the original
 * EIP-712 or ERC-191 digest, not the ERC-7739 hash the passkey signs, and the request's `data`,
 * not the ERC-4337 `execute()` callData.
 */
export function getSigningDigests<R extends SigningRequest>(request: R): SigningDigests<R>;
export function getSigningDigests(request: SigningRequest): SigningDigests {
  switch (request.method) {
    case "eth_sendTransaction":
      return calldataDigests(request.params[0]);
    case "personal_sign":
      return erc191Digests(request.params[0]);
    case "eth_sign":
      return erc191Digests(request.params[1]);
    case "eth_signTypedData_v4":
      return typedDataDigests(request.params[1]);
    default:
      throw new WalletError(
        `getSigningDigests: unsupported method ${(request as { method: string }).method}`
      );
  }
}
