import {
  AbiCoder,
  TypedDataEncoder,
  concat,
  keccak256,
  solidityPacked,
  toUtf8Bytes,
  type TypedDataDomain,
  type TypedDataField,
} from "ethers";

/** The smart account a signature is bound to */
export interface Erc7739Account {
  address: string;
  chainId: number | bigint;
}

/** EIP-712 domain of `W3pkAccount`, set by `initialize` */
export const W3PK_ACCOUNT_DOMAIN_NAME = "W3pkAccount";
export const W3PK_ACCOUNT_DOMAIN_VERSION = "1";

/** ERC-6492 suffix of a signature from a contract not deployed yet */
export const ERC6492_MAGIC = "0x6492649264926492649264926492649264926492649264926492649264926492";

const PERSONAL_SIGN_TYPEHASH = keccak256(toUtf8Bytes("PersonalSign(bytes prefixed)"));
const ZERO_HASH = "0x" + "00".repeat(32);

function accountDomain(account: Erc7739Account): TypedDataDomain {
  return {
    name: W3PK_ACCOUNT_DOMAIN_NAME,
    version: W3PK_ACCOUNT_DOMAIN_VERSION,
    chainId: account.chainId,
    verifyingContract: account.address,
  };
}

function typedDataHash(domainSeparator: string, structHash: string): string {
  return keccak256(concat(["0x1901", domainSeparator, structHash]));
}

/**
 * Hash the passkey signs for an ERC-7739 `PersonalSign` signature: the EIP-191 hash nested in
 * `PersonalSign(bytes prefixed)` under the account's domain
 *
 * @param messageHash - EIP-191 hash of the message (`hashMessage`), as passed to `isValidSignature`
 */
export function personalSignHash(messageHash: string, account: Erc7739Account): string {
  const structHash = keccak256(
    AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32"], [PERSONAL_SIGN_TYPEHASH, messageHash])
  );
  return typedDataHash(TypedDataEncoder.hashDomain(accountDomain(account)), structHash);
}

/** ERC-7739 `TypedDataSign` nesting of an EIP-712 message */
export interface TypedDataSignPayload {
  /** EIP-712 hash of the message, as passed to `isValidSignature` */
  hash: string;
  /** Hash the passkey signs */
  challenge: string;
  appDomainSeparator: string;
  contentsHash: string;
  /** EIP-712 type of the primary type, with its dependencies (implicit mode) */
  contentsDescr: string;
}

/**
 * Nests an EIP-712 message in ERC-7739 `TypedDataSign` for the account
 */
export function typedDataSignPayload(
  domain: TypedDataDomain,
  types: Record<string, Array<TypedDataField>>,
  primaryType: string,
  message: Record<string, unknown>,
  account: Erc7739Account
): TypedDataSignPayload {
  const { EIP712Domain: _, ...messageTypes } = types;
  const encoder = new TypedDataEncoder(messageTypes);
  const contentsDescr = encoder.encodeType(primaryType);
  const contentsHash = encoder.hashStruct(primaryType, message);
  const appDomainSeparator = TypedDataEncoder.hashDomain(domain);

  const typehash = keccak256(
    toUtf8Bytes(
      `TypedDataSign(${primaryType} contents,string name,string version,uint256 chainId,` +
        `address verifyingContract,bytes32 salt)${contentsDescr}`
    )
  );
  const domainBytes = AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes32", "uint256", "address", "bytes32"],
    [
      keccak256(toUtf8Bytes(W3PK_ACCOUNT_DOMAIN_NAME)),
      keccak256(toUtf8Bytes(W3PK_ACCOUNT_DOMAIN_VERSION)),
      account.chainId,
      account.address,
      ZERO_HASH,
    ]
  );
  const structHash = keccak256(concat([typehash, contentsHash, domainBytes]));

  return {
    hash: typedDataHash(appDomainSeparator, contentsHash),
    challenge: typedDataHash(appDomainSeparator, structHash),
    appDomainSeparator,
    contentsHash,
    contentsDescr,
  };
}

/**
 * ERC-7739 `TypedDataSign` signature:
 * `signature ‖ appDomainSeparator ‖ contentsHash ‖ contentsDescr ‖ uint16(contentsDescr.length)`
 */
export function encodeTypedDataSignature(signature: string, payload: TypedDataSignPayload): string {
  const descr = toUtf8Bytes(payload.contentsDescr);
  return solidityPacked(
    ["bytes", "bytes32", "bytes32", "bytes", "uint16"],
    [signature, payload.appDomainSeparator, payload.contentsHash, descr, descr.length]
  );
}

/**
 * ERC-6492 signature, verifiable before the account is deployed:
 * `abi.encode(factory, factoryCalldata, signature) ‖ magic`
 */
export function wrapErc6492Signature(
  factory: string,
  factoryCalldata: string,
  signature: string
): string {
  return concat([
    AbiCoder.defaultAbiCoder().encode(
      ["address", "bytes", "bytes"],
      [factory, factoryCalldata, signature]
    ),
    ERC6492_MAGIC,
  ]);
}
