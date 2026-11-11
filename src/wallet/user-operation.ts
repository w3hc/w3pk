import {
  AbiCoder,
  Interface,
  TypedDataEncoder,
  concat,
  dataLength,
  dataSlice,
  keccak256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue,
  type Provider,
} from "ethers";

/** ERC-4337 EntryPoint v0.9, at the same address on every chain */
export const ENTRY_POINT_V09 = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";

/** `keccak256("PaymasterSignature")[:8]`: ends a `paymasterData` that carries a paymaster signature */
export const PAYMASTER_SIG_MAGIC = "0x22e325a297439656";

const PACKED_USEROP_TYPEHASH = keccak256(
  toUtf8Bytes(
    "PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)"
  )
);

/** EntryPoint v0.9 UserOperation, unpacked as in the ERC-7769 JSON-RPC API */
export interface UserOperation {
  sender: string;
  nonce: bigint;
  factory?: string;
  factoryData?: string;
  callData: string;
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  paymaster?: string;
  paymasterVerificationGasLimit?: bigint;
  paymasterPostOpGasLimit?: bigint;
  paymasterData?: string;
  signature: string;
}

/** A call made by the account */
export interface Call {
  to: string;
  value?: bigint;
  data?: string;
}

const pack128 = (high: bigint, low: bigint) =>
  concat([zeroPadValue(toBeHex(high), 16), zeroPadValue(toBeHex(low), 16)]);

export function getInitCode(op: UserOperation): string {
  return op.factory ? concat([op.factory, op.factoryData ?? "0x"]) : "0x";
}

export function getPaymasterAndData(op: UserOperation): string {
  if (!op.paymaster) return "0x";
  return concat([
    op.paymaster,
    zeroPadValue(toBeHex(op.paymasterVerificationGasLimit ?? 0n), 16),
    zeroPadValue(toBeHex(op.paymasterPostOpGasLimit ?? 0n), 16),
    op.paymasterData ?? "0x",
  ]);
}

/**
 * keccak256 of `paymasterAndData` as EntryPoint v0.9 hashes it: a trailing
 * paymaster signature (`signature || uint16(length) || PAYMASTER_SIG_MAGIC`)
 * is left out, the magic is kept
 */
export function paymasterAndDataHash(paymasterAndData: string): string {
  const length = dataLength(paymasterAndData);
  if (length >= 62 && dataSlice(paymasterAndData, length - 8) === PAYMASTER_SIG_MAGIC) {
    const signatureLength = Number(BigInt(dataSlice(paymasterAndData, length - 10, length - 8)));
    if (signatureLength > length - 62) {
      throw new Error("Invalid paymaster signature length");
    }
    if (signatureLength > 0) {
      return keccak256(
        concat([dataSlice(paymasterAndData, 0, length - 10 - signatureLength), PAYMASTER_SIG_MAGIC])
      );
    }
  }
  return keccak256(paymasterAndData);
}

/**
 * Hash the account signs, as `EntryPoint.getUserOpHash` computes it in v0.9:
 * the EIP-712 hash of the packed UserOperation, domain `ERC4337` version `1`
 */
export function getUserOperationHash(
  op: UserOperation,
  chainId: number,
  entryPoint: string = ENTRY_POINT_V09
): string {
  const structHash = keccak256(
    AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32", "bytes32"],
      [
        PACKED_USEROP_TYPEHASH,
        op.sender,
        op.nonce,
        keccak256(getInitCode(op)),
        keccak256(op.callData),
        pack128(op.verificationGasLimit, op.callGasLimit),
        op.preVerificationGas,
        pack128(op.maxPriorityFeePerGas, op.maxFeePerGas),
        paymasterAndDataHash(getPaymasterAndData(op)),
      ]
    )
  );
  const domainSeparator = TypedDataEncoder.hashDomain({
    name: "ERC4337",
    version: "1",
    chainId,
    verifyingContract: entryPoint,
  });
  return keccak256(concat(["0x1901", domainSeparator, structHash]));
}

/**
 * Required prefund, as EntryPoint v0.9 computes it: the sum of the gas
 * limits times `maxFeePerGas`, the most the UserOperation can cost in wei
 */
export function getRequiredPrefund(op: UserOperation): bigint {
  return (
    (op.verificationGasLimit +
      op.callGasLimit +
      (op.paymasterVerificationGasLimit ?? 0n) +
      (op.paymasterPostOpGasLimit ?? 0n) +
      op.preVerificationGas) *
    op.maxFeePerGas
  );
}

const ACCOUNT_INTERFACE = new Interface([
  "function execute(bytes32 mode, bytes executionCalldata)",
]);

const MODE_SINGLE = zeroPadValue("0x", 32);
const MODE_BATCH = concat(["0x01", zeroPadValue("0x", 31)]);

/**
 * ERC-7579 `execute(mode, executionCalldata)` calldata: single call mode for
 * one call, batch mode (all or nothing) for several
 */
export function encodeExecute(calls: Call[]): string {
  if (calls.length === 0) {
    throw new Error("No call to execute");
  }
  if (calls.length === 1) {
    const [{ to, value, data }] = calls;
    return ACCOUNT_INTERFACE.encodeFunctionData("execute", [
      MODE_SINGLE,
      concat([to, zeroPadValue(toBeHex(value ?? 0n), 32), data ?? "0x"]),
    ]);
  }
  return ACCOUNT_INTERFACE.encodeFunctionData("execute", [
    MODE_BATCH,
    AbiCoder.defaultAbiCoder().encode(
      ["tuple(address,uint256,bytes)[]"],
      [calls.map(({ to, value, data }) => [to, value ?? 0n, data ?? "0x"])]
    ),
  ]);
}

/** UserOperation as the ERC-7769 JSON-RPC API takes it: hex quantities, optional fields left out */
export function toRpcUserOperation(op: Partial<UserOperation> & Pick<UserOperation, "sender">): Record<string, string> {
  const rpc: Record<string, string> = {};
  for (const [key, value] of Object.entries(op)) {
    if (value === undefined) continue;
    rpc[key] = typeof value === "bigint" ? `0x${value.toString(16)}` : (value as string);
  }
  return rpc;
}

const ENTRY_POINT_INTERFACE = new Interface([
  "function getNonce(address sender, uint192 key) view returns (uint256)",
]);

/** The account's EntryPoint nonce for key 0 */
export async function getEntryPointNonce(
  provider: Pick<Provider, "call">,
  sender: string,
  entryPoint: string = ENTRY_POINT_V09
): Promise<bigint> {
  const result = await provider.call({
    to: entryPoint,
    data: ENTRY_POINT_INTERFACE.encodeFunctionData("getNonce", [sender, 0]),
  });
  return ENTRY_POINT_INTERFACE.decodeFunctionResult("getNonce", result)[0];
}

/** EIP-7951 P-256 verification precompile */
export const P256_PRECOMPILE = "0x0000000000000000000000000000000000000100";

/** A valid P-256 signature: `keccak256("w3pk")`, r, s, then the public key of scalar `0xa11ce` */
const P256_TEST_VECTOR =
  "0x915ea4cea6bd44c09d8518eb665c3e6e2dbb999fb7363337731046a1db01d409" +
  "bcf307498abe6eb279d76d95b43b3de96b0315c73628e7ed05c0847c964cd703" +
  "4574fd9b08d887eadcb0f2c5a6c8478019eae591c8f8ba0835d97c74db5e76d9" +
  "7268876e19db7d7a651d55d5f3cd08b0f14f0f2d99ac383d56e705cc58b2de09" +
  "272f3460d10844d9d8a77c0f6f5754c8e1c7fa3a58c6671f9199d8710af43878";

/** Gas added to the bundler's `verificationGasLimit` for the P-256 verification, with the precompile */
export const P256_PRECOMPILE_GAS = 15_000n;
/** The same, with OpenZeppelin's Solidity verifier (about 250,000 gas measured) */
export const P256_SOLIDITY_GAS = 300_000n;

/** Whether the chain has the EIP-7951 precompile, which returns 1 for a valid signature */
export async function hasP256Precompile(provider: Pick<Provider, "call">): Promise<boolean> {
  try {
    const result = await provider.call({ to: P256_PRECOMPILE, data: P256_TEST_VECTOR });
    return result !== "0x" && BigInt(result) === 1n;
  } catch {
    return false;
  }
}
