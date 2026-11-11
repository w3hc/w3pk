import { toUtf8String, isHexString, AbiCoder, dataSlice } from "ethers";
import { WalletError } from "../core/errors";
import { ENTRY_POINT_V09, type UserOperation, getRequiredPrefund, toRpcUserOperation } from "./user-operation";

/**
 * Upper bounds on the gas values of a `PRIMARY` mode UserOperation, checked
 * before the passkey signs: gas limits come from the bundler, fees from the
 * chain RPC, and the EntryPoint charges `preVerificationGas` in full
 */
export interface UserOperationCaps {
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  paymasterVerificationGasLimit: bigint;
  paymasterPostOpGasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  /** Wei, against the required prefund (getRequiredPrefund()); unset, only the other caps bound it */
  maxPrefund?: bigint;
}

const GWEI = 10n ** 9n;

/**
 * Chain-agnostic, so set above legitimate values on every chain: gas limits
 * at or above what mainstream bundlers accept (Alto: 16M gas per
 * UserOperation, Rundler: 5M verification gas), `preVerificationGas` above
 * Arbitrum's pre-EIP-4844 L1 data costs (14.6M seen), fees above Polygon's
 * 7,000 gwei peak. No default prefund cap: one in wei can't fit every
 * chain's native token, set it per chain with `userOperationCaps`.
 */
export const DEFAULT_USER_OPERATION_CAPS: UserOperationCaps = {
  callGasLimit: 30_000_000n,
  verificationGasLimit: 5_000_000n,
  preVerificationGas: 50_000_000n,
  paymasterVerificationGasLimit: 5_000_000n,
  paymasterPostOpGasLimit: 5_000_000n,
  maxFeePerGas: 100_000n * GWEI,
  maxPriorityFeePerGas: 100_000n * GWEI,
};

const CAPPED_FIELDS = [
  "callGasLimit",
  "verificationGasLimit",
  "preVerificationGas",
  "paymasterVerificationGasLimit",
  "paymasterPostOpGasLimit",
  "maxFeePerGas",
  "maxPriorityFeePerGas",
] as const;

/**
 * Checks each gas field and the required prefund against `caps`, unset caps
 * falling back to DEFAULT_USER_OPERATION_CAPS
 *
 * @returns The required prefund, in wei
 * @throws WalletError naming the first value above its cap
 */
export function checkUserOperationCaps(op: UserOperation, caps: Partial<UserOperationCaps> = {}): bigint {
  for (const field of CAPPED_FIELDS) {
    const cap = caps[field] ?? DEFAULT_USER_OPERATION_CAPS[field];
    const value = op[field] ?? 0n;
    if (value > cap) {
      throw new WalletError(`UserOperation ${field} ${value} is above its cap of ${cap} (userOperationCaps)`);
    }
  }
  const prefund = getRequiredPrefund(op);
  if (caps.maxPrefund !== undefined && prefund > caps.maxPrefund) {
    throw new WalletError(
      `UserOperation max fee ${prefund} wei is above its cap of ${caps.maxPrefund} wei (userOperationCaps.maxPrefund)`
    );
  }
  return prefund;
}

let requestId = 0;

/** Sends one JSON-RPC request; throws a WalletError carrying the error message and code */
export async function jsonRpc<T>(url: string, method: string, params: unknown[], timeout = 30_000): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++requestId, method, params }),
    signal: AbortSignal.timeout(timeout),
  });
  const body = (await response.json().catch(() => ({}))) as {
    result?: T;
    error?: { code: number; message: string };
  };
  if (body.error) {
    throw new WalletError(`${method} failed: ${body.error.message} (code ${body.error.code})`, body.error);
  }
  if (!response.ok) {
    throw new WalletError(`${method} failed: HTTP ${response.status}`);
  }
  return body.result as T;
}

type RpcOp = Partial<UserOperation> & Pick<UserOperation, "sender">;

export interface GasEstimate {
  preVerificationGas: bigint;
  verificationGasLimit: bigint;
  callGasLimit: bigint;
  paymasterVerificationGasLimit?: bigint;
  paymasterPostOpGasLimit?: bigint;
}

const optionalBigInt = (value: string | undefined) => (value == null ? undefined : BigInt(value));

export async function estimateUserOperationGas(
  bundlerUrl: string,
  op: RpcOp,
  entryPoint: string = ENTRY_POINT_V09
): Promise<GasEstimate> {
  const result = await jsonRpc<Record<string, string>>(bundlerUrl, "eth_estimateUserOperationGas", [
    toRpcUserOperation(op),
    entryPoint,
  ]);
  return {
    preVerificationGas: BigInt(result.preVerificationGas),
    verificationGasLimit: BigInt(result.verificationGasLimit),
    callGasLimit: BigInt(result.callGasLimit),
    paymasterVerificationGasLimit: optionalBigInt(result.paymasterVerificationGasLimit),
    paymasterPostOpGasLimit: optionalBigInt(result.paymasterPostOpGasLimit),
  };
}

/** Sends the UserOperation and returns its `userOpHash` */
export async function sendUserOperation(
  bundlerUrl: string,
  op: UserOperation,
  entryPoint: string = ENTRY_POINT_V09
): Promise<string> {
  return jsonRpc<string>(bundlerUrl, "eth_sendUserOperation", [toRpcUserOperation(op), entryPoint]);
}

export interface UserOperationReceipt {
  userOpHash: string;
  success: boolean;
  reason?: string;
  receipt: { transactionHash: string };
}

/** Readable revert reason: `Error(string)` decoded, any other data as hex */
function revertReason(reason: string | undefined): string {
  if (!reason || reason === "0x") return "no revert reason";
  if (isHexString(reason) && reason.startsWith("0x08c379a0")) {
    try {
      return AbiCoder.defaultAbiCoder().decode(["string"], dataSlice(reason, 4))[0];
    } catch {
      return reason;
    }
  }
  if (!isHexString(reason)) return reason;
  try {
    const text = toUtf8String(reason);
    return /^[\x20-\x7e]+$/.test(text) ? text : reason;
  } catch {
    return reason;
  }
}

/**
 * Polls `eth_getUserOperationReceipt` until the UserOperation is included,
 * retrying failed polls until the timeout
 *
 * @throws WalletError on timeout, or if the UserOperation reverted (with its revert reason)
 */
export async function waitForUserOperationReceipt(
  bundlerUrl: string,
  userOpHash: string,
  { timeout = 60_000, interval = 1_000 }: { timeout?: number; interval?: number } = {}
): Promise<UserOperationReceipt> {
  const deadline = Date.now() + timeout;
  let lastError: unknown;
  for (;;) {
    let receipt: UserOperationReceipt | null = null;
    try {
      receipt = await jsonRpc<UserOperationReceipt | null>(
        bundlerUrl,
        "eth_getUserOperationReceipt",
        [userOpHash],
        Math.max(deadline - Date.now(), 1)
      );
      lastError = undefined;
    } catch (error) {
      lastError = error;
    }
    if (receipt) {
      if (!receipt.success) {
        throw new WalletError(
          `UserOperation ${userOpHash} reverted in transaction ${receipt.receipt.transactionHash}: ${revertReason(receipt.reason)}`
        );
      }
      return receipt;
    }
    if (Date.now() + interval > deadline) {
      const cause = lastError instanceof Error ? ` (last poll: ${lastError.message})` : "";
      throw new WalletError(`UserOperation ${userOpHash} not included after ${timeout} ms${cause}`, lastError);
    }
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
}

export interface PaymasterStubData {
  paymaster?: string;
  paymasterData?: string;
  paymasterVerificationGasLimit?: bigint;
  paymasterPostOpGasLimit?: bigint;
  isFinal?: boolean;
}

/** ERC-7677 `pm_getPaymasterStubData`, for gas estimation */
export async function getPaymasterStubData(
  paymasterUrl: string,
  op: RpcOp,
  chainId: number,
  context: Record<string, unknown> = {},
  entryPoint: string = ENTRY_POINT_V09
): Promise<PaymasterStubData> {
  const result = await jsonRpc<Record<string, any>>(paymasterUrl, "pm_getPaymasterStubData", [
    toRpcUserOperation(op),
    entryPoint,
    `0x${chainId.toString(16)}`,
    context,
  ]);
  return {
    paymaster: result.paymaster,
    paymasterData: result.paymasterData,
    paymasterVerificationGasLimit: optionalBigInt(result.paymasterVerificationGasLimit),
    paymasterPostOpGasLimit: optionalBigInt(result.paymasterPostOpGasLimit),
    isFinal: result.isFinal,
  };
}

/** ERC-7677 `pm_getPaymasterData`, for the UserOperation that is sent */
export async function getPaymasterData(
  paymasterUrl: string,
  op: RpcOp,
  chainId: number,
  context: Record<string, unknown> = {},
  entryPoint: string = ENTRY_POINT_V09
): Promise<{ paymaster?: string; paymasterData?: string }> {
  const result = await jsonRpc<Record<string, string>>(paymasterUrl, "pm_getPaymasterData", [
    toRpcUserOperation(op),
    entryPoint,
    `0x${chainId.toString(16)}`,
    context,
  ]);
  return { paymaster: result.paymaster, paymasterData: result.paymasterData };
}
