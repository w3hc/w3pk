import { toUtf8String, isHexString, AbiCoder, dataSlice } from "ethers";
import { WalletError } from "../core/errors";
import { ENTRY_POINT_V09, type UserOperation, toRpcUserOperation } from "./user-operation";

let requestId = 0;

/** Sends one JSON-RPC request; throws a WalletError carrying the error message and code */
export async function jsonRpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++requestId, method, params }),
  });
  if (!response.ok) {
    throw new WalletError(`${method} failed: HTTP ${response.status}`);
  }
  const body = (await response.json()) as { result?: T; error?: { code: number; message: string } };
  if (body.error) {
    throw new WalletError(`${method} failed: ${body.error.message} (code ${body.error.code})`, body.error);
  }
  return body.result as T;
}

type RpcOp = Partial<UserOperation> & Pick<UserOperation, "sender">;

export interface GasEstimate {
  preVerificationGas: bigint;
  verificationGasLimit: bigint;
  callGasLimit: bigint;
  paymasterVerificationGasLimit?: bigint;
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
 * Polls `eth_getUserOperationReceipt` until the UserOperation is included
 *
 * @throws WalletError on timeout, or if the UserOperation reverted (with its revert reason)
 */
export async function waitForUserOperationReceipt(
  bundlerUrl: string,
  userOpHash: string,
  { timeout = 60_000, interval = 1_000 }: { timeout?: number; interval?: number } = {}
): Promise<UserOperationReceipt> {
  const deadline = Date.now() + timeout;
  for (;;) {
    const receipt = await jsonRpc<UserOperationReceipt | null>(bundlerUrl, "eth_getUserOperationReceipt", [
      userOpHash,
    ]);
    if (receipt) {
      if (!receipt.success) {
        throw new WalletError(
          `UserOperation ${userOpHash} reverted in transaction ${receipt.receipt.transactionHash}: ${revertReason(receipt.reason)}`
        );
      }
      return receipt;
    }
    if (Date.now() + interval > deadline) {
      throw new WalletError(`UserOperation ${userOpHash} not included after ${timeout} ms`);
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
