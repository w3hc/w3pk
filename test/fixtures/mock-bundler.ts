/**
 * In-process chain RPC, ERC-4337 bundler and ERC-7677 paymaster service, on
 * one local HTTP endpoint, for sendTransaction tests
 *
 * It verifies each UserOperation as the EntryPoint v0.9 would before
 * including it: the userOpHash, the WebAuthn signature against the passkey of
 * test/fixtures/passkey-signer.ts, the nonce, and the factory on first use.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { AbiCoder, Interface, getBytes, keccak256, toBeHex, zeroPadValue } from "ethers";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { QX, QY } from "./passkey-signer";
import {
  ENTRY_POINT_V09,
  P256_PRECOMPILE,
  type UserOperation,
  getUserOperationHash,
} from "../../src/wallet/user-operation";

const coder = AbiCoder.defaultAbiCoder();
const entryPoint = new Interface(["function getNonce(address sender, uint192 key) view returns (uint256)"]);

export const BASE_FEE = 10n ** 9n;
export const PRIORITY_FEE = 10n ** 8n;
export const GAS_ESTIMATE = {
  preVerificationGas: 50_000n,
  verificationGasLimit: 100_000n,
  callGasLimit: 80_000n,
  paymasterVerificationGasLimit: 40_000n,
};
export const PAYMASTER = "0x" + "9a".repeat(20);

export interface MockBundlerOptions {
  chainId?: number;
  /** Whether the chain has the EIP-7951 precompile (default: true) */
  precompile?: boolean;
  /** Polls answered with null before the receipt (default: 1) */
  pendingPolls?: number;
  /** Revert data of the execution, which then fails (default: none) */
  revert?: string;
  /** Never include UserOperations */
  neverInclude?: boolean;
  /** paymasterData the paymaster signs with (default: 0x1234) */
  paymasterData?: string;
  /** Whether pm_getPaymasterStubData answers isFinal */
  isFinal?: boolean;
  /** eth_estimateUserOperationGas answer (default: GAS_ESTIMATE) */
  gasEstimate?: typeof GAS_ESTIMATE;
}

export interface MockBundler {
  url: string;
  chainId: number;
  calls: { method: string; params: any[] }[];
  /** UserOperations included, as sent */
  included: Record<string, string>[];
  deployed: Set<string>;
  nonces: Map<string, bigint>;
  transactions: Map<string, { userOpHash: string; success: boolean }>;
  close(): Promise<void>;
}

class RpcError extends Error {
  constructor(public code: number, message: string) {
    super(message);
  }
}

function fromRpc(op: Record<string, string>): UserOperation {
  const big = (value?: string) => (value === undefined ? undefined : BigInt(value));
  return {
    sender: op.sender,
    nonce: BigInt(op.nonce),
    factory: op.factory,
    factoryData: op.factoryData,
    callData: op.callData,
    callGasLimit: BigInt(op.callGasLimit),
    verificationGasLimit: BigInt(op.verificationGasLimit),
    preVerificationGas: BigInt(op.preVerificationGas),
    maxFeePerGas: BigInt(op.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(op.maxPriorityFeePerGas),
    paymaster: op.paymaster,
    paymasterVerificationGasLimit: big(op.paymasterVerificationGasLimit),
    paymasterPostOpGasLimit: big(op.paymasterPostOpGasLimit),
    paymasterData: op.paymasterData,
    signature: op.signature,
  };
}

/** Whether `signature` is a W3pkAccount WebAuthn assertion over `hash` by the test passkey */
export function verifiesWebAuthn(signature: string, hash: string): boolean {
  const [r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON] = coder.decode(
    ["bytes32", "bytes32", "uint256", "uint256", "bytes", "string"],
    signature
  );
  const challenge = Buffer.from(getBytes(hash)).toString("base64url");
  if (!clientDataJSON.startsWith('"type":"webauthn.get"', Number(typeIndex))) return false;
  if (!clientDataJSON.startsWith(`"challenge":"${challenge}"`, Number(challengeIndex))) return false;
  if ((getBytes(authenticatorData)[32] & 0x05) !== 0x05) return false;
  const message = new Uint8Array([
    ...getBytes(authenticatorData),
    ...sha256(new TextEncoder().encode(clientDataJSON)),
  ]);
  const publicKey = new Uint8Array([4, ...getBytes(QX), ...getBytes(QY)]);
  return p256.verify(new Uint8Array([...getBytes(r), ...getBytes(s)]), message, publicKey, { lowS: true });
}

export async function startMockBundler(options: MockBundlerOptions = {}): Promise<MockBundler> {
  const chainId = options.chainId ?? 1;
  const gasEstimate = options.gasEstimate ?? GAS_ESTIMATE;
  const state = {
    calls: [] as { method: string; params: any[] }[],
    included: [] as Record<string, string>[],
    deployed: new Set<string>(),
    nonces: new Map<string, bigint>(),
    transactions: new Map<string, { userOpHash: string; success: boolean }>(),
    receipts: new Map<string, { txHash: string; polls: number; success: boolean }>(),
  };

  const block = () => ({
    hash: "0x" + "11".repeat(32),
    parentHash: "0x" + "00".repeat(32),
    number: "0x10",
    timestamp: "0x6553f100",
    nonce: "0x0000000000000000",
    difficulty: "0x0",
    gasLimit: "0x1c9c380",
    gasUsed: "0x0",
    miner: "0x" + "00".repeat(20),
    extraData: "0x",
    baseFeePerGas: toBeHex(BASE_FEE),
    transactions: [],
  });

  function checkFactory(op: Record<string, string>) {
    const deployed = state.deployed.has(op.sender.toLowerCase());
    if (deployed && op.factory) throw new RpcError(-32500, "AA10 sender already constructed");
    if (!deployed && !op.factory) throw new RpcError(-32500, "AA20 account not deployed");
  }

  function handle(method: string, params: any[]): unknown {
    state.calls.push({ method, params });
    switch (method) {
      case "eth_chainId":
        return toBeHex(chainId);
      case "eth_getCode":
        return state.deployed.has(params[0].toLowerCase()) ? "0x6080" : "0x";
      case "eth_call": {
        const { to, data } = params[0];
        if (to.toLowerCase() === P256_PRECOMPILE) {
          return options.precompile === false ? "0x" : zeroPadValue("0x01", 32);
        }
        if (to.toLowerCase() === ENTRY_POINT_V09.toLowerCase()) {
          const [sender] = entryPoint.decodeFunctionData("getNonce", data);
          return coder.encode(["uint256"], [state.nonces.get(sender.toLowerCase()) ?? 0n]);
        }
        throw new RpcError(-32000, `unexpected eth_call to ${to}`);
      }
      case "eth_getTransactionCount":
        return "0x0";
      case "eth_estimateGas":
        return "0x5208";
      case "eth_blockNumber":
        return "0x10";
      case "eth_sendRawTransaction": {
        const txHash = keccak256(params[0]);
        state.transactions.set(txHash, { userOpHash: "", success: true });
        return txHash;
      }
      case "eth_getBlockByNumber":
        return block();
      case "eth_gasPrice":
        return toBeHex(BASE_FEE + PRIORITY_FEE);
      case "eth_maxPriorityFeePerGas":
        return toBeHex(PRIORITY_FEE);
      case "eth_getTransactionReceipt": {
        const tx = state.transactions.get(params[0]);
        if (!tx) return null;
        return {
          transactionHash: params[0],
          transactionIndex: "0x0",
          blockHash: "0x" + "22".repeat(32),
          blockNumber: "0x11",
          from: "0x" + "be".repeat(20),
          to: ENTRY_POINT_V09,
          cumulativeGasUsed: "0x30d40",
          gasUsed: "0x30d40",
          effectiveGasPrice: toBeHex(BASE_FEE + PRIORITY_FEE),
          contractAddress: null,
          logs: [],
          logsBloom: "0x" + "00".repeat(256),
          status: "0x1",
          type: "0x2",
        };
      }

      case "eth_supportedEntryPoints":
        return [ENTRY_POINT_V09];
      case "eth_estimateUserOperationGas": {
        const [op, ep] = params;
        if (ep !== ENTRY_POINT_V09) throw new RpcError(-32602, `unsupported EntryPoint ${ep}`);
        checkFactory(op);
        const estimate: Record<string, string> = {
          preVerificationGas: toBeHex(gasEstimate.preVerificationGas),
          verificationGasLimit: toBeHex(gasEstimate.verificationGasLimit),
          callGasLimit: toBeHex(gasEstimate.callGasLimit),
        };
        if (op.paymaster) estimate.paymasterVerificationGasLimit = toBeHex(gasEstimate.paymasterVerificationGasLimit);
        return estimate;
      }
      case "eth_sendUserOperation": {
        const [rpcOp, ep] = params;
        if (ep !== ENTRY_POINT_V09) throw new RpcError(-32602, `unsupported EntryPoint ${ep}`);
        const op = fromRpc(rpcOp);
        const hash = getUserOperationHash(op, chainId);
        if (!verifiesWebAuthn(op.signature, hash)) throw new RpcError(-32507, "AA24 signature error");
        const sender = op.sender.toLowerCase();
        if (op.nonce !== (state.nonces.get(sender) ?? 0n)) throw new RpcError(-32602, "AA25 invalid account nonce");
        checkFactory(rpcOp);
        if (Boolean(rpcOp.factory) !== Boolean(rpcOp.factoryData)) throw new RpcError(-32602, "factory without factoryData");
        if (op.paymaster && op.paymasterData !== (options.paymasterData ?? "0x1234")) {
          throw new RpcError(-32501, "AA34 paymaster signature error");
        }
        if (op.verificationGasLimit < gasEstimate.verificationGasLimit) {
          throw new RpcError(-32602, "verificationGasLimit below the estimate");
        }
        if (options.neverInclude) return hash;
        if (op.factory) state.deployed.add(sender);
        state.nonces.set(sender, op.nonce + 1n);
        state.included.push(rpcOp);
        const txHash = keccak256(hash);
        const success = options.revert === undefined;
        state.transactions.set(txHash, { userOpHash: hash, success });
        state.receipts.set(hash, { txHash, polls: 0, success });
        return hash;
      }
      case "eth_getUserOperationReceipt": {
        const entry = state.receipts.get(params[0]);
        if (!entry || entry.polls++ < (options.pendingPolls ?? 1)) return null;
        return {
          userOpHash: params[0],
          entryPoint: ENTRY_POINT_V09,
          success: entry.success,
          reason: entry.success ? "0x" : options.revert,
          logs: [],
          receipt: { transactionHash: entry.txHash, status: "0x1" },
        };
      }

      case "pm_getPaymasterStubData": {
        const [, ep, chain, context] = params;
        if (ep !== ENTRY_POINT_V09 || BigInt(chain) !== BigInt(chainId)) throw new RpcError(-32602, "bad params");
        if (context?.policy === "deny") throw new RpcError(-32001, "not sponsored");
        return {
          paymaster: PAYMASTER,
          paymasterData: "0x" + "00".repeat(dataLengthOf(options.paymasterData ?? "0x1234")),
          paymasterPostOpGasLimit: toBeHex(20_000n),
          isFinal: options.isFinal ?? false,
        };
      }
      case "pm_getPaymasterData": {
        const [op, ep, chain] = params;
        if (ep !== ENTRY_POINT_V09 || BigInt(chain) !== BigInt(chainId)) throw new RpcError(-32602, "bad params");
        if (!op.paymasterVerificationGasLimit || !op.paymasterPostOpGasLimit) throw new RpcError(-32602, "no gas limits");
        return { paymaster: PAYMASTER, paymasterData: options.paymasterData ?? "0x1234" };
      }
    }
    throw new RpcError(-32601, `method ${method} not found`);
  }

  const answer = (request: any) => {
    try {
      return { jsonrpc: "2.0", id: request.id, result: handle(request.method, request.params ?? []) };
    } catch (error) {
      const code = error instanceof RpcError ? error.code : -32603;
      return { jsonrpc: "2.0", id: request.id, error: { code, message: (error as Error).message } };
    }
  };

  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const payload = JSON.parse(body);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(Array.isArray(payload) ? payload.map(answer) : answer(payload)));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}`,
    chainId,
    calls: state.calls,
    included: state.included,
    deployed: state.deployed,
    nonces: state.nonces,
    transactions: state.transactions,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

const dataLengthOf = (hex: string) => (hex.length - 2) / 2;
