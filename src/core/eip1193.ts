import type { SecurityMode } from "../types";
import { WalletError } from "./errors";
import {
  erc191Message,
  getSigningDigests,
  signableTypedData,
  type SigningDigests,
  type SigningRequest,
} from "./signing-digests";
import type { Web3Passkey } from "./sdk";

/** Payload of the EIP-1193 `connect` event */
export interface ProviderConnectInfo {
  readonly chainId: string;
}

/** Error passed to EIP-1193 `disconnect` listeners */
export interface ProviderRpcError extends Error {
  code: number;
  data?: unknown;
}

/** Payload of the EIP-1193 `message` event */
export interface ProviderMessage {
  readonly type: string;
  readonly data: unknown;
}

type EIP1193Events = {
  accountsChanged: (accounts: string[]) => void;
  chainChanged: (chainId: string) => void;
  connect: (info: ProviderConnectInfo) => void;
  disconnect: (error: ProviderRpcError) => void;
  message: (message: ProviderMessage) => void;
};

type EIP1193Event = keyof EIP1193Events;

type Listener = (...args: unknown[]) => void;

/** EIP-1193 provider returned by `Web3Passkey.getEIP1193Provider()` */
export interface EIP1193ProviderInterface {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on(event: 'accountsChanged', handler: (accounts: string[]) => void): void;
  on(event: 'chainChanged', handler: (chainId: string) => void): void;
  on(event: 'connect', handler: (info: ProviderConnectInfo) => void): void;
  on(event: 'disconnect', handler: (error: ProviderRpcError) => void): void;
  on(event: 'message', handler: (message: ProviderMessage) => void): void;
  removeListener(event: 'accountsChanged', handler: (accounts: string[]) => void): void;
  removeListener(event: 'chainChanged', handler: (chainId: string) => void): void;
  removeListener(event: 'connect', handler: (info: ProviderConnectInfo) => void): void;
  removeListener(event: 'disconnect', handler: (error: ProviderRpcError) => void): void;
  removeListener(event: 'message', handler: (message: ProviderMessage) => void): void;
}

type SigningMethod = SigningRequest["method"];

/** What a transaction's digests carry besides them */
interface TransactionCost {
  /**
   * PRIMARY mode: the UserOperation's required prefund in wei, the most it can cost, whoever
   * pays (the account or a paymaster); the same for each transaction of an array
   */
  maxFee?: bigint;
}

/** ERC-8213 digests of a signing request, with its method: narrow on `method` */
export type BeforeSignDigests = {
  [M in SigningMethod]: { method: M } & SigningDigests<Extract<SigningRequest, { method: M }>> &
    (M extends "eth_sendTransaction" ? TransactionCost : {});
}[SigningMethod];

/** ERC-8213 digests of a transaction, with its method */
export type TransactionBeforeSignDigests = Extract<BeforeSignDigests, { method: "eth_sendTransaction" }>;

/** Awaited with a request's digests before its passkey prompt; throw, reject or return `false` to cancel it */
export type BeforeSignHook<D> = (digests: D) => boolean | void | Promise<boolean | void>;

/** Options of `Web3Passkey.getEIP1193Provider()` */
export interface EIP1193ProviderOptions {
  mode?: SecurityMode;
  tag?: string;
  chainId?: number;
  rpcUrl?: string;
  bundlerUrl?: string;
  /** Awaited before each signing request's passkey prompt; throw, reject or return `false` to cancel it with error 4001 */
  onBeforeSign?: BeforeSignHook<BeforeSignDigests>;
}

/** EIP-1193 error 4001: onBeforeSign cancelled the request, its error as `cause` */
export class UserRejectedRequestError extends Error implements ProviderRpcError {
  code = 4001;

  constructor(public cause?: unknown) {
    super("w3pk: onBeforeSign rejected the request");
    this.name = "UserRejectedRequestError";
  }
}

/** Awaits `hook` with `digests`; throws UserRejectedRequestError if it throws, rejects or returns `false` */
export async function confirmBeforeSign<D>(hook: BeforeSignHook<D>, digests: D): Promise<void> {
  let approved;
  try {
    approved = await hook(digests);
  } catch (error) {
    throw new UserRejectedRequestError(error);
  }
  if (approved === false) throw new UserRejectedRequestError();
}

/** EIP-1193 error 4200: the provider does not support the method */
class UnsupportedMethodError extends Error implements ProviderRpcError {
  code = 4200;

  constructor(message: string) {
    super(message);
    this.name = "UnsupportedMethodError";
  }
}

/** A JSON-RPC error from the chain's endpoint, with its code and data unchanged */
class JsonRpcError extends Error implements ProviderRpcError {
  constructor(public code: number, message: string, public data?: unknown) {
    super(message);
    this.name = "JsonRpcError";
  }
}

/** Read-only methods forwarded to the active chain's RPC endpoint */
const READ_METHODS = new Set([
  'eth_blockNumber',
  'eth_call',
  'eth_estimateGas',
  'eth_getBalance',
  'eth_getCode',
  'eth_getStorageAt',
  'eth_getTransactionCount',
  'eth_getTransactionByHash',
  'eth_getTransactionReceipt',
  'eth_getBlockByNumber',
  'eth_getBlockByHash',
  'eth_getLogs',
  'eth_gasPrice',
  'eth_maxPriorityFeePerGas',
  'eth_feeHistory',
  'net_version',
]);

let requestId = 0;

async function forward(url: string, method: string, params: unknown[] | undefined): Promise<unknown> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++requestId, method, params: params ?? [] }),
  });
  const body = await response.json().catch(() => undefined);
  if (body?.error) {
    const { code, message, data } = body.error;
    throw new JsonRpcError(code, message, data);
  }
  if (!response.ok || !body || !('result' in body)) {
    throw new WalletError(`w3pk EIP-1193: ${method} failed: HTTP ${response.status} from ${url}`);
  }
  return body.result;
}

function parseChainId(value: unknown): bigint {
  try {
    return BigInt(value as string | number | bigint);
  } catch {
    throw new WalletError(`Invalid chainId: ${String(value)}`);
  }
}

/** Build the EIP-1193 provider returned by `Web3Passkey.getEIP1193Provider()` */
export function createEIP1193Provider(
  sdk: Pick<Web3Passkey, 'getAddress' | 'sendTransaction' | 'signMessage'>,
  options?: EIP1193ProviderOptions,
  rpcUrlFor?: (chainId: number) => string | undefined
): EIP1193ProviderInterface {
  let activeChainId = options?.chainId ?? 1;
  const initialChainId = activeChainId;
  const isPrimary = options?.mode === 'PRIMARY';
  // options.rpcUrl and bundlerUrl serve the initial chain only; other chains use the config's
  const endpoints = () =>
    activeChainId !== initialChainId
      ? {}
      : { rpcUrl: options?.rpcUrl, bundlerUrl: options?.bundlerUrl };
  const rpcUrl = () => {
    const url = endpoints().rpcUrl ?? rpcUrlFor?.(activeChainId);
    if (!url) {
      throw new WalletError(
        `No RPC endpoint set for chainId ${activeChainId}. Set rpcUrls in the config ` +
        `(rpcUrls: { ${activeChainId}: ['https://...'] })` +
        (activeChainId === initialChainId ? ' or pass options.rpcUrl.' : '.')
      );
    }
    return url;
  };
  const primarySigning = () => (isPrimary ? { chainId: activeChainId, rpcUrl: endpoints().rpcUrl } : {});
  const beforeSign = async (request: SigningRequest) => {
    if (!options?.onBeforeSign) return;
    const digests = { method: request.method, ...getSigningDigests(request) } as BeforeSignDigests;
    await confirmBeforeSign(options.onBeforeSign, digests);
  };

  // Minimal EventEmitter (subset needed by EIP-1193)
  const listeners: Partial<Record<EIP1193Event, Listener[]>> = {};

  const emit = <E extends EIP1193Event>(event: E, ...args: Parameters<EIP1193Events[E]>) => {
    (listeners[event] ?? []).forEach(fn => fn(...args));
  };

  const provider: EIP1193ProviderInterface = {
    async request({ method, params: rawParams }: { method: string; params?: unknown[] }): Promise<unknown> {
      const params = rawParams as any[] | undefined;
      switch (method) {
        // ── Account discovery ──────────────────────────────────────────
        case 'eth_accounts':
        case 'eth_requestAccounts': {
          const address = await sdk.getAddress(
            options?.mode ?? 'STANDARD',
            options?.tag ?? 'MAIN'
          );
          return [address];
        }

        // ── Chain ──────────────────────────────────────────────────────
        case 'eth_chainId': {
          return '0x' + activeChainId.toString(16);
        }

        // ── Transaction ────────────────────────────────────────────────
        case 'eth_sendTransaction': {
          const txParam = (params ?? [])[0] ?? {};
          if (!txParam.chainId && !activeChainId) {
            throw new WalletError('eth_sendTransaction: chainId is required');
          }
          if (txParam.chainId != null && parseChainId(txParam.chainId) !== BigInt(activeChainId)) {
            throw new WalletError(
              `eth_sendTransaction: chainId ${txParam.chainId} does not match the active chain ${activeChainId}`
            );
          }
          const tx = {
            to: txParam.to,
            value: txParam.value !== undefined
              ? BigInt(txParam.value)
              : undefined,
            data: txParam.data ?? '0x',
            chainId: activeChainId,
            gasLimit: txParam.gas !== undefined
              ? BigInt(txParam.gas)
              : undefined,
            maxFeePerGas: txParam.maxFeePerGas !== undefined
              ? BigInt(txParam.maxFeePerGas)
              : undefined,
            maxPriorityFeePerGas: txParam.maxPriorityFeePerGas !== undefined
              ? BigInt(txParam.maxPriorityFeePerGas)
              : undefined,
            nonce: txParam.nonce !== undefined
              ? parseInt(txParam.nonce, 16)
              : undefined,
          };
          const sendOptions = {
            mode: options?.mode,
            tag: options?.tag,
            ...endpoints(),
          };
          await beforeSign({ method: 'eth_sendTransaction', params: [txParam] });

          const result = await sdk.sendTransaction(tx, sendOptions);
          return result.hash;
        }

        // ── Message signing ────────────────────────────────────────────
        // personal_sign(data, address) — params are reversed vs eth_sign
        case 'personal_sign': {
          const [data] = params ?? [];
          const signOptions = {
            mode: options?.mode,
            tag: options?.tag,
            signingMethod: 'EIP191' as const,
            ...primarySigning(),
          };
          await beforeSign({ method: 'personal_sign', params: [data] });
          const result = await sdk.signMessage(erc191Message(data), signOptions);
          return result.signature;
        }

        // eth_sign(address, data) — legacy, same signing as personal_sign
        case 'eth_sign': {
          // Through EIP-1271, a bare hash would skip ERC-7739's replay protection
          if (isPrimary) {
            throw new UnsupportedMethodError(
              'w3pk EIP-1193: eth_sign is not supported in PRIMARY mode. Use personal_sign or eth_signTypedData_v4.'
            );
          }
          const [address, data] = params ?? [];
          await beforeSign({ method: 'eth_sign', params: [address, data] });
          const result = await sdk.signMessage(erc191Message(data), {
            mode: options?.mode,
            tag: options?.tag,
            signingMethod: 'EIP191',
          });
          return result.signature;
        }

        // EIP-712 typed data signing
        case 'eth_signTypedData_v4': {
          const [address, request] = params ?? [];
          const typedData = signableTypedData(request);
          const { domain, types, primaryType, message } = typedData;

          if (domain?.chainId != null && parseChainId(domain.chainId) !== BigInt(activeChainId)) {
            throw new WalletError(
              `eth_signTypedData_v4: domain chainId ${domain.chainId} does not match the active chain ${activeChainId}`
            );
          }

          const signOptions = {
            mode: options?.mode,
            tag: options?.tag,
            signingMethod: 'EIP712' as const,
            eip712Domain: domain,
            eip712Types: types,
            eip712PrimaryType: primaryType,
            ...primarySigning(),
          };
          const signedMessage = JSON.stringify(message);
          await beforeSign({ method: 'eth_signTypedData_v4', params: [address, typedData] });

          const result = await sdk.signMessage(signedMessage, signOptions);
          return result.signature;
        }

        // ── Chain switching ────────────────────────────────────────────
        case 'wallet_switchEthereumChain': {
          const newChainId = parseInt((params ?? [])[0]?.chainId ?? '0x1', 16);
          activeChainId = newChainId;
          emit('chainChanged', '0x' + newChainId.toString(16));
          return null;
        }

        default:
          if (READ_METHODS.has(method)) {
            return forward(rpcUrl(), method, params);
          }
          throw new UnsupportedMethodError(
            `w3pk EIP-1193: unsupported method "${method}"`
          );
      }
    },

    on(event: EIP1193Event, handler: EIP1193Events[EIP1193Event]) {
      (listeners[event] ??= []).push(handler as Listener);
    },

    removeListener(event: EIP1193Event, handler: EIP1193Events[EIP1193Event]) {
      if (!listeners[event]) return;
      listeners[event] = listeners[event].filter(fn => fn !== handler);
    },
  };

  return provider;
}
