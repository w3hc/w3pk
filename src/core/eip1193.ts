import type { SecurityMode } from "../types";
import { WalletError } from "./errors";
import type { Web3Passkey } from "./sdk";

/** EIP-1193 provider returned by `Web3Passkey.getEIP1193Provider()` */
export interface EIP1193ProviderInterface {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on(event: string, handler: (...args: any[]) => void): void;
  removeListener(event: string, handler: (...args: any[]) => void): void;
}

/** Returns true if a string looks like a 0x-prefixed hex value */
function isHex(value: string): boolean {
  return typeof value === 'string' && /^0x[0-9a-fA-F]*$/.test(value);
}

/** Decode a hex-encoded UTF-8 string (used for personal_sign / eth_sign data) */
function hexToUtf8(hex: string): string {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
  return new TextDecoder().decode(bytes);
}

/** Build the EIP-1193 provider returned by `Web3Passkey.getEIP1193Provider()` */
export function createEIP1193Provider(
  sdk: Pick<Web3Passkey, 'getAddress' | 'sendTransaction' | 'signMessage'>,
  options?: {
    mode?: SecurityMode;
    tag?: string;
    chainId?: number;
    rpcUrl?: string;
  }
): EIP1193ProviderInterface {
  let activeChainId = options?.chainId ?? 1;

  // Minimal EventEmitter (subset needed by EIP-1193)
  const listeners: Record<string, Array<(...args: any[]) => void>> = {};

  const emit = (event: string, ...args: any[]) => {
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
          const chainId = txParam.chainId
            ? parseInt(txParam.chainId, 16)
            : activeChainId;

          const result = await sdk.sendTransaction(
            {
              to: txParam.to,
              value: txParam.value !== undefined
                ? BigInt(txParam.value)
                : undefined,
              data: txParam.data ?? '0x',
              chainId,
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
            },
            {
              mode: options?.mode,
              tag: options?.tag,
              rpcUrl: options?.rpcUrl,
            }
          );
          return result.hash;
        }

        // ── Message signing ────────────────────────────────────────────
        // personal_sign(data, address) — params are reversed vs eth_sign
        case 'personal_sign': {
          const [data] = params ?? [];
          const message = isHex(data)
            ? hexToUtf8(data)
            : data;
          const result = await sdk.signMessage(message, {
            mode: options?.mode,
            tag: options?.tag,
            signingMethod: 'EIP191',
          });
          return result.signature;
        }

        // eth_sign(address, data) — legacy, same signing as personal_sign
        case 'eth_sign': {
          const [, data] = params ?? [];
          const message = isHex(data)
            ? hexToUtf8(data)
            : data;
          const result = await sdk.signMessage(message, {
            mode: options?.mode,
            tag: options?.tag,
            signingMethod: 'EIP191',
          });
          return result.signature;
        }

        // EIP-712 typed data signing
        case 'eth_signTypedData_v4': {
          const [, typedDataJson] = params ?? [];
          const typedData = typeof typedDataJson === 'string'
            ? JSON.parse(typedDataJson)
            : typedDataJson;

          const { domain, types, message: typedMessage, primaryType } = typedData;

          // Remove EIP-712 meta-type if present (ethers doesn't want it)
          const filteredTypes = { ...types };
          delete filteredTypes['EIP712Domain'];

          const result = await sdk.signMessage(
            JSON.stringify(typedMessage),
            {
              mode: options?.mode,
              tag: options?.tag,
              signingMethod: 'EIP712',
              eip712Domain: domain,
              eip712Types: filteredTypes,
              eip712PrimaryType: primaryType,
            }
          );
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
          throw new WalletError(
            `w3pk EIP-1193: unsupported method "${method}"`
          );
      }
    },

    on(event: string, handler: (...args: any[]) => void) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].push(handler);
    },

    removeListener(event: string, handler: (...args: any[]) => void) {
      if (!listeners[event]) return;
      listeners[event] = listeners[event].filter(fn => fn !== handler);
    },
  };

  return provider;
}
