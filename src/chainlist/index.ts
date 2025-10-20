/**
 * Chainlist module for fetching RPC endpoints
 */

import type { Chain, ChainlistOptions } from "./types";

const DEFAULT_CHAINS_URL = "https://chainid.network/chains.json";
const DEFAULT_CACHE_DURATION = 3600000; // 1 hour

interface CacheEntry {
  data: Chain[];
  timestamp: number;
}

let cache: CacheEntry | null = null;

/**
 * Patterns that indicate an RPC URL requires an API key
 */
const API_KEY_PATTERNS = [
  /\$\{[\w_]+\}/i, // ${INFURA_API_KEY}, ${API_KEY}, etc.
  /\{[\w_]+\}/i, // {API_KEY}, {INFURA_API_KEY}, etc.
  /<[\w_]+>/i, // <API_KEY>, <INFURA_API_KEY>, etc.
  /YOUR[-_]?API[-_]?KEY/i,
  /INSERT[-_]?API[-_]?KEY/i,
  /API[-_]?KEY[-_]?HERE/i,
];

/**
 * Check if an RPC URL requires an API key
 */
function requiresApiKey(rpcUrl: string): boolean {
  return API_KEY_PATTERNS.some((pattern) => pattern.test(rpcUrl));
}

/**
 * Fetch all chains data from chainid.network
 */
async function fetchChains(
  chainsJsonUrl: string = DEFAULT_CHAINS_URL
): Promise<Chain[]> {
  const response = await fetch(chainsJsonUrl);

  if (!response.ok) {
    throw new Error(
      `Failed to fetch chains data: ${response.status} ${response.statusText}`
    );
  }

  return await response.json();
}

/**
 * Get all chains data with caching
 */
async function getChainsData(options?: ChainlistOptions): Promise<Chain[]> {
  const chainsJsonUrl = options?.chainsJsonUrl ?? DEFAULT_CHAINS_URL;
  const cacheDuration = options?.cacheDuration ?? DEFAULT_CACHE_DURATION;
  const now = Date.now();

  // Check if cache is valid
  if (cache && now - cache.timestamp < cacheDuration) {
    return cache.data;
  }

  // Fetch fresh data
  const data = await fetchChains(chainsJsonUrl);
  cache = { data, timestamp: now };

  return data;
}

/**
 * Get RPC endpoints for a specific chain ID, excluding those that require API keys
 *
 * @param chainId - The chain ID to get endpoints for
 * @param options - Optional configuration
 * @returns Array of RPC URLs that don't require API keys
 *
 * @example
 * ```typescript
 * import { getEndpoints } from 'w3pk/chainlist'
 *
 * // Get Ethereum mainnet RPCs
 * const endpoints = await getEndpoints(1)
 * console.log(endpoints)
 * // [
 * //   "https://api.mycryptoapi.com/eth",
 * //   "https://cloudflare-eth.com",
 * //   "https://ethereum-rpc.publicnode.com",
 * //   ...
 * // ]
 * ```
 */
export async function getEndpoints(
  chainId: number,
  options?: ChainlistOptions
): Promise<string[]> {
  const chains = await getChainsData(options);
  const chain = chains.find((c) => c.chainId === chainId);

  if (!chain) {
    return [];
  }

  // Filter out RPC URLs that require API keys and websocket URLs
  return chain.rpc.filter(
    (rpcUrl) =>
      !requiresApiKey(rpcUrl) &&
      !rpcUrl.startsWith("wss://") &&
      !rpcUrl.startsWith("ws://")
  );
}

/**
 * Get all available chains
 *
 * @param options - Optional configuration
 * @returns Array of all chains
 */
export async function getAllChains(
  options?: ChainlistOptions
): Promise<Chain[]> {
  return getChainsData(options);
}

/**
 * Get chain information by chain ID
 *
 * @param chainId - The chain ID to get information for
 * @param options - Optional configuration
 * @returns Chain information or undefined if not found
 */
export async function getChainById(
  chainId: number,
  options?: ChainlistOptions
): Promise<Chain | undefined> {
  const chains = await getChainsData(options);
  return chains.find((c) => c.chainId === chainId);
}

/**
 * Clear the chains data cache
 */
export function clearCache(): void {
  cache = null;
}

// Export types
export type { Chain, ChainlistOptions } from "./types";
