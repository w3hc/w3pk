/**
 * Chainlist types
 */

export interface Chain {
  name: string;
  chain: string;
  icon?: string;
  rpc: string[];
  features?: Array<{ name: string }>;
  faucets: string[];
  nativeCurrency: {
    name: string;
    symbol: string;
    decimals: number;
  };
  infoURL: string;
  shortName: string;
  chainId: number;
  networkId: number;
  slip44?: number;
  ens?: {
    registry: string;
  };
  explorers?: Array<{
    name: string;
    url: string;
    icon?: string;
    standard: string;
  }>;
  title?: string;
  status?: string;
  redFlags?: string[];
}

export interface ChainlistOptions {
  /**
   * Custom URL for chains.json data
   * @default 'https://chainid.network/chains.json'
   */
  chainsJsonUrl?: string;

  /**
   * Cache duration in milliseconds
   * @default 3600000 (1 hour)
   */
  cacheDuration?: number;
}
