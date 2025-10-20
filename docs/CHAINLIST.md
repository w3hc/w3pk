# Chainlist Support

The chainlist module provides easy access to RPC endpoints for thousands of blockchain networks using data from [chainid.network](https://chainid.network).

## Features

- Fetch RPC endpoints for any blockchain by chain ID
- Automatically filters out endpoints that require API keys
- Excludes websocket URLs (returns only HTTP/HTTPS endpoints)
- Built-in caching for improved performance (1-hour default)
- Access to full chain metadata including native currency, explorers, and more
- Support for 2390+ blockchain networks

## Installation

The chainlist module is included in w3pk. Simply import it:

```typescript
import { getEndpoints } from 'w3pk/chainlist'
```

## Usage

### Get RPC Endpoints

Fetch all public RPC endpoints for a specific chain:

```typescript
import { getEndpoints } from 'w3pk/chainlist'

// Get Ethereum mainnet endpoints
const ethEndpoints = await getEndpoints(1)
console.log(ethEndpoints)
// [
//   "https://api.mycryptoapi.com/eth",
//   "https://cloudflare-eth.com",
//   "https://ethereum-rpc.publicnode.com",
//   ...
// ]

// Get Polygon endpoints
const polygonEndpoints = await getEndpoints(137)

// Get Optimism endpoints
const optimismEndpoints = await getEndpoints(10)
```

### Get Chain Information

Fetch detailed information about a specific chain:

```typescript
import { getChainById } from 'w3pk/chainlist'

const chain = await getChainById(1)
console.log(chain)
// {
//   name: "Ethereum Mainnet",
//   chainId: 1,
//   nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
//   rpc: [...],
//   explorers: [...],
//   ...
// }
```

### Get All Chains

Fetch information about all available chains:

```typescript
import { getAllChains } from 'w3pk/chainlist'

const chains = await getAllChains()
console.log(`Total chains: ${chains.length}`)

// Find chains by name
const ethereumChains = chains.filter(c =>
  c.name.toLowerCase().includes('ethereum')
)
```

### Caching

The module automatically caches chain data for 1 hour to improve performance. You can customize the cache duration or clear the cache:

```typescript
import { getEndpoints, clearCache } from 'w3pk/chainlist'

// Custom cache duration (5 minutes)
const endpoints = await getEndpoints(1, {
  cacheDuration: 300000 // 5 minutes in milliseconds
})

// Clear the cache manually
clearCache()
```

### Custom Data Source

You can use a custom chains.json URL if needed:

```typescript
import { getEndpoints } from 'w3pk/chainlist'

const endpoints = await getEndpoints(1, {
  chainsJsonUrl: 'https://your-custom-url.com/chains.json'
})
```

## API Reference

### `getEndpoints(chainId, options?)`

Get RPC endpoints for a specific chain ID, excluding those that require API keys.

**Parameters:**
- `chainId` (number): The chain ID to get endpoints for
- `options` (ChainlistOptions, optional): Configuration options
  - `chainsJsonUrl` (string): Custom URL for chains.json data (default: 'https://chainid.network/chains.json')
  - `cacheDuration` (number): Cache duration in milliseconds (default: 3600000 - 1 hour)

**Returns:** `Promise<string[]>` - Array of RPC URLs that don't require API keys

**Example:**
```typescript
const endpoints = await getEndpoints(1)
```

### `getChainById(chainId, options?)`

Get chain information by chain ID.

**Parameters:**
- `chainId` (number): The chain ID to get information for
- `options` (ChainlistOptions, optional): Configuration options

**Returns:** `Promise<Chain | undefined>` - Chain information or undefined if not found

**Example:**
```typescript
const chain = await getChainById(137)
```

### `getAllChains(options?)`

Get all available chains.

**Parameters:**
- `options` (ChainlistOptions, optional): Configuration options

**Returns:** `Promise<Chain[]>` - Array of all chains

**Example:**
```typescript
const chains = await getAllChains()
```

### `clearCache()`

Clear the chains data cache.

**Example:**
```typescript
clearCache()
```

## Types

### `Chain`

```typescript
interface Chain {
  name: string
  chain: string
  icon?: string
  rpc: string[]
  features?: Array<{ name: string }>
  faucets: string[]
  nativeCurrency: {
    name: string
    symbol: string
    decimals: number
  }
  infoURL: string
  shortName: string
  chainId: number
  networkId: number
  slip44?: number
  ens?: {
    registry: string
  }
  explorers?: Array<{
    name: string
    url: string
    icon?: string
    standard: string
  }>
  title?: string
  status?: string
  redFlags?: string[]
}
```

### `ChainlistOptions`

```typescript
interface ChainlistOptions {
  chainsJsonUrl?: string  // Default: 'https://chainid.network/chains.json'
  cacheDuration?: number  // Default: 3600000 (1 hour)
}
```

## Popular Chain IDs

Here are some commonly used chain IDs:

| Network | Chain ID |
|---------|----------|
| Ethereum Mainnet | 1 |
| Polygon | 137 |
| Optimism | 10 |
| Arbitrum One | 42161 |
| Base | 8453 |
| BNB Chain | 56 |
| Avalanche C-Chain | 43114 |
| Gnosis | 100 |
| Celo | 42220 |
| Fantom | 250 |

For a complete list, visit [chainid.network](https://chainid.network).

## Filtering Logic

The module filters out RPC URLs that:
1. Require API keys (detected by patterns like `${INFURA_API_KEY}`, `{API_KEY}`, etc.)
2. Are websocket URLs (starting with `ws://` or `wss://`)

This ensures you only get publicly accessible HTTP/HTTPS endpoints.

## Example: Using with ethers.js

```typescript
import { getEndpoints } from 'w3pk/chainlist'
import { ethers } from 'ethers'

// Get Polygon endpoints
const endpoints = await getEndpoints(137)

// Try connecting to the first available endpoint
for (const rpcUrl of endpoints) {
  try {
    const provider = new ethers.JsonRpcProvider(rpcUrl)
    await provider.getBlockNumber() // Test connection
    console.log(`Connected to ${rpcUrl}`)
    break
  } catch (error) {
    console.log(`Failed to connect to ${rpcUrl}, trying next...`)
  }
}
```

## Example: Fallback RPC Provider

```typescript
import { getEndpoints } from 'w3pk/chainlist'
import { ethers } from 'ethers'

async function createFallbackProvider(chainId: number) {
  const endpoints = await getEndpoints(chainId)

  const providers = endpoints.map(url =>
    new ethers.JsonRpcProvider(url)
  )

  return new ethers.FallbackProvider(providers)
}

const provider = await createFallbackProvider(1)
```

## Testing

Run the chainlist tests:

```bash
pnpm test:chainlist
```

## See Also

- [chainid.network](https://chainid.network) - Source of chain data
- [Example code](../examples/chainlist-demo.ts)
