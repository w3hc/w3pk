[![npm version](https://img.shields.io/npm/v/w3pk.svg)](https://www.npmjs.com/package/w3pk)
[![npm downloads](https://img.shields.io/npm/dm/w3pk.svg)](https://www.npmjs.com/package/w3pk)

# w3pk

Passwordless Web3 authentication SDK with encrypted wallets and privacy features.

**Demo:** https://d2u.w3hc.org/voting

## Install
```bash
npm install w3pk ethers
```

## Quick Start
```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org'
})

// Register
await w3pk.register({
  username: 'alice',
  ethereumAddress: '0x...'
})

// Login
await w3pk.login()

// Sign message
const signature = await w3pk.signMessage('Hello World')

// Derive addresses
const wallet = await w3pk.deriveWallet(0) // First address
const wallet2 = await w3pk.deriveWallet(1) // Second address

// Get RPC endpoints for any chain (no API key required)
const endpoints = await w3pk.getEndpoints(1) // Example for Ethereum mainnet
const rpcUrl = endpoints[0] // Get first endpoint
// Will return "https://cloudflare-eth.com"
```

## Features

**Core (Included)**
- 🔐 Passwordless authentication (WebAuthn/FIDO2)
- 💰 Encrypted wallet management (AES-GCM-256)
- 🌱 HD wallet generation (BIP39/BIP44)
- 🔢 Multi-address derivation
- 🥷 Stealth addresses (privacy-preserving transactions)
- 🔗 Chainlist support (2390+ networks, auto-filtered RPC endpoints)

**Optional: Zero-Knowledge Proofs**

Requires additional dependencies (~70MB):
```bash
npm install snarkjs circomlibjs
```

See [ZK Integration Guide](./docs/ZK_INTEGRATION_GUIDE.md) for:
- Anonymous membership proofs
- Private balance verification
- Range proofs without revealing values
- NFT ownership proofs

[Bundle size comparison →](./docs/BUNDLE_SIZES.md)

## API

### Authentication
```typescript
// Register new user
await w3pk.register({ username, ethereumAddress })

// Login (usernameless)
await w3pk.login()

// Logout
await w3pk.logout()

// Check status
w3pk.isAuthenticated
w3pk.user
```

### Wallet
```typescript
// Generate wallet
const wallet = await w3pk.generateWallet()

// Derive HD wallet addresses
const derived = await w3pk.deriveWallet(index)
// Returns: { address, privateKey }

// Export mnemonic
const mnemonic = await w3pk.exportMnemonic()

// Sign message
const signature = await w3pk.signMessage(message)
```

### RPC Endpoints (Chainlist)
```typescript
// Get public RPC endpoints for any chain
const endpoints = await w3pk.getEndpoints(1) // Ethereum mainnet
const rpcUrl = endpoints[0] // First endpoint
// Returns: "https://cloudflare-eth.com"

// Other examples
await w3pk.getEndpoints(137)   // Polygon
await w3pk.getEndpoints(10)    // Optimism
await w3pk.getEndpoints(42161) // Arbitrum One
await w3pk.getEndpoints(8453)  // Base

// Integration with ethers.js
import { ethers } from 'ethers'

const endpoints = await w3pk.getEndpoints(137) // Polygon
const provider = new ethers.JsonRpcProvider(endpoints[0])
const blockNumber = await provider.getBlockNumber()
console.log(`Current block: ${blockNumber}`)
```

**Features:**
- ✅ Auto-filters endpoints requiring API keys
- ✅ 2390+ blockchain networks
- ✅ WebSocket URLs excluded (HTTP/HTTPS only)
- ✅ Built-in caching (1-hour default)
- ✅ Data from [chainid.network](https://chainid.network)

[Full Documentation →](./docs/CHAINLIST.md)

### Stealth Addresses
```typescript
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  stealthAddresses: {}
})

// Generate unlinkable address
const stealth = await w3pk.stealth?.generateStealthAddress()
// Returns: { stealthAddress, stealthPrivateKey, ephemeralPublicKey }

// Get master keys
const keys = await w3pk.stealth?.getKeys()
// Returns: { metaAddress, viewingKey, spendingKey }
```

## Documentation

- [Quick Start Guide](./docs/QUICK_START.md)
- [RPC Endpoints](./docs/CHAINLIST.md)
- [ZK Integration Guide](./docs/ZK_INTEGRATION_GUIDE.md)
- [Bundle Size Comparison](./docs/BUNDLE_SIZES.md)

## Examples

- [Basic Authentication](./examples/basic-auth.ts)
- [Wallet Management](./examples/wallet-demo.ts)
- [RPC Endpoints](./examples/sdk-with-chainlist.ts)
- [Stealth Addresses](./examples/stealth-demo.ts)
- [ZK Proofs](./examples/zk-proof-demo.ts) (requires ZK deps)
- [NFT Ownership](./examples/nft-ownership-proof.ts) (requires ZK deps)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

GPL-3.0

## Contact

**Julien Béranger** ([GitHub](https://github.com/julienbrg))
- Element: [@julienbrg:matrix.org](https://matrix.to/#/@julienbrg:matrix.org)
- Farcaster: [julien-](https://warpcast.com/julien-)
- Telegram: [@julienbrg](https://t.me/julienbrg)
- Twitter: [@julienbrg](https://twitter.com/julienbrg)

---

<img src="https://bafkreid5xwxz4bed67bxb2wjmwsec4uhlcjviwy7pkzwoyu5oesjd3sp64.ipfs.w3s.link" alt="built-with-ethereum-w3hc" width="100"/>