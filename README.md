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
- 🥷 ERC-5564 stealth addresses (privacy-preserving transactions with view tags)
- 🔗 Chainlist support (2390+ networks, auto-filtered RPC endpoints)
- ⚡ EIP-7702 network detection (329+ supported networks)

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

[Full Documentation →](./docs/CHAINLIST.md)

### EIP-7702 Support
```typescript
// Check if network supports EIP-7702 (cached list + RPC verification)
const supported = await w3pk.supportsEIP7702(1) // true (Ethereum, instant)

// Unknown networks test via RPC (auto-uses getEndpoints)
await w3pk.supportsEIP7702(999) // false (tests up to 3 RPC endpoints)

// Configure RPC testing
await w3pk.supportsEIP7702(999, {
  maxEndpoints: 5,  // Test up to 5 endpoints
  timeout: 5000     // 5 second timeout per RPC
})
```

### ERC-5564 Stealth Addresses

Privacy-preserving payments using unlinkable, one-time addresses.

```typescript
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  stealthAddresses: {}
})

// STEP 1 (Recipient): Get stealth meta-address to share publicly
const metaAddress = await w3pk.stealth?.getStealthMetaAddress()
// Example: 0x03f2e32f9a060b8fe18736f5c4da328265d9d29ac13d5fed45649700a9c5f2cdca...
// This is 66 bytes (spending + viewing public keys) - safe to share publicly!

// STEP 2 (Sender): Generate stealth address for recipient
const announcement = await w3pk.stealth?.generateStealthAddress()
// Returns:
// - stealthAddress: 0x1234... (send funds here)
// - ephemeralPublicKey: 0x02abcd... (publish on-chain)
// - viewTag: 0xa4 (enables ~99% skip rate when scanning)

// Sender publishes announcement on-chain and sends funds to stealthAddress
// Only the recipient can identify this payment belongs to them!

// STEP 3 (Recipient): Parse announcements to find your payments
const result = await w3pk.stealth?.parseAnnouncement({
  stealthAddress: announcement.stealthAddress,
  ephemeralPublicKey: announcement.ephemeralPublicKey,
  viewTag: announcement.viewTag
})

if (result.isForUser) {
  console.log('Payment found:', result.stealthAddress)
  console.log('Private key:', result.stealthPrivateKey)
  // Use this private key to spend the funds
}

// STEP 4 (Recipient): Efficiently scan many announcements
// View tags enable ~99% (255/256) skip rate - makes scanning extremely fast!
const myPayments = await w3pk.stealth?.scanAnnouncements(announcements)
console.log(`Found ${myPayments.length} payments`)
```

**Key Benefits:**
- **Privacy**: Each payment uses a unique, unlinkable address
- **Non-interactive**: No communication needed between sender/recipient
- **Efficient**: View tags enable scanning 1000s of announcements quickly
- **ERC-5564 compliant**: Works with other standard implementations

[Complete ERC-5564 Guide →](./docs/ERC5564_STEALTH_ADDRESSES.md)

## Documentation

- [Quick Start Guide](./docs/QUICK_START.md) - Get started in 5 minutes
- [ERC-5564 Stealth Addresses](./docs/ERC5564_STEALTH_ADDRESSES.md) - Complete guide with examples
- [ERC-5564 Flow Diagrams](./docs/ERC5564_FLOW_DIAGRAM.md) - Visual explanations of how stealth addresses work
- [RPC Endpoints](./docs/CHAINLIST.md) - Chainlist integration guide
- [ZK Integration Guide](./docs/ZK_INTEGRATION_GUIDE.md) - Zero-knowledge proofs (optional)
- [Bundle Size Comparison](./docs/BUNDLE_SIZES.md) - Core vs ZK bundle sizes

## Examples

- [Basic Authentication](./examples/basic-auth.ts)
- [Wallet Management](./examples/wallet-demo.ts)
- [RPC Endpoints](./examples/sdk-with-chainlist.ts)
- [ERC-5564 Stealth Addresses](./examples/erc5564-stealth-demo.ts)
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