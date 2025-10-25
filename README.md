[![npm version](https://img.shields.io/npm/v/w3pk.svg)](https://www.npmjs.com/package/w3pk)
[![npm downloads](https://img.shields.io/npm/dm/w3pk.svg)](https://www.npmjs.com/package/w3pk)

# w3pk

Passwordless Web3 authentication SDK with encrypted wallets and privacy features.

**Demo: [w3pk.w3hc.org](https://w3pk.w3hc.org)**

## Install
```bash
npm install w3pk ethers
```

## Quick Start
```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey()

// Register (auto-generates wallet and stores it securely)
const { mnemonic } = await w3pk.register({ username: 'alice' })
console.log('⚠️  Save this recovery phrase:', mnemonic)

// Login (for subsequent sessions)
await w3pk.login()

// Sign message
const signature = await w3pk.signMessage('Hello World')

// Derive addresses
const wallet0 = await w3pk.deriveWallet(0)
const wallet1 = await w3pk.deriveWallet(1)

// Get RPC endpoints for any chain
const endpoints = await w3pk.getEndpoints(1) // Ethereum
const rpcUrl = endpoints[0]
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

See [ZK Integration Guide](./docs/ZK_INTEGRATION_GUIDE.md) to get started.

## API

### Authentication Flow

```typescript
// Register (auto-stores wallet)
const { mnemonic } = await w3pk.register({ username: 'alice' })
// Returns: { mnemonic } - SAVE THIS!

// Subsequent sessions: just login
await w3pk.login()

// Logout
await w3pk.logout()

// Status
w3pk.isAuthenticated
w3pk.user
```

**Advanced: Pre-generate wallet (optional)**
```typescript
// If you want to see the wallet before registering:
const { mnemonic } = await w3pk.generateWallet()
const { mnemonic } = await w3pk.register({ username: 'alice' })
// register() will use the pre-generated wallet
```

### Wallet Operations

```typescript
// Derive addresses
const wallet0 = await w3pk.deriveWallet(0)
// Returns: { address, privateKey }

// Export mnemonic
const mnemonic = await w3pk.exportMnemonic()

// Sign message
const signature = await w3pk.signMessage(message)
```

### Session Management

By default, after authentication, operations work for 1 hour without repeated biometric prompts:

```typescript
// Configure session duration
const w3pk = createWeb3Passkey({
  sessionDuration: 2 // 2 hours (default: 1)
})

// After login, mnemonic is cached in memory
await w3pk.login()                // ✅ Requires biometric

// These operations use the cached session
await w3pk.deriveWallet(0)        // ✅ No prompt (uses session)
await w3pk.exportMnemonic()       // ✅ No prompt (uses session)
await w3pk.signMessage('Hello')   // ✅ No prompt (uses session)
await w3pk.stealth.getKeys()      // ✅ No prompt (uses session)

// Check session status
w3pk.hasActiveSession()           // true
w3pk.getSessionRemainingTime()    // 3540 (seconds)

// Extend session
w3pk.extendSession()              // Adds 2 more hours

// Clear session manually (force re-authentication)
w3pk.clearSession()

// Disable sessions (most secure - prompt every time)
const w3pk = createWeb3Passkey({ sessionDuration: 0 })
```

#### Force Authentication for Sensitive Operations

Even with an active session, you can require fresh biometric authentication for specific operations:

```typescript
// Session is active, but force authentication anyway
await w3pk.exportMnemonic({ requireAuth: true })     // ✅ Always prompts
await w3pk.signMessage('Transfer $1000', { requireAuth: true }) // ✅ Always prompts
await w3pk.deriveWallet(5, { requireAuth: true })    // ✅ Always prompts
await w3pk.stealth.getKeys({ requireAuth: true })    // ✅ Always prompts

// Example: Require auth for high-value transactions
async function transferFunds(amount: number, recipient: string) {
  // For transfers above $100, require fresh authentication
  const requireAuth = amount > 100

  const signature = await w3pk.signMessage(
    `Transfer ${amount} to ${recipient}`,
    { requireAuth }
  )

  // ... submit transaction
}
```

### RPC Endpoints
```typescript
// Get public RPC endpoints
const endpoints = await w3pk.getEndpoints(1) // Ethereum
const rpcUrl = endpoints[0]

// Other chains
await w3pk.getEndpoints(137)   // Polygon
await w3pk.getEndpoints(10)    // Optimism
await w3pk.getEndpoints(42161) // Arbitrum
await w3pk.getEndpoints(8453)  // Base

// Use with ethers.js
import { ethers } from 'ethers'

const endpoints = await w3pk.getEndpoints(137)
const provider = new ethers.JsonRpcProvider(endpoints[0])
const blockNumber = await provider.getBlockNumber()
```

[Full Documentation →](./docs/CHAINLIST.md)

### EIP-7702 Support
```typescript
// Check network support
const supported = await w3pk.supportsEIP7702(1) // true

// Configure RPC testing
await w3pk.supportsEIP7702(999, {
  maxEndpoints: 5,
  timeout: 5000
})
```

### ERC-5564 Stealth Addresses

```typescript
const w3pk = createWeb3Passkey({
  stealthAddresses: {}
})

// Get stealth meta-address
const metaAddress = await w3pk.stealth?.getStealthMetaAddress()

// Generate stealth address
const announcement = await w3pk.stealth?.generateStealthAddress()

// Parse announcement
const result = await w3pk.stealth?.parseAnnouncement({
  stealthAddress: announcement.stealthAddress,
  ephemeralPublicKey: announcement.ephemeralPublicKey,
  viewTag: announcement.viewTag
})

if (result.isForUser) {
  // Use private key to spend funds
  console.log('Private key:', result.stealthPrivateKey)
}

// Scan announcements
const myPayments = await w3pk.stealth?.scanAnnouncements(announcements)
```

## Documentation

- [Quick Start Guide](./docs/QUICK_START.md) - Get started in 5 minutes
- [Security Architecture](./docs/SECURITY.md) - Integration best practices
- [ERC-5564 Stealth Addresses](./docs/ERC5564_STEALTH_ADDRESSES.md) - Complete guide with examples
- [ERC-5564 Flow Diagrams](./docs/ERC5564_FLOW_DIAGRAM.md) - Visual explanations of how stealth addresses work
- [RPC Endpoints](./docs/CHAINLIST.md) - Chainlist integration guide
- [ZK Integration Guide](./docs/ZK_INTEGRATION_GUIDE.md) - Zero-knowledge proofs (optional)
- [Bundle Size Comparison](./docs/BUNDLE_SIZES.md) - Core vs ZK bundle sizes

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