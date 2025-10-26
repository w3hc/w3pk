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
- 🔒 Client-only biometric-gated wallet encryption (AES-GCM-256)
- ⏱️ Session management (configurable duration, prevents repeated prompts)
- 🌱 HD wallet generation (BIP39/BIP44)
- 🔢 Multi-address derivation
- 🥷 ERC-5564 stealth addresses (privacy-preserving transactions with view tags)
- 🔗 Chainlist support (2390+ networks, auto-filtered RPC endpoints)
- ⚡ EIP-7702 network detection (329+ supported networks)
- 🛡️ Three-layer backup & recovery system
  - Passkey auto-sync (iCloud/Google/Microsoft)
  - Encrypted backups (ZIP/QR with password protection)
  - Social recovery (Shamir Secret Sharing)

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
await w3pk.login()

// These operations use the cached session
await w3pk.deriveWallet(0)
await w3pk.exportMnemonic()
await w3pk.signMessage('Hello')
await w3pk.stealth.getKeys()

// Check session status
w3pk.hasActiveSession() // true
w3pk.getSessionRemainingTime() // 3540 seconds

// Extend session
w3pk.extendSession() // Adds 2 more hours

// Clear session manually (force re-authentication)
w3pk.clearSession()

// Disable sessions (most secure - prompt every time)
const w3pk = createWeb3Passkey({ sessionDuration: 0 })
```

#### Force Authentication for Sensitive Operations

Even with an active session, you can require fresh biometric authentication for specific operations:

```typescript
// Session is active, but force authentication anyway
await w3pk.exportMnemonic({ requireAuth: true })
await w3pk.signMessage('Transfer $1000', { requireAuth: true })
await w3pk.deriveWallet(5, { requireAuth: true })
await w3pk.stealth.getKeys({ requireAuth: true })

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
await w3pk.getEndpoints(10)    // Optimism
await w3pk.getEndpoints(42161) // Arbitrum
await w3pk.getEndpoints(8453)  // Base

// Use with ethers.js
import { ethers } from 'ethers'

const endpoints = await w3pk.getEndpoints(137)
const provider = new ethers.JsonRpcProvider(endpoints[0])
const blockNumber = await provider.getBlockNumber()
```

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

### Backup & Recovery

```typescript
// Get backup status
const status = await w3pk.getBackupStatus()
console.log('Security Score:', status.securityScore.score) // 0-100

// Create encrypted ZIP backup
const blob = await w3pk.createZipBackup('MyS3cur3!Password@2042')
// Save blob to file system

// Create QR backup
const { qrCodeDataURL } = await w3pk.createQRBackup('password')
// Display QR code or save as image

// Setup social recovery (3-of-5 guardians)
await w3pk.setupSocialRecovery(
  [
    { name: 'Alice', email: 'alice@example.com' },
    { name: 'Bob', phone: '+1234567890' },
    { name: 'Charlie' }
  ],
  3 // threshold
)

// Generate guardian invite
const invite = await w3pk.generateGuardianInvite(guardianId)
// Share invite.qrCode or invite.shareCode with guardian

// Recover from guardian shares
const { mnemonic } = await w3pk.recoverFromGuardians([
  share1, share2, share3
])

// Restore from backup
await w3pk.restoreFromBackup(encryptedData, password)

// Simulate recovery scenarios for testing
const result = await w3pk.simulateRecoveryScenario({
  type: 'lost-device',
  hasBackup: true,
  hasSocialRecovery: true
})
console.log('Can recover:', result.canRecover)
```

See [Recovery Guide](./docs/RECOVERY.md) for complete documentation.

## Browser Compatibility

**Supported (95%+ of users):**
- Chrome 67+ (May 2018), Edge 18+ (Nov 2018), Firefox 60+ (May 2018), Safari 14+ (Sep 2020)
- iOS 14.5+ (April 2021), Android 9+ (August 2018)
- Windows Hello, Touch ID, Face ID, platform authenticators

**Not Supported:**
- Safari < 14, Chrome/Firefox < 2018, IE11, Android < 9, iOS < 14.5
- Private/Incognito mode (credentials don't persist)
- WebView/embedded browsers (often disabled)

## Documentation

- [Quick Start Guide](./docs/QUICK_START.md) - Get started in 5 minutes
- [Recovery & Backup System](./docs/RECOVERY.md) - Three-layer backup architecture
- [Browser Compatibility](./docs/BROWSER_COMPATIBILITY.md) - Supported browsers, devices, and OS versions
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