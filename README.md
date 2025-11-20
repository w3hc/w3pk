[![npm version](https://img.shields.io/npm/v/w3pk.svg)](https://www.npmjs.com/package/w3pk)
[![npm downloads](https://img.shields.io/npm/dm/w3pk.svg)](https://www.npmjs.com/package/w3pk)
[![Reproducible Build](https://img.shields.io/badge/reproducible-builds-blue?logo=ipfs)](https://github.com/w3hc/w3pk/blob/main/docs/BUILD_VERIFICATION.md)

# w3pk

Passwordless Web3 authentication SDK with encrypted wallets and privacy features.

- **Live demo: [w3pk.w3hc.org](https://w3pk.w3hc.org)**
- [Quick start](./docs/QUICK_START.md)

## Install
```bash
npm install w3pk ethers
```

## Quick Start
```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey()

// Register (auto-generates wallet and stores it securely)
const { address, username } = await w3pk.register({ username: 'alice' })
console.log('✅ Registered:', username, 'with address:', address)

// Login (for subsequent sessions)
await w3pk.login()

// Sign message
const signature = await w3pk.signMessage('Hello World')

// Derive addresses (2 modes)
const gamingWallet = await w3pk.deriveWallet('GAMING') // By tag - includes privateKey
const mainWallet = await w3pk.deriveWallet() // Auto (MAIN tag) - public address only, no privateKey

// Get RPC endpoints for any chain
const endpoints = await w3pk.getEndpoints(1) // Ethereum
const rpcUrl = endpoints[0]
```

## Features

- 🔐 Passwordless authentication (WebAuthn/FIDO2)
- 🔒 **Enhanced Security Model**: Applications cannot access master mnemonic or MAIN tag private keys
- 🛡️ Origin-specific key isolation with tag-based access control
- ⏱️ Session management (configurable duration, prevents repeated prompts)
- 🌱 HD wallet generation (BIP39/BIP44)
- 🔢 Multi-address derivation
- 🌐 Origin-specific addresses (deterministic derivation per website with tag support)
- 🥷 ERC-5564 stealth addresses (opt-in, privacy-preserving transactions with view tags)
- 🧮 ZK primitives (zero-knowledge proof generation and verification)
- 🔗 Chainlist support (2390+ networks, auto-filtered RPC endpoints)
- ⚡ EIP-7702 network detection (329+ supported networks)
- 🔍 Build verification (IPFS CIDv1 hashing for package integrity)
- 🛡️ Three-layer backup & recovery system
  - Passkey auto-sync (iCloud/Google/Microsoft)
  - Encrypted backups (ZIP/QR with password protection)
  - Social recovery (Shamir Secret Sharing)

## API

### Authentication Flow

```typescript
// Register (generates and stores wallet securely)
const { address, username } = await w3pk.register({ username: 'alice' })
// Returns: { address, username } 

// Subsequent sessions: just login
await w3pk.login()

// Logout
await w3pk.logout()

// Status
w3pk.isAuthenticated
w3pk.user
```

**Important: Backup your wallet!**
```typescript

// Create encrypted backups:
const zipBackup = await w3pk.createZipBackup('strong-password')
const qrBackup = await w3pk.createQRBackup('optional-password')
```

### Wallet Operations

**SECURITY MODEL**: `deriveWallet()` supports two secure modes:

```typescript
// 1. MAIN tag (default) - ADDRESS ONLY, NO PRIVATE KEY
const mainWallet = await w3pk.deriveWallet()
// Returns: { address, index, origin, tag: 'MAIN' }
// ✅ Safe for display
// ❌ No privateKey exposed

// 2. Custom tag - INCLUDES PRIVATE KEY for app-specific use
const gamingWallet = await w3pk.deriveWallet('GAMING')
const funWallet = await w3pk.deriveWallet('FUN')
const basicWallet = await w3pk.deriveWallet('BASIC')
// Returns: { address, privateKey, index, origin, tag }

// Different tags = different addresses
console.log(mainWallet.address !== gamingWallet.address) // true
console.log(gamingWallet.address !== tradingWallet.address) // true

// SECURITY: Applications CANNOT access master mnemonic
// await w3pk.exportMnemonic() // ❌ Throws error

// Sign message (works with any address - no key exposure needed)
const signature = await w3pk.signMessage('Hello World')
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
await w3pk.deriveWallet('GAMING')
await w3pk.signMessage('Hello')
await w3pk.stealth?.getKeys() // If stealth module enabled

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
import { isStrongPassword } from 'w3pk'

// Validate password strength before creating backups
const password = 'MyS3cur3!Password@2042'
if (!isStrongPassword(password)) {
  throw new Error('Password does not meet security requirements')
}
// Requirements: 12+ chars, uppercase, lowercase, number, special char, not common

// Get backup status
const status = await w3pk.getBackupStatus()
console.log('Security Score:', status.securityScore.score) // 0-100

// Create encrypted ZIP backup
const blob = await w3pk.createZipBackup(password)
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

### Build Verification

```typescript
import { getCurrentBuildHash, verifyBuildHash } from 'w3pk'

// Get IPFS hash of installed w3pk build
const hash = await getCurrentBuildHash()
console.log('Build hash:', hash)
// => bafybeifysgwvsyog2akxjk4cjky2grqqyzfehamuwyk6zy56srgkc5jopi

// Verify against trusted hash (from GitHub releases)
const trusted = 'bafybeifysgwvsyog2akxjk4cjky2grqqyzfehamuwyk6zy56srgkc5jopi'
const isValid = await verifyBuildHash(trusted)
if (isValid) {
  console.log('✅ Build integrity verified!')
}
```

See [Build Verification Guide](./docs/BUILD_VERIFICATION.md) for complete documentation.

## Security & Verification

### Current Build Hash (v0.7.6)

```
bafybeifysgwvsyog2akxjk4cjky2grqqyzfehamuwyk6zy56srgkc5jopi
```

**Verify package integrity:**

```typescript
import { verifyBuildHash } from 'w3pk'

const TRUSTED_HASH = 'bafybeifysgwvsyog2akxjk4cjky2grqqyzfehamuwyk6zy56srgkc5jopi'
const isValid = await verifyBuildHash(TRUSTED_HASH)

if (!isValid) {
  throw new Error('Package integrity check failed!')
}
```

**Multi-source verification:**
- **GitHub:** Check release notes for official hash
- **On-chain:** Verify via DAO-maintained registry (coming soon)
- **Local build:** `pnpm build && pnpm build:hash`

See [Build Verification Guide](./docs/BUILD_VERIFICATION.md) for complete documentation.

---

## Documentation

- [Quick Start Guide](./docs/QUICK_START.md) - Get started in 5 minutes
- [API Reference](./docs/API_REFERENCE.md) - Complete API documentation
- [Build Verification](./docs/BUILD_VERIFICATION.md) - Package integrity verification
- [Security Architecture](./docs/SECURITY.md) - Integration best practices
- [Recovery & Backup System](./docs/RECOVERY.md) - Three-layer backup architecture
- [ZK Proofs](./docs/ZK.md) - Zero-Knowledge cryptography utilities
- [Browser compatibility](./docs/BROWSER_COMPATIBILITY.md)

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