[![npm version](https://img.shields.io/npm/v/w3pk.svg)](https://www.npmjs.com/package/w3pk)
[![npm downloads](https://img.shields.io/npm/dm/w3pk.svg)](https://www.npmjs.com/package/w3pk)
[![Reproducible Build](https://img.shields.io/badge/reproducible-builds-blue?logo=ipfs)](https://github.com/w3hc/w3pk/blob/main/docs/BUILD_VERIFICATION.md)

# w3pk

Passwordless Web3 authentication SDK with encrypted wallets and privacy features.

**Live demo:** [w3pk.w3hc.org](https://w3pk.w3hc.org)

## Install
```bash
npm install w3pk ethers
```

## Quick Start
```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey()

// Register new user (generates wallet, stores with WebAuthn)
const { address, username } = await w3pk.register({ username: 'alice' })

// Login for subsequent sessions
await w3pk.login()

// Sign messages (EIP-191, SIWE, EIP-712, rawHash)
const signature = await w3pk.signMessage('Hello World')

// Derive wallets (STANDARD/STRICT/YOLO modes)
const wallet = await w3pk.deriveWallet('STANDARD', 'GAMING')

// Get RPC endpoints
const endpoints = await w3pk.getEndpoints(1)
```

## Features

- Passwordless authentication (WebAuthn/FIDO2)
- Origin-specific key isolation with tag-based access control
- Session management (in-memory + optional persistent)
- HD wallet generation (BIP39/BIP44)
- Multi-address derivation with security modes (STANDARD/STRICT/YOLO)
- Multiple signing methods (EIP-191, SIWE/EIP-4361, EIP-712, rawHash)
- ERC-5564 stealth addresses (opt-in)
- ZK primitives (zero-knowledge proof generation and verification)
- Chainlist support (2390+ networks)
- EIP-7702 network detection (329+ networks)
- EIP-7951 PRIMARY mode (P-256 passkey signing)
- Build verification (IPFS CIDv1 hashing)
- Three-layer backup & recovery (passkey sync, encrypted backups, social recovery)

## API

### Authentication

```typescript
// Check for existing wallet
const hasWallet = await w3pk.hasExistingCredential()

// Register or login
if (hasWallet) {
  await w3pk.login()
} else {
  const { address, username } = await w3pk.register({ username: 'alice' })
}

// List all wallets on device
const wallets = await w3pk.listExistingCredentials()

// Logout
await w3pk.logout()
```

### Wallet Derivation

```typescript
// STANDARD mode - address only (no private key)
const mainWallet = await w3pk.deriveWallet('STANDARD')
// Returns: { address, index, origin, tag: 'MAIN' }

// YOLO mode - includes private key for app-specific use
const gamingWallet = await w3pk.deriveWallet('YOLO', 'GAMING')
// Returns: { address, privateKey, index, origin, tag: 'GAMING' }

// STRICT mode - address only, no persistent sessions allowed
const strictWallet = await w3pk.deriveWallet('STRICT', 'SECURE')

// Different tags generate different addresses
console.log(mainWallet.address !== gamingWallet.address) // true
```

**Security:** Master mnemonic is never exposed. Applications cannot access `exportMnemonic()`.

### Message Signing

```typescript
// EIP-191 (default)
const sig = await w3pk.signMessage('Hello World')

// SIWE (Sign-In with Ethereum)
const siweMessage = createSiweMessage({ ... })
const siweSig = await w3pk.signMessage(siweMessage, {
  signingMethod: 'SIWE'
})

// EIP-712 (typed data)
const eip712Sig = await w3pk.signMessage(JSON.stringify(typedData), {
  signingMethod: 'EIP712',
  eip712Domain,
  eip712Types,
  eip712PrimaryType: 'Transfer'
})

// Raw hash
const rawSig = await w3pk.signMessage(hash, {
  signingMethod: 'rawHash'
})

// Force authentication for sensitive operations
const sensitiveSig = await w3pk.signMessage('Transfer $1000', {
  requireAuth: true
})
```

### Session Management

```typescript
// In-memory sessions (default, 1 hour)
const w3pk = createWeb3Passkey({
  sessionDuration: 2 // 2 hours
})

// Persistent sessions (survives page refresh)
const w3pkPersistent = createWeb3Passkey({
  sessionDuration: 1,
  persistentSession: {
    enabled: true,
    duration: 168,        // 7 days (in hours)
    requireReauth: true   // Prompt on refresh
  }
})

// Auto-restore mode (silent restore)
const w3pkAutoRestore = createWeb3Passkey({
  persistentSession: {
    enabled: true,
    duration: 30 * 24,
    requireReauth: false
  }
})

// Session status
w3pk.hasActiveSession()
w3pk.getSessionRemainingTime()
w3pk.extendSession()
await w3pk.clearSession()
```

**Note:** STRICT mode never allows persistent sessions.

### RPC Endpoints

```typescript
// Get public RPC endpoints for any chain
const endpoints = await w3pk.getEndpoints(1)      // Ethereum
const optimismRpc = await w3pk.getEndpoints(10)   // Optimism
const arbitrumRpc = await w3pk.getEndpoints(42161) // Arbitrum

// Use with ethers.js
import { ethers } from 'ethers'
const provider = new ethers.JsonRpcProvider(endpoints[0])
const blockNumber = await provider.getBlockNumber()
```

### EIP-7702 Support

```typescript
// Check network support
const supported = await w3pk.supportsEIP7702(1)

// Configure RPC testing
await w3pk.supportsEIP7702(999, {
  maxEndpoints: 5,
  timeout: 5000
})

// Sign authorization for gasless transactions
const authorization = await w3pk.signAuthorization({
  contractAddress: '0x...',
  chainId: 1,
  nonce: 0n
})
// Returns: { chainId, address, nonce, yParity, r, s }
```

### EIP-7951 PRIMARY Mode

```typescript
// Get PRIMARY address (P-256 passkey-derived)
const primaryAddr = await w3pk.getAddress('PRIMARY')

// Sign with P-256 passkey directly (no private key)
const result = await w3pk.signMessageWithPasskey("Hello World")
// Returns: { signature: { r, s }, messageHash, signedHash, address }
```

### ERC-5564 Stealth Addresses

```typescript
const w3pk = createWeb3Passkey({
  stealthAddresses: {}
})

// Get stealth meta-address
const metaAddress = await w3pk.stealth?.getStealthMetaAddress()

// Generate stealth address for recipient
const announcement = await w3pk.stealth?.generateStealthAddress()

// Check if announcement is for you
const result = await w3pk.stealth?.parseAnnouncement({
  stealthAddress: announcement.stealthAddress,
  ephemeralPublicKey: announcement.ephemeralPublicKey,
  viewTag: announcement.viewTag
})

if (result.isForUser) {
  console.log('Private key:', result.stealthPrivateKey)
}

// Scan multiple announcements
const myPayments = await w3pk.stealth?.scanAnnouncements(announcements)
```

### Backup & Recovery

```typescript
import { isStrongPassword } from 'w3pk'

// Validate password strength
const password = 'MyS3cur3!Password@2042'
if (!isStrongPassword(password)) {
  throw new Error('Password must be 12+ chars with uppercase, lowercase, number, special char')
}

// Get backup status
const status = await w3pk.getBackupStatus()
console.log('Security Score:', status.securityScore.total) // 0-100

// Create encrypted backup file
const { blob, filename } = await w3pk.createBackupFile('password', password)

// Setup social recovery (M-of-N guardians)
await w3pk.setupSocialRecovery(
  [
    { name: 'Alice', email: 'alice@example.com' },
    { name: 'Bob', phone: '+1234567890' },
    { name: 'Charlie' }
  ],
  2 // threshold
)

// Generate guardian invite
const invite = await w3pk.generateGuardianInvite(guardianShare)

// Recover from guardian shares
const { mnemonic } = await w3pk.recoverFromGuardians([share1, share2])

// Restore from backup file
await w3pk.restoreFromBackup(encryptedData, password)

// Simulate recovery scenarios
const result = await w3pk.simulateRecoveryScenario({
  type: 'lost-device',
  hasBackup: true,
  hasSocialRecovery: true
})
```

### Build Verification

```typescript
import { getCurrentBuildHash, verifyBuildHash } from 'w3pk'

// Get IPFS hash of installed build
const hash = await getCurrentBuildHash()

// Verify against trusted hash
const TRUSTED_HASH = 'bafybeig2xoiu2hfcjexz6cwtjcjf4u4vwxzcm66zhnqivhh6jvi7nx2qa4'
const isValid = await verifyBuildHash(TRUSTED_HASH)
```

## Security & Verification

### Current Build Hash (v0.8.8)

```
bafybeig2xoiu2hfcjexz6cwtjcjf4u4vwxzcm66zhnqivhh6jvi7nx2qa4
```

**Verify package integrity:**

```typescript
import { verifyBuildHash } from 'w3pk'

const TRUSTED_HASH = 'bafybeig2xoiu2hfcjexz6cwtjcjf4u4vwxzcm66zhnqivhh6jvi7nx2qa4'
const isValid = await verifyBuildHash(TRUSTED_HASH)

if (!isValid) {
  throw new Error('Package integrity check failed!')
}
```

## Documentation

- [Quick Start Guide](./docs/QUICK_START.md)
- [Integration Guidelines](./docs/INTEGRATION_GUIDELINES.md)
- [API Reference](./docs/API_REFERENCE.md)
- [Build Verification](./docs/BUILD_VERIFICATION.md)
- [EIP-7951](./docs/EIP-7951.md)
- [Security Architecture](./docs/SECURITY.md)
- [Recovery & Backup System](./docs/RECOVERY.md)
- [ZK Proofs](./docs/ZK.md)
- [Browser Compatibility](./docs/BROWSER_COMPATIBILITY.md)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md)

## License

GPL-3.0

## Contact

**Julien Béranger** ([GitHub](https://github.com/julienbrg))
- Element: [@julienbrg:matrix.org](https://matrix.to/#/@julienbrg:matrix.org)
- Farcaster: [julien-](https://warpcast.com/julien-)
- Telegram: [@julienbrg](https://t.me/julienbrg)
- Twitter: [@julienbrg](https://twitter.com/julienbrg)


<img src="https://bafkreid5xwxz4bed67bxb2wjmwsec4uhlcjviwy7pkzwoyu5oesjd3sp64.ipfs.w3s.link" alt="built-with-ethereum-w3hc" width="100"/>