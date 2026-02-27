[![npm version](https://img.shields.io/npm/v/w3pk.svg)](https://www.npmjs.com/package/w3pk)
[![npm downloads](https://img.shields.io/npm/dm/w3pk.svg)](https://www.npmjs.com/package/w3pk)
[![Reproducible Build](https://img.shields.io/badge/reproducible-builds-blue?logo=ipfs)](https://github.com/w3hc/w3pk/blob/main/docs/BUILD_VERIFICATION.md)

# w3pk

Passwordless Web3 authentication SDK with encrypted wallets and privacy features.

**Live demo:** [w3pk.w3hc.org](https://w3pk.w3hc.org)

## Install
```bash
npm install w3pk ethers
# or
npm install w3pk viem
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

// Send transactions on-chain
const tx = await w3pk.sendTransaction({ to: '0x...', value: 1n * 10n**18n, chainId: 1 })

// EIP-1193 provider (ethers, viem, wagmi, RainbowKit)
const eip1193 = w3pk.getEIP1193Provider({ chainId: 1 })

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
- On-chain transaction sending with automatic RPC resolution (`sendTransaction`)
- EIP-1193 provider for ethers, viem, wagmi, RainbowKit (`getEIP1193Provider`)
- ERC-5564 stealth addresses (opt-in)
- ZK primitives (zero-knowledge proof generation and verification)
- Chainlist support (2390+ networks)
- EIP-7702 network detection (329+ networks)
- External wallet integration (delegate MetaMask/Ledger to w3pk via EIP-7702)
- EIP-7951 PRIMARY mode (P-256 passkey signing)
- Build verification (IPFS CID hashing + DAO-maintained onchain registry)
- Three-layer backup & recovery (passkey sync, encrypted backups, social recovery)
- AI-powered host app inspection

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

w3pk supports multiple security modes for deriving wallets with different privacy and security trade-offs:

```typescript
// PRIMARY mode - WebAuthn P-256 passkey (EIP-7951)
// Uses hardware-backed passkey directly, no seed phrase involved
const primaryWallet = await w3pk.deriveWallet('PRIMARY')
// Returns: { address, publicKey, origin, mode: 'PRIMARY', tag: 'MAIN' }

// STANDARD mode - Default balanced security (recommended)
// Returns address only, private key stays in SDK for signing
const mainWallet = await w3pk.deriveWallet('STANDARD')
// Returns: { address, index, origin, mode: 'STANDARD', tag: 'MAIN' }

// YOLO mode - Private key exposed to app
// Use only when app needs direct key access (advanced use cases)
const gamingWallet = await w3pk.deriveWallet('YOLO', 'GAMING')
// Returns: { address, privateKey, index, origin, mode: 'YOLO', tag: 'GAMING' }

// STRICT mode - Maximum security, re-auth required every time
// Requires biometric/PIN for each call - impractical for most apps
const strictWallet = await w3pk.deriveWallet('STRICT', 'SECURE')
// Returns: { address, privateKey, index, origin, mode: 'STRICT', tag: 'SECURE' }

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

### Sending Transactions

```typescript
// Check which address will be used before sending
const from = await w3pk.getAddress('STANDARD', 'MAIN')
console.log('sending from:', from)

// Send ETH — defaults to STANDARD mode, MAIN tag, current origin
// sender = getOriginSpecificAddress(mnemonic, window.location.origin, 'STANDARD', 'MAIN')
const result = await w3pk.sendTransaction({
  to: '0xRecipient...',
  value: 1n * 10n**18n,  // 1 ETH in wei
  chainId: 1
})
console.log('tx hash:', result.hash)
console.log('from:', result.from)   // same address as `from` above
console.log('mode:', result.mode)   // 'STANDARD'

// Send contract call with custom RPC and STRICT auth
const callResult = await w3pk.sendTransaction(
  { to: '0xContract...', data: '0xabcd...', chainId: 10 },
  { mode: 'STRICT', rpcUrl: 'https://mainnet.optimism.io' }
)

// YOLO mode — app-specific isolated address
const yoloTx = await w3pk.sendTransaction(
  { to: '0x...', value: 5n * 10n**17n, chainId: 8453 },
  { mode: 'YOLO', tag: 'GAMING' }
)
```

**Mode behaviour:**

| Mode | Auth on send | Gas source |
|------|-------------|------------|
| STANDARD | Session (auto) | Sender address |
| STRICT | Always (biometric) | Sender address |
| YOLO | Session (auto) | Sender address |
| PRIMARY | — (not supported, throws) | Requires bundler |

### EIP-1193 Provider

Use w3pk with any EIP-1193 consumer — ethers, viem, wagmi, RainbowKit — without exposing private keys.

```typescript
const eip1193 = w3pk.getEIP1193Provider({ chainId: 1 })
```

**ethers v6**
```typescript
import { BrowserProvider } from 'ethers'
const provider = new BrowserProvider(eip1193)
const signer = await provider.getSigner()
const tx = await signer.sendTransaction({ to: '0x...', value: parseEther('1') })
```

**viem**
```typescript
import { createWalletClient, custom } from 'viem'
import { mainnet } from 'viem/chains'
const client = createWalletClient({ chain: mainnet, transport: custom(eip1193) })
const [address] = await client.getAddresses()
const hash = await client.sendTransaction({ to: '0x...', value: parseEther('1') })
```

**Supported JSON-RPC methods:**

| Method | Action |
|--------|--------|
| `eth_accounts` / `eth_requestAccounts` | Returns derived address |
| `eth_chainId` | Returns active chain as hex |
| `eth_sendTransaction` | Delegates to `sendTransaction()` |
| `personal_sign` / `eth_sign` | EIP-191 message signing |
| `eth_signTypedData_v4` | EIP-712 typed data signing |
| `wallet_switchEthereumChain` | Updates active chainId, emits `chainChanged` |

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

// Delegate external wallet (MetaMask, Ledger, etc.) to w3pk account
const auth = await w3pk.requestExternalWalletDelegation({
  chainId: 1,
  nonce: 0n
})
// User's external wallet account now controlled by w3pk WebAuthn
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
await w3pk.restoreFromBackupFile(encryptedData, password)

// Simulate recovery scenarios
const result = await w3pk.simulateRecoveryScenario({
  type: 'lost-device',
  description: 'Device lost with iCloud Keychain enabled'
})
```

### Build Verification

```typescript
import { getCurrentBuildHash } from 'w3pk'
import { ethers } from 'ethers'
import packageJson from './package.json'

// Get installed w3pk version from package.json
const installedVersion = packageJson.dependencies['w3pk'].replace(/^[~^]/, '') // Remove ^ or ~

// Get IPFS hash of installed build
const hash = await getCurrentBuildHash()
console.log('Installed version:', installedVersion)
console.log('Local build hash:', hash)

// Verify against DAO-maintained onchain registry (OP Mainnet)
const REGISTRY = '0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a'
const ABI = ['function getCidByVersion(string version) view returns (string)']
const provider = new ethers.JsonRpcProvider('https://mainnet.optimism.io')
const registry = new ethers.Contract(REGISTRY, ABI, provider)

// Query registry for the specific installed version (note: "v" prefix required)
const onchainCid = await registry.getCidByVersion(`v${installedVersion}`)
const isValid = hash === onchainCid

console.log('Onchain CID:', onchainCid)
console.log('Verified:', isValid ? '✅' : '❌')
```

### Security Inspection

Analyze web3 applications to understand their transaction and signing methods:

**Browser (analyze current page):**
```typescript
import { inspect, inspectNow } from 'w3pk'

// Full inspection with custom options
const result = await inspect({
  appUrl: 'https://example.com',
  rukhUrl: 'https://rukh.w3hc.org',
  model: 'anthropic',
  focusMode: 'transactions'
})
console.log(result.report)

// Quick console inspection
await inspectNow()  // Logs report directly to console
```

**Node.js (analyze local files):**
```typescript
import { inspect, gatherCode } from 'w3pk/inspect/node'

// Generate security report via Rukh API
const report = await inspect(
  '../my-dapp',           // App path
  'https://rukh.w3hc.org', // Rukh API URL
  'w3pk',                  // Context
  'anthropic',             // Model
  'transactions'           // Focus mode
)

// Or just gather code for analysis
const result = await gatherCode({
  appPath: '../my-dapp',
  focusMode: 'transactions',
  maxFileSizeKB: 500
})
console.log(`Analyzed ${result.includedFiles.length} files`)
```

## Security & Verification

### Onchain Build Registry

W3PK maintains a DAO-controlled onchain registry of verified build hashes on OP Mainnet:

- **Registry Contract:** [`0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a`](https://optimistic.etherscan.io/address/0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a)
- **Network:** OP Mainnet (Chain ID: 10)
- **Purpose:** Immutable source of truth for official W3PK releases

Host applications should verify their installed W3PK build against this registry. See [Build Verification](./docs/BUILD_VERIFICATION.md) for implementation details.

## Documentation

- [Quick Start Guide](./docs/QUICK_START.md)
- [Integration Guidelines](./docs/INTEGRATION_GUIDELINES.md)
- [API Reference](./docs/API_REFERENCE.md)
- [Build Verification](./docs/BUILD_VERIFICATION.md)
- [Security Inspection](./docs/INSPECTION.md)
- [EIP-7951](./docs/EIP-7951.md)
- [Security Architecture](./docs/SECURITY.md)
- [Post-Quantum Cryptography](./docs/POST_QUANTUM.md) - Quantum-safe migration roadmap
- [Recovery & Backup System](./docs/RECOVERY.md)
- [Portability Guide](./docs/PORTABILITY.md)
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