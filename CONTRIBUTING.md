# Contributing to w3pk

Thank you for your interest in contributing! This guide will help you get started.

## Requirements

- **Node.js**: >= 18.0.0
- **Package Manager**: pnpm (recommended) or npm
- **Browser**: For testing WebAuthn features
  - Chrome 67+ (May 2018)
  - Firefox 60+ (May 2018)
  - Safari 14+ (September 2020)
  - Edge 18+ (November 2018)
  - Mobile: iOS 14.5+, Android 9+
  - See [Browser Compatibility Guide](./docs/BROWSER_COMPATIBILITY.md) for details

## Process

1. **Create an issue** describing the bug fix or feature
2. **Create a branch** from the issue (use GitHub's "Create a branch" feature)
3. **Commit** your changes with clear messages
4. **Open a pull request** referencing the issue
5. **Request a review** from maintainers

## Development Setup

```bash
# Install pnpm (if not already installed)
npm install -g pnpm

# Install dependencies
pnpm install

# Run tests
pnpm test

# Run specific test suites
pnpm test:basic           # Basic SDK tests
pnpm test:comprehensive   # Comprehensive tests
pnpm test:zk              # Zero-knowledge proof tests
pnpm test:nft             # NFT ownership tests
pnpm test:chainlist       # RPC endpoint tests
pnpm test:eip7702         # EIP-7702 support tests
pnpm test:erc5564         # Stealth address tests

# Build
pnpm build

# Watch mode for development
pnpm dev
```

## Project Structure

```
w3pk/
├── src/
│   ├── auth/           # WebAuthn authentication
│   ├── wallet/         # Wallet generation & signing
│   ├── stealth/        # ERC-5564 stealth addresses
│   ├── zk/             # Zero-knowledge proofs (optional)
│   ├── chainlist/      # RPC endpoint management
│   ├── eip7702/        # EIP-7702 detection
│   └── core/           # SDK core & configuration
├── test/               # Test files
├── examples/           # Usage examples
└── docs/               # Documentation
```

## SDK API Reference

### Core SDK (`createWeb3Passkey`)

```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey({
  sessionDuration?: number  // Session duration in hours (default: 1)
  debug?: boolean
  onError?: (error: Web3PasskeyError) => void
  onAuthStateChanged?: (isAuth: boolean, user?: UserInfo) => void
  storage?: Storage
  stealthAddresses?: StealthAddressConfig
  zkProofs?: ZKProofConfig
})
```

### Authentication Flow

**Simple flow** (recommended for first-time users):

```typescript
// Register (auto-generates wallet and stores it securely)
const { mnemonic } = await w3pk.register({ username: 'alice' })
// Returns: { mnemonic: string } - IMPORTANT: User must save this!
```

**Advanced flow** (if you want to pre-generate wallet):

```typescript
// 1. Generate wallet first (optional)
const { mnemonic } = await w3pk.generateWallet()
// Returns: { mnemonic: string }

// 2. Register (uses pre-generated wallet and stores it securely)
const { mnemonic } = await w3pk.register({ username: 'alice' })
```

For returning users:
```typescript
// Just login
await w3pk.login()
```

#### `register(options)`
Register a new user with WebAuthn passkey. Auto-generates wallet if none exists.
```typescript
const { mnemonic } = await w3pk.register({
  username: string
})
// Returns: { mnemonic: string } - User must save this recovery phrase!
```

#### `login()`
Login with WebAuthn (usernameless).
```typescript
const user = await w3pk.login()
// Returns: { id, username, displayName, ethereumAddress }
```

#### `logout()`
Logout the current user.
```typescript
await w3pk.logout()
```

#### `isAuthenticated` (getter)
Check authentication status.
```typescript
const isAuth = w3pk.isAuthenticated // boolean
```

#### `user` (getter)
Get current user info.
```typescript
const user = w3pk.user // UserInfo | null
```

### Session Management

w3pk uses session caching to prevent repeated biometric prompts while maintaining security.

#### Session Configuration
```typescript
const w3pk = createWeb3Passkey({
  sessionDuration: 1  // Hours (default: 1)
})
```

#### `hasActiveSession()`
Check if session is active.
```typescript
const hasSession = w3pk.hasActiveSession() // boolean
```

#### `getSessionRemainingTime()`
Get remaining session time in seconds.
```typescript
const seconds = w3pk.getSessionRemainingTime() // number
```

#### `extendSession()`
Extend session by configured duration.
```typescript
w3pk.extendSession()
```

#### `clearSession()`
Manually clear session (force re-authentication).
```typescript
w3pk.clearSession()
```

### Wallet Methods

#### `generateWallet()`
Generate a new BIP39 wallet (no authentication required).
```typescript
const { mnemonic } = await w3pk.generateWallet()
// Returns: { mnemonic: string }
// Note: Wallet is stored in memory until register() is called
```

#### `deriveWallet(index, options?)`
Derive HD wallet at specific index (requires authentication).
```typescript
const wallet = await w3pk.deriveWallet(0, {
  requireAuth?: boolean  // Force fresh biometric (default: false)
})
// Returns: { address: string, privateKey: string }
```

#### `exportMnemonic(options?)`
Export mnemonic phrase (requires authentication).
```typescript
const mnemonic = await w3pk.exportMnemonic({
  requireAuth?: boolean  // Force fresh biometric (default: false)
})
// Returns: string (12-24 words)
```

#### `importMnemonic(mnemonic)`
Import existing mnemonic.
```typescript
await w3pk.importMnemonic('word1 word2 ... word12')
```

#### `signMessage(message, options?)`
Sign a message (requires authentication).
```typescript
const signature = await w3pk.signMessage('Hello World', {
  requireAuth?: boolean  // Force fresh biometric (default: false)
})
// Returns: string (0x... signature)
```

### Network Methods

#### `getEndpoints(chainId)`
Get public RPC endpoints for a chain.
```typescript
const endpoints = await w3pk.getEndpoints(1) // Ethereum
// Returns: string[] (array of RPC URLs)
```

#### `supportsEIP7702(chainId, options?)`
Check if network supports EIP-7702.
```typescript
const supported = await w3pk.supportsEIP7702(1, {
  maxEndpoints?: number  // Max RPC endpoints to test
  timeout?: number       // Timeout per endpoint (ms)
})
// Returns: boolean
```

### Stealth Address Methods (ERC-5564)

When enabled via config: `stealthAddresses: {}`

#### `stealth.getStealthMetaAddress()`
Get stealth meta-address to share publicly.
```typescript
const metaAddress = await w3pk.stealth?.getStealthMetaAddress()
// Returns: string (0x... 66 bytes)
```

#### `stealth.generateStealthAddress(metaAddress?)`
Generate stealth address for recipient.
```typescript
const announcement = await w3pk.stealth?.generateStealthAddress()
// Returns: {
//   stealthAddress: string
//   ephemeralPublicKey: string
//   viewTag: string
// }
```

#### `stealth.parseAnnouncement(announcement)`
Check if announcement is for current user.
```typescript
const result = await w3pk.stealth?.parseAnnouncement({
  stealthAddress: string
  ephemeralPublicKey: string
  viewTag: string
})
// Returns: {
//   isForUser: boolean
//   stealthAddress?: string
//   stealthPrivateKey?: string
// }
```

#### `stealth.scanAnnouncements(announcements)`
Efficiently scan multiple announcements.
```typescript
const myPayments = await w3pk.stealth?.scanAnnouncements([...])
// Returns: ParseAnnouncementResult[]
```

### Zero-Knowledge Proof Methods

When enabled via config: `zkProofs: { enabledProofs: ['membership', 'threshold'] }`

Requires: `npm install snarkjs circomlibjs`

```typescript
const zkModule = w3pk.zk
// Access ZK proof generation methods
// See docs/ZK_INTEGRATION_GUIDE.md for details
```

## Security Model

w3pk uses **authentication-gated encryption** for client-only wallet protection:

### How It Works

1. **Registration**: WebAuthn credential created, wallet encrypted with key derived from credential ID + public key
2. **Login**: User authenticates with biometric/PIN, wallet decrypted, session started (1 hour default)
3. **Operations**: Within session, no repeated prompts. After session expires, requires re-authentication.
4. **Force Auth**: Developers can require fresh biometric with `{ requireAuth: true }` option

### Security Properties

✅ **Biometric-gated access** - SDK enforces WebAuthn authentication before wallet operations
✅ **Session caching** - Prevents repeated prompts (configurable duration)
✅ **Hardware-backed credentials** - Private keys stored in Secure Enclave/TPM
✅ **Deterministic encryption** - Same key every time (credential ID + public key)

⚠️ **Limitation** - File system access to both localStorage + IndexedDB could decrypt wallet files
✅ **But** - SDK still requires WebAuthn authentication before allowing any wallet operations

### For Maximum Security

- Use short session durations: `sessionDuration: 0.1` (6 minutes)
- Or disable sessions: `sessionDuration: 0` (prompt every time)
- Require fresh auth for sensitive ops: `{ requireAuth: true }`
- Consider server-based architecture for enterprise use cases

See [Security Architecture](./docs/SECURITY.md) for detailed analysis.

## Guidelines

### Code Style
- Follow existing code patterns
- Use TypeScript strict mode
- Keep functions focused and small
- Minimize comments (code should be self-documenting)

### Testing
- Add tests for new features
- Maintain 100% test pass rate
- Test both success and error cases
- Use the mock setup from `test/setup.ts`

### Documentation
- Update README.md for user-facing changes
- Update API reference for new methods
- Add examples for new features
- Keep comments minimal and functional

### Commits
- Use clear, descriptive commit messages
- Keep commits focused and atomic
- Reference issue numbers in commits

## Common Tasks

### Adding a New SDK Method

1. Add method to `src/core/sdk.ts`
2. Add tests to appropriate test file
3. Update this CONTRIBUTING.md
4. Update README.md if user-facing
5. Add example to `examples/` if helpful

### Fixing a Bug

1. Write a failing test that reproduces the bug
2. Fix the bug
3. Verify test passes
4. Run full test suite

### Adding a Feature

1. Discuss in an issue first
2. Write tests for the feature
3. Implement the feature
4. Update documentation
5. Add example usage

## Questions?

- **General questions**: Open a discussion issue
- **Bug reports**: Open an issue with reproduction steps
- **Feature requests**: Open an issue describing the use case
- **Major changes**: Discuss in an issue before implementing

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0.