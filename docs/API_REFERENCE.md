# w3pk API Reference

Complete reference for all methods, types, and utilities in the w3pk SDK.

## Table of Contents

- [Installation & Initialization](#installation--initialization)
- [Core Authentication](#core-authentication)
- [Wallet Management](#wallet-management)
  - [Origin-Specific Address Derivation](#origin-specific-address-derivation)
  - [`sendTransaction()`](#sendtransactiontx-options-promisetransactionresult)
  - [`getEIP1193Provider()`](#geteip1193provideroptions-eip1193providerinterface)
- [Stealth Addresses (ERC-5564)](#stealth-addresses-erc-5564)
- [Zero-Knowledge Proofs](#zero-knowledge-proofs)
- [Backup & Recovery](#backup--recovery)
- [Cross-Device Sync](#cross-device-sync)
  - [`syncWalletWithPasskey()`](#syncwalletwithpasskey)
- [Session Management](#session-management)
- [Blockchain Utilities](#blockchain-utilities)
- [Standalone Utilities](#standalone-utilities)
  - [Validation Utilities](#validation-utilities)
  - [Build Verification Utilities](#build-verification-utilities)
  - [Wallet Generation Utilities](#wallet-generation-utilities)
- [Security Inspection](#security-inspection)
  - [Browser Inspection](#browser-inspection)
  - [Node.js Inspection](#nodejs-inspection)
- [Error Types](#error-types)
- [Type Definitions](#type-definitions)

---

## Installation & Initialization

### `createWeb3Passkey(config?: Web3PasskeyConfig): Web3Passkey`

Creates and returns a new Web3Passkey SDK instance.

**Parameters:**

```typescript
interface Web3PasskeyConfig {
  debug?: boolean;                    // Enable debug mode (default: false)
  onError?: (error: Web3PasskeyError) => void;  // Global error handler
  onAuthStateChanged?: (isAuthenticated: boolean, user?: UserInfo) => void;  // Auth state callback
  storage?: Storage;                  // Custom storage backend (default: IndexedDB)
  sessionDuration?: number;           // Session duration in hours (default: 1)
  persistentSession?: Partial<PersistentSessionConfig>;  // Enable "Remember Me" functionality
  stealthAddresses?: StealthAddressConfig;  // Enable stealth addresses
  zkProofs?: ZKProofConfig;          // Enable ZK proofs
}

interface PersistentSessionConfig {
  enabled: boolean;       // Enable persistent sessions (default: false)
  duration: number;       // Duration in hours (default: 168 = 7 days)
  requireReauth: boolean; // Require re-auth on page refresh (default: true)
}
```

**Example:**

```typescript
import { createWeb3Passkey } from 'w3pk'

// Basic configuration
const w3pk = createWeb3Passkey({
  debug: false,
  sessionDuration: 2,
  onAuthStateChanged: (isAuthenticated, user) => {
    console.log('Auth state:', isAuthenticated, user)
  }
})

// With persistent sessions enabled (7 days, requires reauth on refresh)
const w3pkWithRememberMe = createWeb3Passkey({
  persistentSession: {
    enabled: true,           // Enable "Remember Me"
    duration: 168,           // 7 days (in hours)
    requireReauth: true      // Prompt for biometric on page refresh
  }
})

// Full "Remember Me" experience (30 days, auto-restore)
const w3pkAutoRestore = createWeb3Passkey({
  persistentSession: {
    enabled: true,
    duration: 30 * 24,       // 30 days
    requireReauth: false     // Silent session restore (no prompt)
  }
})
```

---

## Core Authentication

### `register(options: { username: string }): Promise<RegisterResult>`

Register a new user with WebAuthn passkey authentication.

**Parameters:**

```typescript
{
  username: string;  // 3-50 characters, alphanumeric + underscore + hyphen (must start/end with alphanumeric)
}
```

**Returns:**

```typescript
interface RegisterResult {
  address: string;      // Ethereum address (account #0 derived from BIP44)
  username: string;     // Registered username
}
```

**What happens:**
1. Generates BIP39 mnemonic (12 words) if no wallet exists
2. Creates WebAuthn credential (triggers biometric prompt)
3. Derives Ethereum wallet from mnemonic (path: m/44'/60'/0'/0/0)
4. Encrypts mnemonic using WebAuthn credential (AES-GCM-256)
5. Stores encrypted wallet in IndexedDB
6. Starts 1-hour session with decrypted mnemonic in memory
7. Returns Ethereum address and username

**Example:**

```typescript
const { address, username } = await w3pk.register({
  username: 'alice'
})
console.log('Registered:', username, 'with address:', address)
```

---

### `login(): Promise<UserInfo>`

Authenticate user with WebAuthn (passwordless, usernameless).

**Returns:**

```typescript
interface UserInfo {
  id: string;              // Ethereum address
  username: string;        // Username
  displayName: string;     // Same as username
  ethereumAddress: string; // Ethereum address
}
```

**What happens:**
1. Retrieves credential ID from IndexedDB
2. Triggers WebAuthn authentication (biometric prompt)
3. Retrieves encrypted wallet from IndexedDB
4. Decrypts mnemonic using WebAuthn signature
5. Starts new session (1 hour by default)
6. Returns user info
7. Subsequent operations use cached session - no repeated biometric prompts

**Example:**

```typescript
const user = await w3pk.login()
console.log('Logged in as:', user.username)
```

---

### `logout(): Promise<void>`

Logout current user and clear session.

**What happens:**
1. Clears session - removes cached mnemonic from memory
2. Overwrites sensitive data with zeros
3. Triggers `onAuthStateChanged` callback with `false`
4. Next wallet operation requires fresh authentication

**Example:**

```typescript
await w3pk.logout()
console.log('Logged out')
```

---

### `isAuthenticated: boolean` (property)

Get current authentication status.

**Example:**

```typescript
if (w3pk.isAuthenticated) {
  console.log('User is logged in')
}
```

---

### `user: UserInfo | null` (property)

Get current user information or `null` if not authenticated.

**Example:**

```typescript
const currentUser = w3pk.user
if (currentUser) {
  console.log('Current user:', currentUser.username)
}
```

---

### `hasExistingCredential(): Promise<boolean>`

Check if there are existing credentials (wallets) on this device.

**Returns:** `boolean` - `true` if at least one credential exists

**What happens:**
1. Queries localStorage for stored credentials
2. Returns `true` if any wallets are found
3. Returns `false` if no wallets exist or storage fails

**Use case:** Prevent accidental multiple wallet creation, especially on iOS/macOS where multiple passkeys can cause confusion.

**Example:**

```typescript
const hasWallet = await w3pk.hasExistingCredential()
if (hasWallet) {
  // User already has a wallet - suggest login instead
  await w3pk.login()
} else {
  // No wallet found - proceed with registration
  await w3pk.register({ username: 'alice' })
}
```

---

### `getExistingCredentialCount(): Promise<number>`

Get the number of existing credentials (wallets) on this device.

**Returns:** `number` - Count of existing wallets

**Use case:** Show warning messages with specific counts when user attempts to create multiple wallets.

**Example:**

```typescript
const count = await w3pk.getExistingCredentialCount()
if (count > 0) {
  console.warn(`⚠️ You have ${count} wallet(s) on this device`)
  console.warn('Creating another wallet will generate a DIFFERENT address')
}
```

---

### `listExistingCredentials(): Promise<Array<CredentialInfo>>`

List all existing credentials (wallets) on this device with metadata.

**Returns:**

```typescript
interface CredentialInfo {
  username: string;        // Username
  ethereumAddress: string; // Ethereum address
  createdAt: string;       // ISO timestamp
  lastUsed: string;        // ISO timestamp
}
```

**Use case:** Allow users to see and select which wallet to login to when multiple wallets exist.

**Example:**

```typescript
const wallets = await w3pk.listExistingCredentials()

console.log('Available wallets:')
wallets.forEach((wallet, i) => {
  console.log(`${i + 1}. ${wallet.username}`)
  console.log(`   Address: ${wallet.ethereumAddress}`)
  console.log(`   Last used: ${wallet.lastUsed}`)
})

// Let user select which wallet to login to
const selectedWallet = wallets[userSelection]
await w3pk.login() // Will authenticate with selected credential
```

---

## Wallet Management

### `generateWallet(): Promise<{ mnemonic: string }>`

Generate a new BIP39 wallet (12-word mnemonic).

**Returns:**

```typescript
{
  mnemonic: string;  // 12-word BIP39 mnemonic phrase
}
```

**Example:**

```typescript
const { mnemonic } = await w3pk.generateWallet()
console.log('New wallet:', mnemonic)
```

---

### `deriveWallet(mode?: SecurityMode, tag?: string, options?: { requireAuth?: boolean; origin?: string }): Promise<WalletInfo>`

Origin-centric wallet derivation with three security modes:

**Security Modes:**
- **`STANDARD` (default)**: Address only (no private key), persistent sessions allowed
- **`STRICT`**: Address only (no private key), no persistent sessions (requires auth each time)
- **`YOLO`**: Full access (address + private key), persistent sessions allowed

**Parameters:**
- `mode?: SecurityMode` - Security mode: 'STANDARD' | 'STRICT' | 'YOLO' (default: 'STANDARD')
- `tag?: string` - Tag for derivation (default: 'MAIN')
- `options.requireAuth?: boolean` - Force fresh authentication (default: false)
- `options.origin?: string` - Override origin URL (default: current origin)

**Returns:**

```typescript
interface WalletInfo {
  address: string;       // Ethereum address
  privateKey?: string;   // Private key (only in YOLO mode)
  index?: number;        // BIP32 derivation index
  origin?: string;       // Origin URL
  mode?: SecurityMode;   // Security mode used
  tag?: string;          // Tag name
}
```

**Example:**

```typescript
// Default: STANDARD mode with MAIN tag
const wallet = await w3pk.deriveWallet()
console.log('Address:', wallet.address)
console.log('Private key:', wallet.privateKey) // undefined (STANDARD mode)

// STRICT mode: No persistent sessions
const strictWallet = await w3pk.deriveWallet('STRICT')
// This will require biometric/PIN authentication every time

// YOLO mode: Full access with private key
const yoloWallet = await w3pk.deriveWallet('YOLO')
console.log('Address:', yoloWallet.address)
console.log('Private key:', yoloWallet.privateKey) // Available!

// YOLO mode with custom tag
const gamingWallet = await w3pk.deriveWallet('YOLO', 'GAMING')
console.log('Gaming wallet:', gamingWallet.address)
console.log('Tag:', gamingWallet.tag) // 'GAMING'

// STANDARD mode with custom tag
const tradingWallet = await w3pk.deriveWallet('STANDARD', 'TRADING')
console.log('Trading wallet:', tradingWallet.address)
console.log('Private key:', tradingWallet.privateKey) // undefined

// Force fresh authentication
const secureWallet = await w3pk.deriveWallet('STANDARD', 'MAIN', { requireAuth: true })

// Override origin (advanced use case)
const customWallet = await w3pk.deriveWallet('YOLO', 'GAMING', {
  origin: 'https://custom-domain.com'
})
```

**Security Benefits:**
- Origin-centric: Each origin gets unique addresses
- Mode-based private key access control
- STRICT mode prevents session-based attacks
- Deterministic (same origin + mode + tag = same address every time)
- Privacy-preserving by default

---

### `getAddress(mode?: SecurityMode, tag?: string, options?: { origin?: string }): Promise<string>`

Lightweight method to get the public address for a specific security mode and tag without exposing private keys or creating full wallet objects.

**Parameters:**
- `mode?: SecurityMode` - Security mode: 'PRIMARY' | 'STANDARD' | 'STRICT' | 'YOLO' (default: 'STANDARD')
- `tag?: string` - Tag for derivation (default: 'MAIN')
- `options.origin?: string` - Override origin URL (default: current origin)

**Returns:** `Promise<string>` - The Ethereum address for this mode/tag combination

**Example:**

```typescript
// Get default STANDARD + MAIN address
const mainAddr = await w3pk.getAddress()
console.log('Main address:', mainAddr)

// Get PRIMARY address (P-256 from passkey)
const primaryAddr = await w3pk.getAddress('PRIMARY')
console.log('PRIMARY address:', primaryAddr)

// Get YOLO GAMING address
const gamingAddr = await w3pk.getAddress('YOLO', 'GAMING')
console.log('Gaming address:', gamingAddr)

// Get STRICT address (will require authentication)
const strictAddr = await w3pk.getAddress('STRICT')
console.log('Strict address:', strictAddr)

// Display multiple addresses in UI
const addresses = {
  primary: await w3pk.getAddress('PRIMARY'),
  standard: await w3pk.getAddress('STANDARD'),
  gaming: await w3pk.getAddress('YOLO', 'GAMING'),
  trading: await w3pk.getAddress('STANDARD', 'TRADING')
}
console.log('All addresses:', addresses)
```

**Use Cases:**
- Display addresses in UI without exposing private keys
- Verify which address will be used before signing
- Show multiple addresses for different modes/tags
- Lightweight address retrieval for read-only operations

**Security Notes:**
- Never exposes private keys (even in YOLO mode)
- PRIMARY mode returns P-256 address derived from WebAuthn public key
- STRICT mode requires fresh authentication each time
- Other modes use session cache if available

---

### Origin-Specific Address Derivation

Generate deterministic addresses per origin/website with security mode and tag support.

#### `getOriginSpecificAddress(mnemonic: string, origin: string, mode?: SecurityMode, tag?: string): Promise<OriginWalletInfo>`

Derives an origin-specific address from mnemonic with mode and tag support.

**Parameters:**
- `mnemonic: string` - The BIP39 mnemonic phrase
- `origin: string` - The origin URL (e.g., "https://example.com")
- `mode?: SecurityMode` - Security mode: 'STANDARD' | 'STRICT' | 'YOLO' (default: 'STANDARD')
- `tag?: string` - Optional tag to generate different addresses for same origin (default: "MAIN")

**Returns:**

```typescript
interface OriginWalletInfo {
  address: string;        // Ethereum address
  privateKey?: string;    // Private key (only in YOLO mode)
  index: number;          // BIP32 derivation index
  origin: string;         // Normalized origin
  mode: SecurityMode;     // Security mode used
  tag: string;            // Normalized tag (uppercase)
}
```

**How it works:**
1. Normalizes the origin URL (lowercase, removes trailing slash, handles standard ports)
2. Combines origin, mode, and tag: `${origin}:${MODE}:${TAG}`
3. SHA-256 hashes the combined string
4. Derives deterministic index from hash (0 to 2^31-1)
5. Derives wallet at BIP32 path: `m/44'/60'/0'/0/{index}`
6. Exposes private key only in YOLO mode

**Example:**

```typescript
import { getOriginSpecificAddress } from 'w3pk'

const mnemonic = 'test test test test test test test test test test test junk'

// STANDARD mode (default) - no private key
const standardWallet = await getOriginSpecificAddress(
  mnemonic,
  'https://example.com'
)
console.log('Standard:', standardWallet.address)
console.log('Private key:', standardWallet.privateKey) // undefined

// STRICT mode - no private key, no persistent sessions
const strictWallet = await getOriginSpecificAddress(
  mnemonic,
  'https://example.com',
  'STRICT'
)
console.log('Strict:', strictWallet.address)
console.log('Private key:', strictWallet.privateKey) // undefined

// YOLO mode - includes private key
const yoloWallet = await getOriginSpecificAddress(
  mnemonic,
  'https://example.com',
  'YOLO'
)
console.log('YOLO:', yoloWallet.address)
console.log('Private key:', yoloWallet.privateKey) // Available!
// Different address from MAIN

// Get TRADING-specific address
const tradingWallet = await getOriginSpecificAddress(
  mnemonic,
  'https://example.com',
  'TRADING'
)
console.log('Trading:', tradingWallet.address)
// Different address from both MAIN and GAMING

// Same origin + same tag = same address (deterministic)
const wallet2 = await getOriginSpecificAddress(
  mnemonic,
  'https://example.com',
  'GAMING'
)
console.log(gamingWallet.address === wallet2.address) // true
```

**Use Cases:**
- **Privacy**: Each website gets unique addresses by default
- **Compartmentalization**: Separate gaming, trading, social, etc. on same site
- **Deterministic**: Reproducible addresses, no storage needed
- **Tags**: MAIN, GAMING, TRADING, SOCIAL, SIMPLE, or custom tags

**Tag Normalization:**
- Tags are case-insensitive: "gaming", "GAMING", "GaMiNg" all produce same address
- Tags are stored uppercase in the return value
- Default tag when not specified: "MAIN"

**Origin Isolation:**
- `https://example.com` and `http://example.com` are different origins
- `https://example.com` and `https://app.example.com` are different origins
- Standard ports are normalized: `https://example.com:443` → `https://example.com`
- Non-standard ports are preserved: `https://example.com:8443` stays as-is

---

#### Helper Functions

##### `deriveIndexFromOriginModeAndTag(origin: string, mode?: SecurityMode, tag?: string): Promise<number>`

Derives deterministic index from origin, security mode, and tag.

**Parameters:**
- `origin: string` - The origin URL (e.g., "https://example.com")
- `mode?: SecurityMode` - Security mode: 'STANDARD' | 'STRICT' | 'YOLO' (default: 'STANDARD')
- `tag?: string` - Optional tag to generate different addresses for same origin (default: "MAIN")

**Returns:** `Promise<number>` - Deterministic BIP32 index (0 to 2^31-1)

**Example:**
```typescript
import { deriveIndexFromOriginModeAndTag } from 'w3pk'

const index = await deriveIndexFromOriginModeAndTag('https://example.com', 'YOLO', 'GAMING')
console.log('Index:', index) // 1870479373
```

##### `normalizeOrigin(origin: string): string`

Normalizes an origin URL for consistent derivation.

**Example:**
```typescript
import { normalizeOrigin } from 'w3pk'

const normalized = normalizeOrigin('https://EXAMPLE.COM/')
console.log(normalized) // 'https://example.com'
```

##### `getCurrentOrigin(): string`

Gets current browser origin (browser only).

**Example:**
```typescript
import { getCurrentOrigin } from 'w3pk'

const origin = getCurrentOrigin()
console.log('Current origin:', origin) // e.g., 'https://app.example.com'
```

---

##### `deriveAddressFromP256PublicKey(publicKeySpki: string): Promise<string>`

Derive Ethereum address from P-256 public key (EIP-7951 compatible).

This is used internally for PRIMARY mode to derive addresses directly from WebAuthn passkey public keys.

**Parameters:**
- `publicKeySpki: string` - Public key in SPKI format (base64url encoded)

**Returns:** `Promise<string>` - Ethereum address (0x-prefixed)

**How it works:**
1. Decodes base64url SPKI public key
2. Extracts x and y coordinates from P-256 public key
3. Creates uncompressed public key (64 bytes: x || y)
4. Hashes with keccak256
5. Takes last 20 bytes as Ethereum address

**Example:**
```typescript
import { deriveAddressFromP256PublicKey } from 'w3pk'

// Public key from WebAuthn credential (base64url SPKI format)
const publicKeySpki = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...'

const address = await deriveAddressFromP256PublicKey(publicKeySpki)
console.log('P-256 address:', address) // 0x...
```

**Use Cases:**
- PRIMARY mode address derivation
- EIP-7951 account abstraction wallets
- WebAuthn-native smart contract wallets
- Passkey-first authentication without seed phrases

**Related:**
- See [EIP-7951 Implementation Guide](../docs/EIP-7951.md) (if exists)
- Used by `getAddress('PRIMARY')` and `deriveWallet('PRIMARY')`

---

##### `DEFAULT_MODE: SecurityMode`

Default security mode constant (`'STANDARD'`).

**Example:**
```typescript
import { DEFAULT_MODE } from 'w3pk'

console.log(DEFAULT_MODE) // 'STANDARD'
```

---

##### `DEFAULT_TAG: string`

Default derivation tag constant (`'MAIN'`).

**Example:**
```typescript
import { DEFAULT_TAG } from 'w3pk'

console.log(DEFAULT_TAG) // 'MAIN'
```

---

### `exportMnemonic(options?: { requireAuth?: boolean }): Promise<string>`

Export the mnemonic phrase.

**Parameters:**
- `options.requireAuth?: boolean` - Force fresh authentication (default: false)

**Returns:** `string` - The 12-word mnemonic phrase

**Security:**
- Uses active session or prompts for authentication if session expired
- For backups, recommended to use `{ requireAuth: true }` to ensure conscious export

**Example:**

```typescript
// Using session
const mnemonic = await w3pk.exportMnemonic()
console.log('Mnemonic:', mnemonic)

// Force fresh authentication for backup
const mnemonicBackup = await w3pk.exportMnemonic({ requireAuth: true })
console.log('BACKUP THIS:', mnemonicBackup)
```

---

### `importMnemonic(mnemonic: string): Promise<void>`

Import a mnemonic phrase and encrypt it for current user.

**Parameters:**
- `mnemonic: string` - Valid BIP39 mnemonic (12 or 24 words)

**Security:**
- Requires fresh WebAuthn authentication
- Will overwrite existing wallet
- Irreversible operation

**Example:**

```typescript
const recoveredMnemonic = 'witch collapse practice feed shame open despair creek road again ice least'
await w3pk.importMnemonic(recoveredMnemonic)
console.log('Wallet restored')
```

---

### `signMessage(message: string, options?: SignMessageOptions): Promise<SignatureResult>`

Sign a message with the wallet using ECDSA with configurable signing methods.

By default, signs with **STANDARD mode + MAIN tag** (origin-centric address) using **EIP-191**.
You can specify a different mode, tag, and signing method to customize the signature.

**Parameters:**
- `message: string` - Message to sign (or hash for rawHash method, JSON for EIP712)
- `options.mode?: SecurityMode` - Security mode: 'STANDARD' | 'STRICT' | 'YOLO' (default: 'STANDARD')
- `options.tag?: string` - Tag for derivation (default: 'MAIN')
- `options.requireAuth?: boolean` - Force fresh authentication (default: false)
- `options.origin?: string` - Override origin URL (testing only)
- `options.signingMethod?: SigningMethod` - Signing method: 'EIP191' | 'SIWE' | 'EIP712' | 'rawHash' (default: 'EIP191')
- `options.eip712Domain?: object` - EIP-712 domain separator (required for EIP712 method)
- `options.eip712Types?: object` - EIP-712 type definitions (required for EIP712 method)
- `options.eip712PrimaryType?: string` - Primary type name (required for EIP712 method)

**Returns:** `SignatureResult`

```typescript
interface SignatureResult {
  signature: string;     // Ethereum signature (hex string)
  address: string;       // Address that signed the message
  mode: SecurityMode;    // Security mode used
  tag: string;           // Tag used
  origin: string;        // Origin used
}
```

**Signing Methods:**

| Method | Description | Use Case |
|--------|-------------|----------|
| `EIP191` (default) | Standard Ethereum signed message with `\x19Ethereum Signed Message:\n<length>` prefix | General message signing, wallet authentication |
| `SIWE` | Sign-In with Ethereum (EIP-4361) compliant | Web3 login flows, dApp authentication |
| `EIP712` | Sign structured typed data (EIP-712) | Token permits, DAO voting, NFT minting, gasless transactions |
| `rawHash` | Sign raw 32-byte hashes without EIP-191 prefix | Pre-computed EIP-712 hashes, Safe multisig transactions |

**EIP-191 Signing (default):**
- Standard Ethereum message signing
- Adds prefix: `\x19Ethereum Signed Message:\n<length>`
- Compatible with all Ethereum wallets
- Verifiable with `ethers.verifyMessage()`

**SIWE Signing (EIP-4361):**
- Sign-In with Ethereum compliant
- Message should be a properly formatted SIWE message
- Uses EIP-191 prefix (for EOA accounts)
- See https://docs.login.xyz for message format
- Use `createSiweMessage()` helper for proper formatting

**EIP-712 Signing:**
- Signs structured typed data according to EIP-712 standard
- Automatically computes domain separator and struct hash
- Requires `eip712Domain`, `eip712Types`, and `eip712PrimaryType` options
- Message should be JSON string or object with typed data values
- More user-friendly than rawHash for structured data
- Verifiable with `TypedDataEncoder.recoverAddress()`

**rawHash Signing:**
- Signs raw 32-byte hashes directly without EIP-191 prefix
- Message must be a 32-byte hash (64 hex characters, with or without 0x prefix)
- Useful for pre-computed EIP-712 hashes or Safe transactions
- Throws error if message is not exactly 32 bytes
- Use when you need manual control over hash computation

**What happens:**
1. Derives wallet based on mode and tag
2. Checks for active session (unless STRICT mode forces auth)
3. If no session - prompts for biometric authentication
4. Signs message using specified signing method
5. Returns signature with metadata

**Example:**

```typescript
// Default: Sign with STANDARD + MAIN address using EIP-191
const result = await w3pk.signMessage('Hello World')
console.log('Signature:', result.signature)
console.log('Signed by:', result.address)
console.log('Mode:', result.mode)        // 'STANDARD'
console.log('Tag:', result.tag)          // 'MAIN'

// Sign with YOLO + GAMING address
const gamingResult = await w3pk.signMessage('Hello World', {
  mode: 'YOLO',
  tag: 'GAMING'
})
console.log('Gaming address:', gamingResult.address)  // Different address!

// Sign with STRICT mode (requires auth every time)
const strictResult = await w3pk.signMessage('Transfer $10000', {
  mode: 'STRICT'
})
// User will be prompted for biometric/PIN

// Sign with custom tag in STANDARD mode
const tradingResult = await w3pk.signMessage('Trade order', {
  tag: 'TRADING'
})
console.log('Trading address:', tradingResult.address)

// Force authentication for sensitive operation
const secureResult = await w3pk.signMessage('Critical operation', {
  requireAuth: true
})

// SIWE (Sign-In with Ethereum) - EIP-4361
const siweMessage = `example.com wants you to sign in with your Ethereum account:
0x1234...5678

Sign in to example.com

URI: https://example.com
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`

const siweResult = await w3pk.signMessage(siweMessage, {
  signingMethod: 'SIWE'
})
console.log('SIWE signature:', siweResult.signature)
// Verifiable with ethers.verifyMessage(siweMessage, signature)

// EIP-712 (Structured Typed Data) - Better UX for permits, voting, etc.
const domain = {
  name: 'MyToken',
  version: '1',
  chainId: 1,
  verifyingContract: '0x1234567890123456789012345678901234567890'
}

const types = {
  Permit: [
    { name: 'owner', type: 'address' },
    { name: 'spender', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' }
  ]
}

const message = {
  owner: '0xYourAddress',
  spender: '0xSpenderAddress',
  value: '1000000000000000000',
  nonce: '0',
  deadline: '1735689600'
}

// Sign typed data directly (recommended for structured data)
const eip712Result = await w3pk.signMessage(JSON.stringify(message), {
  signingMethod: 'EIP712',
  eip712Domain: domain,
  eip712Types: types,
  eip712PrimaryType: 'Permit'
})
console.log('EIP-712 signature:', eip712Result.signature)

// Alternatively: Sign raw 32-byte hash (for pre-computed hashes)
import { TypedDataEncoder, recoverAddress } from 'ethers'

// Manually compute the hash
const hash = TypedDataEncoder.hash(domain, types, message)
console.log('EIP-712 hash:', hash) // 0xabcd...1234 (32 bytes)

// Sign the raw hash without EIP-191 prefix
const rawHashResult = await w3pk.signMessage(hash, {
  signingMethod: 'rawHash'
})
console.log('Raw hash signature:', rawHashResult.signature)

// Verify with recoverAddress (not verifyMessage!)
const recovered = recoverAddress(hash, rawHashResult.signature)
console.log('Recovered address:', recovered)
console.log('Matches signer:', recovered === rawHashResult.address)
```

**Use Cases:**

| Scenario | Mode | Tag | Signing Method | Purpose |
|----------|------|-----|----------------|---------|
| Wallet authentication | STANDARD | MAIN | EIP191 | Standard message signing |
| Web3 login (SIWE) | STANDARD | MAIN | SIWE | Sign-In with Ethereum |
| Token permit (gasless) | STANDARD | MAIN | EIP712 | EIP-2612 permit signature |
| DAO voting | STANDARD | MAIN | EIP712 | Off-chain voting signature |
| NFT allowlist | STANDARD | MAIN | EIP712 | Whitelist verification |
| Safe multisig transaction | YOLO | MAIN | rawHash | Pre-computed Safe EIP-712 hash |
| Banking app | STRICT | MAIN | EIP191 | View-only, requires auth each time |
| Gaming transactions | YOLO | GAMING | EIP191 | Full access, different address |
| Trading bot | YOLO | TRADING | EIP191 | Full access, isolated address |

---

### `signAuthorization(params: SignAuthorizationParams, options?: { requireAuth?: boolean }): Promise<EIP7702Authorization>`

Sign an EIP-7702 authorization for gasless transactions.

**Parameters:**

```typescript
params: {
  contractAddress: string;  // Contract to delegate to
  chainId?: number;         // Chain ID (default: 1)
  nonce?: bigint;           // Nonce (default: 0n)
  privateKey?: string;      // Optional: private key for derived/stealth addresses
}

options?: {
  requireAuth?: boolean;    // Force fresh authentication (default: false)
}
```

**Returns:**

```typescript
interface EIP7702Authorization {
  chainId: bigint;     // Chain ID
  address: string;     // Signer's address
  nonce: bigint;       // Nonce value
  yParity: number;     // Signature y parity (0 or 1)
  r: string;           // Signature r value (hex)
  s: string;           // Signature s value (hex)
}
```

**What is EIP-7702?**

EIP-7702 allows EOAs (Externally Owned Accounts) to **permanently delegate** code execution to a contract through authorization signatures. This enables:
- **Zero ETH required** - DAO treasury or sponsor pays all gas
- **Gasless transactions** - Users don't need gas tokens
- **One-time authorization** - Sign ONCE, use forever (until revoked)
- **Native protocol support** - Works on 329+ EVM chains

**What happens:**
1. User signs authorization offline (free)
2. Authorization is included in **first transaction** - establishes permanent delegation
3. All future transactions use the delegated contract code (no new authorization needed)
4. Sponsor pays gas costs for all transactions

**Security:** Uses active session or prompts for authentication if session expired.

**Example (Default Address):**

```typescript
// Sign with default address (account #0)
const authorization = await w3pk.signAuthorization({
  contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
  chainId: 11155111,  // Sepolia
  nonce: 0n
})

console.log('Authorization:', authorization)
// { chainId: 11155111n, address: '0x...', nonce: 0n, yParity: 1, r: '0x...', s: '0x...' }

// First transaction - establishes delegation permanently
import { walletClient } from 'viem'
const hash = await walletClient.sendTransaction({
  to: govContract,
  data: proposeData,
  authorizationList: [authorization]  // Only needed first time!
})

// All future transactions - NO authorization needed!
const hash2 = await walletClient.sendTransaction({
  to: govContract,
  data: voteData
  // No authorizationList - delegation persists!
})
```

**Example (Derived Address):**

```typescript
import { deriveWalletFromMnemonic } from 'w3pk'

// Get mnemonic from session
const mnemonic = await w3pk.exportMnemonic()

// Derive wallet at index 5
const { address, privateKey } = deriveWalletFromMnemonic(mnemonic, 5)

// Sign from derived address
const authorization = await w3pk.signAuthorization({
  contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
  chainId: 1,
  privateKey  // Use derived private key
})

console.log('Signed from:', authorization.address)
// Output: derived address at index 5
```

**Example (Stealth Address):**

```typescript
import { computeStealthPrivateKey, deriveStealthKeys } from 'w3pk'

// Get stealth keys
const mnemonic = await w3pk.exportMnemonic()
const { viewingKey, spendingKey } = deriveStealthKeys(mnemonic)

// Get ephemeral key from ERC-5564 announcement
const ephemeralPubKey = '0x...'  // From blockchain event

// Compute stealth private key
const stealthPrivateKey = computeStealthPrivateKey(
  viewingKey,
  spendingKey,
  ephemeralPubKey
)

// Sign from stealth address
const authorization = await w3pk.signAuthorization({
  contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
  chainId: 1,
  privateKey: stealthPrivateKey
})

console.log('Anonymous authorization from:', authorization.address)
```

**Example (Force Authentication):**

```typescript
// Force fresh biometric authentication for sensitive operations
const authorization = await w3pk.signAuthorization({
  contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
  chainId: 1
}, {
  requireAuth: true  // Prompt for WebAuthn even if session is active
})
```

**Revoking Authorization:**

```typescript
// To revoke delegation, sign new authorization to zero address
const revocation = await w3pk.signAuthorization({
  contractAddress: '0x0000000000000000000000000000000000000000',
  chainId: 11155111,
  nonce: currentNonce + 1n
})

// Send transaction with revocation
await walletClient.sendTransaction({
  to: userAddress,  // Send to self
  value: 0n,
  authorizationList: [revocation]
})

console.log('Delegation revoked!')
```

**Important Notes:**

⚠️ **CRITICAL:** EIP-7702 authorizations are **PERMANENT** until explicitly revoked!

- Only authorize audited, verified, trusted contracts
- Delegation persists across all transactions until revoked
- Verify contract address carefully before signing
- Use appropriate nonce values
- Monitor authorization usage on-chain

**Related Documentation:**
- [EIP-7702 Complete Guide](../docs/EIP_7702.md)
- [EIP-7702 Specification](https://eips.ethereum.org/EIPS/eip-7702)
- [Integration Examples](../examples/eip7702-authorization.ts)

---

### `requestExternalWalletDelegation(params: { chainId?: number; nonce?: bigint }): Promise<EIP7702Authorization>`

Request user to sign an EIP-7702 authorization using an external wallet (MetaMask, Rabby, etc.) to delegate their account to the current w3pk account.

This is a high-level convenience method that handles the entire flow of getting the user's w3pk address and requesting the external wallet to sign the delegation authorization.

**Parameters:**

```typescript
params: {
  chainId?: number;   // Chain ID for the authorization (default: 1)
  nonce?: bigint;     // Nonce for the authorization (default: 0n)
}
```

**Returns:** `EIP7702Authorization` - The signed authorization from the external wallet

**Use Cases:**
- Delegate external wallet accounts (MetaMask, Ledger, etc.) to w3pk for WebAuthn control
- Delegate ENS-linked addresses to w3pk for identity preservation
- Upgrade existing wallets to WebAuthn security without losing identity
- Enable gasless transactions for external wallet accounts
- Combine external wallet assets with w3pk's WebAuthn security

**Example:**

```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey()
await w3pk.register({ username: 'alice' })

// User signs with external wallet to delegate their account to w3pk
const authorization = await w3pk.requestExternalWalletDelegation({
  chainId: 1,
  nonce: 0n
})

console.log('External wallet authorized:', authorization)
// { chainId: 1n, address: '0x...w3pk...', nonce: 0n, yParity: 1, r: '0x...', s: '0x...' }

// Include in transaction to activate delegation
import { walletClient } from 'viem'
const hash = await walletClient.sendTransaction({
  to: w3pkAddress,
  value: 0n,
  authorizationList: [authorization]
})

// Now external wallet account is controlled by w3pk WebAuthn!
```

**What happens:**
1. Gets current w3pk account address (STANDARD + MAIN)
2. Detects external wallet provider (MetaMask, Rabby, etc.)
3. Requests user to sign EIP-7702 authorization
4. Returns authorization ready to include in transaction

**Security:**
- User must explicitly approve in their external wallet
- Authorization signature is verified before returning
- Only delegates to the current w3pk account address
- Delegation is permanent until revoked

**Related:**
- See [EIP_7702.md External Wallets](../docs/EIP_7702.md#external-wallets) for complete guide
- See [examples/ens-to-w3pk-delegation.ts](../examples/ens-to-w3pk-delegation.ts) for integration patterns

---

### `requestExternalWalletAuthorization(provider: EIP1193Provider, params: ExternalWalletAuthParams): Promise<EIP7702Authorization>`

Low-level API to request an external wallet to sign an EIP-7702 authorization. Use this when you need full control over the provider and parameters.

**Parameters:**

```typescript
interface EIP1193Provider {
  request(args: { method: string; params?: any[] }): Promise<any>
  on?(event: string, handler: (...args: any[]) => void): void
  removeListener?(event: string, handler: (...args: any[]) => void): void
}

params: {
  delegateToAddress: string;  // Address to delegate to (w3pk or any address)
  chainId?: number;           // Chain ID (default: 1)
  nonce?: bigint;             // Nonce (default: 0n)
  accountIndex?: number;      // Account index in wallet (default: 0)
}
```

**Returns:** `EIP7702Authorization`

**Example:**

```typescript
import { requestExternalWalletAuthorization } from 'w3pk'

// Get w3pk account
const w3pkAddress = await w3pk.getAddress()

// Request MetaMask to sign authorization
const authorization = await requestExternalWalletAuthorization(
  window.ethereum,
  {
    delegateToAddress: w3pkAddress,
    chainId: 1,
    nonce: 0n,
    accountIndex: 0  // Use first MetaMask account
  }
)

console.log('Authorization:', authorization)
```

**Use Cases:**
- Custom provider configuration
- Non-browser environments
- Multiple account delegation
- Integration with wallet SDKs

**Wallet Detection Utilities:**

```typescript
import {
  getDefaultProvider,
  detectWalletProvider,
  supportsEIP7702Authorization
} from 'w3pk'

// Get default provider
const provider = getDefaultProvider()
if (!provider) {
  console.error('No wallet detected')
}

// Detect wallet type
const walletName = detectWalletProvider(provider)
console.log('Wallet:', walletName) // "MetaMask", "Rabby", etc.

// Check EIP-7702 support
const supported = await supportsEIP7702Authorization(provider)
if (!supported) {
  console.warn('Wallet may not support signing')
}
```

**Related:**
- See [EIP_7702.md External Wallets](../docs/EIP_7702.md#external-wallets) for integration patterns
- See [examples/ens-to-w3pk-delegation.ts](../examples/ens-to-w3pk-delegation.ts) for usage examples

---

### `signMessageWithPasskey(message: string): Promise<PasskeySignatureResult>`

Sign a message directly with WebAuthn P-256 passkey for PRIMARY mode (EIP-7951 compatible).

Unlike `signMessage()` which uses secp256k1 ECDSA, this method uses the P-256 curve directly from WebAuthn. This is designed for account abstraction wallets that verify WebAuthn signatures on-chain.

**Parameters:**
- `message: string` - Message to sign

**Returns:** `PasskeySignatureResult`

```typescript
interface PasskeySignatureResult {
  signature: {
    r: string;      // Signature r component (hex)
    s: string;      // Signature s component (hex, low-s normalized)
  };
  messageHash: string;  // Original message hash (SHA-256)
  signedHash: string;   // WebAuthn signed hash (authenticatorData + clientDataHash)
  address: string;      // PRIMARY mode address (derived from P-256 public key)
  publicKey: {
    qx: string;     // Public key x-coordinate (hex)
    qy: string;     // Public key y-coordinate (hex)
  };
}
```

**What happens:**
1. Hashes the message with SHA-256
2. Requests WebAuthn signature using the passkey
3. WebAuthn signs: `SHA-256(authenticatorData || SHA-256(clientDataJSON))`
4. Extracts r and s from DER-encoded signature
5. Applies low-s normalization for Ethereum compatibility
6. Derives P-256 address using keccak256 (EIP-7951)
7. Returns signature components and public key coordinates

**Example:**

```typescript
// Sign message with passkey
const result = await w3pk.signMessageWithPasskey("Hello World")

console.log('Signature r:', result.signature.r)
console.log('Signature s:', result.signature.s)
console.log('Message hash:', result.messageHash)
console.log('Signed hash:', result.signedHash)
console.log('Address:', result.address)
console.log('Public key qx:', result.publicKey.qx)
console.log('Public key qy:', result.publicKey.qy)

// Use with account abstraction contract
await accountAbstractionContract.verifyWebAuthnSignature({
  message: "Hello World",
  r: result.signature.r,
  s: result.signature.s,
  qx: result.publicKey.qx,
  qy: result.publicKey.qy
})
```

**Key Differences from signMessage():**

| Feature | `signMessage()` | `signMessageWithPasskey()` |
|---------|----------------|---------------------------|
| Curve | secp256k1 | P-256 (WebAuthn native) |
| Private Key | Uses BIP39 mnemonic | Uses WebAuthn credential directly |
| Compatibility | Standard Ethereum wallets | Account abstraction (EIP-7951) |
| Signature Format | 65-byte compact (r,s,v) | DER-encoded, extracted r,s |
| Address Derivation | keccak256(secp256k1 pubkey) | keccak256(P-256 pubkey) |
| Low-s Normalization | Standard | P-256 curve order |

**Security:**
- Requires active user authentication (biometric/PIN)
- No private key exposure (uses WebAuthn credential directly)
- Signature is bound to the origin (RP ID hash verification)
- Counter validation prevents credential cloning

**Use Cases:**
- EIP-7951 account abstraction wallets
- WebAuthn-native smart contract wallets
- Hardware-backed signatures without seed phrases
- Passkey-first authentication flows

**Related Documentation:**
- [EIP-7951 Implementation Guide](../docs/EIP-7951.md)
- [EIP-7951 Specification](https://eips.ethereum.org/EIPS/eip-7951)

---

### `sendTransaction(tx, options?): Promise<TransactionResult>`

Send an on-chain transaction using the wallet derived for the active security mode.

Follows the exact same authentication and derivation flow as `signMessage()`: session management, mode/tag/origin resolution, and STRICT-mode re-authentication.

**Parameters:**

```typescript
tx: {
  to: string;                    // Recipient address
  value?: bigint;                // Value in wei (default: 0)
  data?: string;                 // Hex calldata (default: "0x")
  chainId: number;               // Required — no implicit default
  gasLimit?: bigint;             // Override gas limit (ethers auto-estimates if omitted)
  maxFeePerGas?: bigint;         // EIP-1559 max fee per gas
  maxPriorityFeePerGas?: bigint; // EIP-1559 max priority fee per gas
  nonce?: number;                // Override nonce (provider auto-fetches if omitted)
}

options?: {
  mode?: SecurityMode;    // 'STANDARD' | 'STRICT' | 'YOLO' (default: 'STANDARD')
  tag?: string;           // Wallet tag (default: 'MAIN')
  requireAuth?: boolean;  // Force fresh authentication (default: false)
  origin?: string;        // Override origin URL (testing only)
  rpcUrl?: string;        // Override RPC endpoint (required for PRIMARY mode)
}
```

**Returns:** `TransactionResult`

```typescript
interface TransactionResult {
  hash: string;           // Transaction hash
  from: string;           // Sender address (derived wallet)
  chainId: number;        // Chain ID used
  mode: SecurityMode;     // Security mode used
  tag: string;            // Tag used
  origin: string;         // Origin used
}
```

**RPC Resolution:**

The RPC endpoint is resolved in this order:
1. `options.rpcUrl` (explicit override)
2. First endpoint from `getEndpoints(tx.chainId)` (chainlist — 2390+ networks)
3. Throws `WalletError` if neither is available

**Sender address**

The transaction is always sent **from the address derived for the active mode, tag, and origin**. With no options the defaults are `mode: 'STANDARD'`, `tag: 'MAIN'`, `origin: window.location.origin`.

```
sender = getOriginSpecificAddress(mnemonic, window.location.origin, 'STANDARD', 'MAIN')
```

Use `getAddress()` to inspect the sender before calling `sendTransaction()`:

```typescript
const from = await w3pk.getAddress('STANDARD', 'MAIN')
console.log('will send from:', from)
```

**What happens:**
1. Guards: requires authenticated user
2. Resolves `effectiveMode`, `effectiveTag`, `origin` (defaults: `'STANDARD'`, `'MAIN'`, `window.location.origin`)
3. Sets `currentSecurityMode`
4. STRICT mode forces fresh authentication; other modes use active session
5. Derives sender wallet from mnemonic at the mode/tag/origin-specific index — this is the `from` address
6. Resolves RPC endpoint; throws if none found
7. Connects wallet to `JsonRpcProvider` and calls `sendTransaction()`
8. Returns `{ hash, from, chainId, mode, tag, origin }`

**Mode Summary:**

| Mode | Auth on call | Private key exposed | Gas source |
|------|-------------|---------------------|------------|
| STANDARD | Session (auto) | No | Sender address |
| STRICT | Always (biometric) | No | Sender address |
| YOLO | Session (auto) | Yes (internally) | Sender address |
| PRIMARY | — | Never | Not supported (throws) |

**Example:**

```typescript
// Check the sender address before sending
const from = await w3pk.getAddress('STANDARD', 'MAIN')
console.log('sending from:', from)

// Send 1 ETH — from = STANDARD + MAIN address for this origin
const result = await w3pk.sendTransaction({
  to: '0xRecipient...',
  value: 1n * 10n**18n,
  chainId: 1
})
console.log('tx hash:', result.hash)
console.log('from:', result.from)  // matches `from` above

// Contract call on Optimism with explicit RPC
const callResult = await w3pk.sendTransaction(
  {
    to: '0xContract...',
    data: '0xabcdef01',
    chainId: 10
  },
  {
    mode: 'STRICT',
    rpcUrl: 'https://mainnet.optimism.io'
  }
)

// YOLO mode — isolated gaming address on Base
const yoloTx = await w3pk.sendTransaction(
  { to: '0x...', value: 5n * 10n**17n, chainId: 8453 },
  { mode: 'YOLO', tag: 'GAMING' }
)

// EIP-1559 fee overrides
const priorityTx = await w3pk.sendTransaction({
  to: '0x...',
  chainId: 1,
  maxFeePerGas: 30n * 10n**9n,         // 30 gwei
  maxPriorityFeePerGas: 2n * 10n**9n,  // 2 gwei
  gasLimit: 21000n
})
```

**Error Cases:**

| Condition | Error |
|-----------|-------|
| Not authenticated | `WalletError: Must be authenticated to send transaction` |
| No RPC for chainId | `WalletError: No RPC endpoint found for chainId <N>. Pass options.rpcUrl.` |
| PRIMARY mode without rpcUrl | `WalletError: PRIMARY mode requires options.rpcUrl pointing to a bundler...` |
| PRIMARY mode (any) | `WalletError: PRIMARY mode sendTransaction is not yet supported.` |
| Node rejection | `WalletError: Failed to send transaction` (wraps original error) |

**Note on PRIMARY mode:** The P-256 WebAuthn key cannot produce a standard secp256k1 signature accepted by EVM nodes. Full PRIMARY support (via EIP-7702 delegation + bundler) is planned for a future release. Use `signMessageWithPasskey()` to obtain a P-256 signature and submit it via a bundler manually in the meantime.

---

### `getEIP1193Provider(options?): EIP1193ProviderInterface`

Return an [EIP-1193](https://eips.ethereum.org/EIPS/eip-1193) compatible provider backed by this SDK instance.

The returned object implements the standard `request({ method, params })` interface, making w3pk compatible with **ethers `BrowserProvider`**, **viem `custom` transport**, **wagmi connectors**, **RainbowKit**, and any other EIP-1193 consumer — without exposing private keys.

**Parameters:**

```typescript
options?: {
  mode?: SecurityMode;  // Security mode used for all operations (default: 'STANDARD')
  tag?: string;         // Wallet tag (default: 'MAIN')
  chainId?: number;     // Initial chainId reported by eth_chainId (default: 1)
  rpcUrl?: string;      // RPC override passed to eth_sendTransaction
}
```

**Returns:** An object with:

```typescript
interface EIP1193ProviderInterface {
  request(args: { method: string; params?: any[] }): Promise<any>;
  on(event: string, handler: (...args: any[]) => void): void;
  removeListener(event: string, handler: (...args: any[]) => void): void;
}
```

**Supported JSON-RPC methods:**

| Method | Returns | Notes |
|--------|---------|-------|
| `eth_accounts` | `string[]` | Derived address for the configured mode + tag |
| `eth_requestAccounts` | `string[]` | Same as `eth_accounts` |
| `eth_chainId` | `string` (hex) | Active chainId; updated by `wallet_switchEthereumChain` |
| `eth_sendTransaction` | `string` (tx hash) | Delegates to `sendTransaction()`; hex params auto-converted |
| `personal_sign` | `string` (sig) | EIP-191; hex-encoded data decoded to UTF-8 automatically |
| `eth_sign` | `string` (sig) | Legacy; same behaviour as `personal_sign` |
| `eth_signTypedData_v4` | `string` (sig) | EIP-712; `EIP712Domain` stripped automatically |
| `wallet_switchEthereumChain` | `null` | Updates active chainId and emits `chainChanged` |

**Events:**

| Event | Payload | Trigger |
|-------|---------|---------|
| `chainChanged` | `string` (hex chainId) | `wallet_switchEthereumChain` |

Unsupported methods throw `WalletError: w3pk EIP-1193: unsupported method "<method>"`.

**Example — ethers v6:**

```typescript
import { BrowserProvider, parseEther } from 'ethers'

await w3pk.login()
const provider = new BrowserProvider(w3pk.getEIP1193Provider({ chainId: 1 }))
const signer = await provider.getSigner()

// Send 1 ETH
const tx = await signer.sendTransaction({
  to: '0xRecipient...',
  value: parseEther('1')
})
console.log('hash:', tx.hash)

// Sign a message
const sig = await signer.signMessage('Hello World')
```

**Example — viem:**

```typescript
import { createWalletClient, custom, parseEther } from 'viem'
import { mainnet } from 'viem/chains'

await w3pk.login()
const client = createWalletClient({
  chain: mainnet,
  transport: custom(w3pk.getEIP1193Provider({ chainId: 1 }))
})

const [address] = await client.getAddresses()
const hash = await client.sendTransaction({
  account: address,
  to: '0xRecipient...',
  value: parseEther('1')
})
```

**Example — wagmi (custom connector):**

```typescript
import { injected } from 'wagmi/connectors'

const connector = injected({
  target() {
    return {
      id: 'w3pk',
      name: 'w3pk Passkey Wallet',
      provider: w3pk.getEIP1193Provider({ chainId: 1 })
    }
  }
})
```

**Example — chain switching:**

```typescript
const provider = w3pk.getEIP1193Provider({ chainId: 1 })

provider.on('chainChanged', (chainId) => {
  console.log('Switched to chain:', parseInt(chainId, 16))
})

await provider.request({
  method: 'wallet_switchEthereumChain',
  params: [{ chainId: '0xa' }]  // Optimism
})
```

**Notes:**
- Each call to `getEIP1193Provider()` returns a **new independent instance** with its own `chainId` state and event listeners.
- `eth_sendTransaction` hex fields (`value`, `gas`, `maxFeePerGas`, `maxPriorityFeePerGas`, `nonce`) are automatically converted to `bigint` / `number` before passing to `sendTransaction()`.
- `personal_sign` data that arrives as a `0x`-prefixed hex string is decoded to UTF-8, matching MetaMask's behaviour.

---

## Stealth Addresses (ERC-5564)

Enable stealth addresses in configuration:

```typescript
const w3pk = createWeb3Passkey({
  stealthAddresses: {}  // Enable with default config
})
```

All stealth address methods are accessed via `w3pk.stealth.*`

### `stealth.generateStealthAddress(options?: { requireAuth?: boolean }): Promise<StealthAddressResult>`

Generate a fresh ERC-5564 compliant stealth address for a recipient.

**Parameters:**
- `options.requireAuth?: boolean` - Force fresh authentication

**Returns:**

```typescript
interface StealthAddressResult {
  stealthAddress: string;       // One-time stealth address to send funds to
  ephemeralPublicKey: string;   // 33 bytes - publish on-chain for recipient
  viewTag: string;              // 1 byte - efficiency optimization for scanning
}
```

**Example:**

```typescript
// Sender: Generate stealth address for recipient
const announcement = await w3pk.stealth.generateStealthAddress()
console.log('Send funds to:', announcement.stealthAddress)
console.log('Publish ephemeral key:', announcement.ephemeralPublicKey)
console.log('View tag:', announcement.viewTag)

// On-chain: emit ERC5564Announcement event with these values
```

---

### `stealth.parseAnnouncement(announcement: Announcement, options?: { requireAuth?: boolean }): Promise<ParseAnnouncementResult>`

Parse an ERC-5564 announcement to check if it belongs to the current user.

**Parameters:**

```typescript
interface Announcement {
  stealthAddress: string;       // Stealth address from announcement
  ephemeralPublicKey: string;   // Ephemeral public key (33 bytes)
  viewTag: string;              // View tag (1 byte)
}
```

- `options.requireAuth?: boolean` - Force fresh authentication

**Returns:**

```typescript
interface ParseAnnouncementResult {
  isForUser: boolean;            // True if announcement is for you
  stealthAddress?: string;       // Only present if isForUser is true
  stealthPrivateKey?: string;    // Only present if isForUser is true - use to spend funds
}
```

**View Tag Optimization:** Uses 1-byte view tag for ~99% skip rate (255/256 false positives filtered).

**Example:**

```typescript
// Recipient: Check if announcement is for you
const result = await w3pk.stealth.parseAnnouncement({
  stealthAddress: '0x1234...',
  ephemeralPublicKey: '0x02abcd...',
  viewTag: '0xa4'
})

if (result.isForUser) {
  console.log('Payment received at:', result.stealthAddress)
  console.log('Private key to spend:', result.stealthPrivateKey)
  // Use stealthPrivateKey to create wallet and spend funds
}
```

---

### `stealth.scanAnnouncements(announcements: Announcement[], options?: { requireAuth?: boolean }): Promise<ParseAnnouncementResult[]>`

Efficiently scan multiple announcements to find payments for the current user.

**Parameters:**
- `announcements: Announcement[]` - Array of announcements from on-chain events
- `options.requireAuth?: boolean` - Force fresh authentication

**Returns:** Array of `ParseAnnouncementResult` containing only announcements that belong to the user.

**Performance:** View tags enable extremely efficient scanning (~99% skip rate).

**Example:**

```typescript
// Recipient: Scan all announcements from on-chain events
const announcements = [
  { stealthAddress: '0x111...', ephemeralPublicKey: '0x02aaa...', viewTag: '0x01' },
  { stealthAddress: '0x222...', ephemeralPublicKey: '0x02bbb...', viewTag: '0x42' },
  { stealthAddress: '0x333...', ephemeralPublicKey: '0x02ccc...', viewTag: '0xa4' },
  // ... 1000s more
]

const myPayments = await w3pk.stealth.scanAnnouncements(announcements)
console.log(`Found ${myPayments.length} payments`)

myPayments.forEach(payment => {
  console.log('Address:', payment.stealthAddress)
  console.log('Private key:', payment.stealthPrivateKey)
})
```

---

### `stealth.getKeys(options?: { requireAuth?: boolean }): Promise<StealthKeys>`

Get ERC-5564 stealth keys (spending and viewing keys).

**Parameters:**
- `options.requireAuth?: boolean` - Force fresh authentication

**Returns:**

```typescript
interface StealthKeys {
  stealthMetaAddress: string;   // 66 bytes (spending + viewing pubkeys)
  spendingPubKey: string;       // 33 bytes compressed public key
  viewingPubKey: string;        // 33 bytes compressed public key
  viewingKey: string;           // 32 bytes private viewing key
  spendingKey: string;          // 32 bytes private spending key
}
```

**Example:**

```typescript
const keys = await w3pk.stealth.getKeys()
console.log('Stealth meta-address:', keys.stealthMetaAddress)
console.log('Spending pubkey:', keys.spendingPubKey)
console.log('Viewing pubkey:', keys.viewingPubKey)
```

---

### `stealth.getStealthMetaAddress(options?: { requireAuth?: boolean }): Promise<string>`

Get the stealth meta-address for receiving funds. Share this publicly.

**Parameters:**
- `options.requireAuth?: boolean` - Force fresh authentication

**Returns:** `string` - ERC-5564 stealth meta-address (66 bytes: spending pubkey + viewing pubkey)

**Usage:** This is what you share publicly for others to send you stealth payments.

**Example:**

```typescript
// Recipient: Get your stealth meta-address to share
const metaAddress = await w3pk.stealth.getStealthMetaAddress()
console.log('Share this publicly:', metaAddress)
// Post this to ENS, on your website, in your bio, etc.
```

---

### `stealth.isAvailable: boolean` (property)

Check if stealth addresses are available (configured and dependencies loaded).

**Example:**

```typescript
if (w3pk.stealth?.isAvailable) {
  console.log('Stealth addresses enabled')
  const metaAddress = await w3pk.stealth.getStealthMetaAddress()
} else {
  console.log('Stealth addresses not configured')
}
```

---

## Zero-Knowledge Proofs

Enable ZK proofs in configuration:

```typescript
const w3pk = createWeb3Passkey({
  zkProofs: {
    enabledProofs: ['membership', 'threshold', 'range', 'ownership', 'nft']
  }
})
```

All ZK methods are accessed via `w3pk.zk.*`

### `zk.proveMembership(input: MembershipProofInput): Promise<ZKProof>`

Prove membership in a set without revealing which member you are.

**Use case:** Prove you're in a whitelist without revealing your identity.

**Parameters:**

```typescript
interface MembershipProofInput {
  value: string;              // Private: your actual value/identity
  pathIndices: number[];      // Private: position in merkle tree
  pathElements: string[];     // Private: merkle proof siblings
  root: string;               // Public: merkle root of the set
}
```

**Returns:** `ZKProof` object

**Example:**

```typescript
import { buildMerkleTree } from 'w3pk/zk/utils'

// Set of approved addresses
const members = ['0x111...', '0x222...', '0x333...']
const myAddress = '0x222...'
const myIndex = 1

// Build merkle tree
const leaves = members.map(addr => BigInt(addr).toString())
const { root, tree } = await buildMerkleTree(leaves)

// Generate merkle proof
const pathIndices = []
const pathElements = []
// ... compute merkle proof

// Generate ZK proof
const proof = await w3pk.zk.proveMembership({
  value: leaves[myIndex],
  pathIndices,
  pathElements,
  root
})

// Verify
const isValid = await w3pk.zk.verifyMembership(proof, root)
console.log('Membership proven:', isValid)
// You've proved you're in the set without revealing you're member #1!
```

---

### `zk.proveThreshold(input: ThresholdProofInput): Promise<ZKProof>`

Prove value exceeds threshold without revealing the actual value.

**Use case:** Prove balance > $1000 without revealing you have $5000.

**Parameters:**

```typescript
interface ThresholdProofInput {
  value: bigint;       // Private: actual value (e.g., 5000)
  blinding: bigint;    // Private: random blinding factor
  threshold: bigint;   // Public: threshold to prove against (e.g., 1000)
  commitment: string;  // Public: commitment to the value
}
```

**Returns:** `ZKProof` object

**Example:**

```typescript
import { generateBlinding } from 'w3pk/zk/utils'

const balance = 5000n
const threshold = 1000n
const blinding = generateBlinding()

// Create commitment
const commitment = await w3pk.zk.createCommitment(balance, blinding)

// Generate proof
const proof = await w3pk.zk.proveThreshold({
  value: balance,
  blinding,
  threshold,
  commitment
})

// Verify
const meetsThreshold = await w3pk.zk.verifyThreshold(
  proof,
  commitment,
  threshold
)
console.log('Balance > $1000:', meetsThreshold)
// Proved balance exceeds threshold without revealing $5000!
```

---

### `zk.proveRange(input: RangeProofInput): Promise<ZKProof>`

Prove value is within a range without revealing the exact value.

**Use case:** Prove age is 18-65 without revealing you're 25.

**Parameters:**

```typescript
interface RangeProofInput {
  value: bigint;       // Private: actual value (e.g., 25)
  blinding: bigint;    // Private: random blinding factor
  min: bigint;         // Public: minimum value (e.g., 18)
  max: bigint;         // Public: maximum value (e.g., 65)
  commitment: string;  // Public: commitment to the value
}
```

**Returns:** `ZKProof` object

**Example:**

```typescript
import { generateBlinding } from 'w3pk/zk/utils'

const age = 25n
const blinding = generateBlinding()
const commitment = await w3pk.zk.createCommitment(age, blinding)

// Generate range proof
const proof = await w3pk.zk.proveRange({
  value: age,
  blinding,
  min: 18n,
  max: 65n,
  commitment
})

// Verify
const inRange = await w3pk.zk.verifyRange(proof, commitment, 18n, 65n)
console.log('Age 18-65:', inRange)
// Proved age in range without revealing 25!
```

---

### `zk.proveOwnership(input: OwnershipProofInput): Promise<ZKProof>`

Prove ownership of an address without revealing the private key.

**Use case:** Prove you own an address without exposing credentials.

**Parameters:**

```typescript
interface OwnershipProofInput {
  privateKey: string;   // Private: private key
  nonce: bigint;        // Private: random nonce
  address: string;      // Public: Ethereum address to prove ownership of
  challenge: string;    // Public: challenge from verifier
}
```

**Returns:** `ZKProof` object

**Example:**

```typescript
const wallet = await w3pk.deriveWallet(0)
const challenge = '0x1234...' // From verifier

const proof = await w3pk.zk.proveOwnership({
  privateKey: wallet.privateKey,
  nonce: BigInt(Math.random() * 1e18),
  address: wallet.address,
  challenge
})

const isOwner = await w3pk.zk.verifyOwnership(proof, wallet.address, challenge)
console.log('Ownership proven:', isOwner)
```

---

### `zk.proveNFTOwnership(input: NFTOwnershipProofInput): Promise<ZKProof>`

Prove NFT ownership without revealing which NFT or exact address.

**Use case:** Prove you own a BAYC NFT without revealing which one or your address.

**Parameters:**

```typescript
interface NFTOwnershipProofInput {
  ownerAddress: string;        // Private: your address
  holderIndex: number;         // Private: position in holders tree
  pathIndices: number[];       // Private: merkle proof indices
  pathElements: string[];      // Private: merkle proof elements
  holdersRoot: string;         // Public: merkle root of NFT holders
  contractAddress: string;     // Public: NFT contract address
  minBalance?: bigint;         // Public: min token balance (default: 1)
}
```

**Returns:** `ZKProof` object

**Example:**

```typescript
import { generateNFTOwnershipProofInputs } from 'w3pk/zk/utils'

const nftContract = '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D' // BAYC
const allHolders = ['0x111...', '0x222...', '0x333...']
const yourAddress = '0x222...'

// Generate proof inputs
const { nftProofInput } = await generateNFTOwnershipProofInputs(
  yourAddress,
  nftContract,
  allHolders
)

// Generate proof
const proof = await w3pk.zk.proveNFTOwnership(nftProofInput)

// Verify
const isOwner = await w3pk.zk.verifyNFTOwnership(
  proof,
  nftContract,
  nftProofInput.holdersRoot,
  1n
)
console.log('NFT ownership proven:', isOwner)
// Proved NFT ownership without revealing which NFT or exact address!
```

---

### `zk.verify(proof: ZKProof): Promise<VerificationResult>`

Verify any ZK proof.

**Parameters:**
- `proof: ZKProof` - The proof to verify

**Returns:**

```typescript
interface VerificationResult {
  valid: boolean;
  type: ProofType;
  publicSignals: Record<string, any>;
  timestamp: number;
}
```

**Example:**

```typescript
const result = await w3pk.zk.verify(proof)
console.log('Proof valid:', result.valid)
console.log('Proof type:', result.type)
```

---

### `zk.verifyBatch(proofs: ZKProof[]): Promise<VerificationResult[]>`

Batch verify multiple proofs efficiently.

**Parameters:**
- `proofs: ZKProof[]` - Array of proofs to verify

**Returns:** Array of `VerificationResult`

**Example:**

```typescript
const results = await w3pk.zk.verifyBatch([proof1, proof2, proof3])
console.log('All valid:', results.every(r => r.valid))
```

---

### `zk.verifyMembership(proof: ZKProof, expectedRoot: string): Promise<boolean>`

Verify membership proof with expected merkle root.

**Example:**

```typescript
const isValid = await w3pk.zk.verifyMembership(proof, root)
```

---

### `zk.verifyThreshold(proof: ZKProof, expectedCommitment: string, expectedThreshold: bigint): Promise<boolean>`

Verify threshold proof.

**Example:**

```typescript
const meetsThreshold = await w3pk.zk.verifyThreshold(proof, commitment, 1000n)
```

---

### `zk.verifyRange(proof: ZKProof, expectedCommitment: string, expectedMin: bigint, expectedMax: bigint): Promise<boolean>`

Verify range proof.

**Example:**

```typescript
const inRange = await w3pk.zk.verifyRange(proof, commitment, 18n, 65n)
```

---

### `zk.verifyOwnership(proof: ZKProof, expectedAddress: string, expectedChallenge: string): Promise<boolean>`

Verify ownership proof.

**Example:**

```typescript
const isOwner = await w3pk.zk.verifyOwnership(proof, address, challenge)
```

---

### `zk.verifyNFTOwnership(proof: ZKProof, expectedContract: string, expectedHoldersRoot: string, expectedMinBalance?: bigint): Promise<boolean>`

Verify NFT ownership proof.

**Example:**

```typescript
const isOwner = await w3pk.zk.verifyNFTOwnership(proof, contract, root, 1n)
```

---

### `zk.createCommitment(value: bigint, blinding: bigint): Promise<string>`

Create a Pedersen commitment for hiding values in ZK proofs.

**Example:**

```typescript
import { generateBlinding } from 'w3pk/zk/utils'

const value = 5000n
const blinding = generateBlinding()
const commitment = await w3pk.zk.createCommitment(value, blinding)
```

---

### `zk.computeMerkleRoot(leaf: string, pathIndices: number[], pathElements: string[]): Promise<string>`

Compute merkle root from a leaf and proof path.

**Example:**

```typescript
const root = await w3pk.zk.computeMerkleRoot(leaf, pathIndices, pathElements)
```

---

### `zk.registerCircuit(type: ProofType, artifacts: CircuitArtifacts): void`

Register a custom circuit for proof generation.

**Parameters:**

```typescript
interface CircuitArtifacts {
  wasmPath: string;           // Path to circuit WASM file
  zkeyPath: string;           // Path to zkey file
  verificationKey: any;       // Verification key JSON
}
```

**Example:**

```typescript
w3pk.zk.registerCircuit('custom', {
  wasmPath: '/circuits/custom.wasm',
  zkeyPath: '/circuits/custom.zkey',
  verificationKey: customVKey
})
```

---

### `zk.isAvailable: boolean` (property)

Check if ZK proofs are available (configured and dependencies loaded).

**Example:**

```typescript
if (w3pk.zk?.isAvailable) {
  console.log('ZK proofs enabled')
  // Use ZK features
} else {
  console.log('ZK dependencies not installed')
  console.log('Run: npm install snarkjs circomlibjs')
}
```

---

## Backup & Recovery

### `getBackupStatus(): Promise<BackupStatus>`

Get comprehensive backup status showing what protects the wallet.

**Returns:**

```typescript
interface BackupStatus {
  passkeySync: PasskeySyncStatus;
  recoveryPhrase: RecoveryPhraseStatus;
  socialRecovery?: SocialRecoveryStatus;
  securityScore: SecurityScore;
}
```

**Example:**

```typescript
const status = await w3pk.getBackupStatus()
console.log('Security Score:', status.securityScore.score) // 0-100
console.log('Passkey sync:', status.passkeySync.enabled)
console.log('Recovery phrase:', status.recoveryPhrase.status)
console.log('Social recovery:', status.socialRecovery?.enabled)
```

---

### `createBackupFile(encryptionType?: 'password' | 'passkey' | 'hybrid', password?: string): Promise<{ blob: Blob; filename: string }>`

Create simplified backup file for wallet recovery.

This backup can be used to:
- Restore wallet with existing passkey
- Register new passkey with this wallet
- Sync wallet across devices
- Split among guardians for social recovery

**Parameters:**
- `encryptionType?: 'password' | 'passkey' | 'hybrid'` - Encryption method (default: 'password')
  - **'password'**: Encrypted with password only - can be restored on any device with password
  - **'passkey'**: Encrypted with passkey - can be restored on devices where passkey is synced
  - **'hybrid'**: Encrypted with both password AND passkey - maximum security
- `password?: string` - Required for 'password' and 'hybrid' encryption

**Returns:**

```typescript
{
  blob: Blob;       // Backup file as downloadable Blob
  filename: string; // Suggested filename for download
}
```

**Security:** Forces fresh authentication

**Example:**

```typescript
// Password-encrypted backup (default)
const { blob, filename } = await w3pk.createBackupFile('password', 'MySecurePassword123!')

// Download the backup
const url = URL.createObjectURL(blob)
const a = document.createElement('a')
a.href = url
a.download = filename
a.click()

// Passkey-encrypted backup (only works on devices where passkey is synced)
const passkeyBackup = await w3pk.createBackupFile('passkey')

// Hybrid backup (both password and passkey required)
const hybridBackup = await w3pk.createBackupFile('hybrid', 'MySecurePassword123!')
```

---

### `setupSocialRecovery(guardians: Guardian[], threshold: number): Promise<Guardian[]>`

Set up social recovery with M-of-N guardian shares using Shamir Secret Sharing.

**Parameters:**
- `guardians: Guardian[]`
  ```typescript
  interface Guardian {
    name: string;
    email?: string;
    phone?: string;
  }
  ```
- `threshold: number` - Number of guardians required to recover (M in M-of-N)

**Returns:** Array of guardians with encrypted shares

**Security:** Forces fresh authentication

**Example:**

```typescript
// Setup 3-of-5 social recovery
const guardians = await w3pk.setupSocialRecovery(
  [
    { name: 'Alice', email: 'alice@example.com' },
    { name: 'Bob', phone: '+1234567890' },
    { name: 'Charlie', email: 'charlie@example.com' },
    { name: 'Dave' },
    { name: 'Eve', email: 'eve@example.com' }
  ],
  3  // Need 3 guardians to recover
)

console.log('Social recovery configured with', guardians.length, 'guardians')
```

---

### `generateGuardianInvite(guardianId: string): Promise<GuardianInvite>`

Generate invitation for a guardian with their recovery share.

**Parameters:**
- `guardianId: string` - Guardian ID

**Returns:**

```typescript
interface GuardianInvite {
  guardianId: string;
  qrCode: string;        // Data URL for QR code
  shareCode: string;     // Text code for manual entry
  explainer: string;     // Educational text for guardian
  link?: string;         // Optional deep link
}
```

**Example:**

```typescript
const invite = await w3pk.generateGuardianInvite(guardian.id)

// Show QR code to guardian
console.log('Show this QR code to guardian:', invite.qrCode)
console.log('Or share this code:', invite.shareCode)
console.log('Instructions:', invite.explainer)
```

---

### `recoverFromGuardians(shares: string[]): Promise<RecoveryResult>`

Recover wallet from guardian shares (Shamir Secret Sharing).

**Parameters:**
- `shares: string[]` - Array of share data from guardians (JSON strings)

**Returns:**

```typescript
interface RecoveryResult {
  mnemonic: string;
  ethereumAddress: string;
}
```

**Example:**

```typescript
// Collect shares from 3 guardians
const shares = [
  aliceShare,  // JSON string from Alice
  bobShare,    // JSON string from Bob
  charlieShare // JSON string from Charlie
]

const { mnemonic, ethereumAddress } = await w3pk.recoverFromGuardians(shares)
console.log('Wallet recovered:', ethereumAddress)
console.log('Mnemonic:', mnemonic)

// Now import the mnemonic
await w3pk.importMnemonic(mnemonic)
```

---

### `restoreFromBackupFile(backupData: string | Blob, password?: string): Promise<{ mnemonic: string; ethereumAddress: string }>`

Restore wallet from backup file with existing passkey.

**Use case:** User has passkey synced to this device and wants to restore wallet from backup.

After restoration, the wallet is automatically associated with the current logged-in user. If not logged in, you can either:
- Call `importMnemonic()` to associate with current user
- Call `registerWithBackupFile()` to create new passkey for this wallet

**Parameters:**
- `backupData: string | Blob` - Backup file (JSON string or Blob)
- `password?: string` - Password (required for password/hybrid encrypted backups)

**Returns:**

```typescript
{
  mnemonic: string;
  ethereumAddress: string;
}
```

**Example:**

```typescript
// User is logged in with passkey
await w3pk.login()

// Restore from backup file
const backupData = '...' // From file upload or QR scanner

// Password-encrypted backup
const result = await w3pk.restoreFromBackupFile(backupData, 'MyPassword123!')
console.log('Wallet restored:', result.ethereumAddress)
// Wallet is automatically associated with current user

// Passkey-encrypted backup (no password needed)
const result2 = await w3pk.restoreFromBackupFile(backupData)
console.log('Wallet restored:', result2.ethereumAddress)
```

---

### `registerWithBackupFile(backupData: string | Blob, password: string, username: string): Promise<{ address: string; username: string }>`

Register new passkey with wallet from backup file.

**Use case:** Fresh device, user has backup file but no passkey yet. This creates a NEW passkey and associates it with the wallet from the backup.

**Parameters:**
- `backupData: string | Blob` - Backup file (JSON string or Blob)
- `password: string` - Password to decrypt the backup
- `username: string` - Username for the new passkey

**Returns:**

```typescript
{
  address: string;
  username: string;
}
```

**Example:**

```typescript
// Fresh device, no passkey yet
const backupData = '...' // From file upload

// Create new passkey from backup
const { address, username } = await w3pk.registerWithBackupFile(
  backupData,
  'MyPassword123!',
  'alice'
)

console.log('New passkey created for:', username)
console.log('Address:', address)
// User is now logged in and can use the wallet
```

**Note:** Only works with password-encrypted backups. For passkey-encrypted backups, use `restoreFromBackupFile()` instead.

---

## Cross-Device Sync

### `getSyncStatus(): Promise<SyncStatus>`

Get cross-device sync status for passkeys.

**Returns:**

```typescript
interface SyncStatus {
  enabled: boolean;
  devices: DeviceInfo[];
  lastSyncTime?: number;
  platform: 'apple' | 'google' | 'microsoft' | 'none';
}
```

**Example:**

```typescript
const syncStatus = await w3pk.getSyncStatus()
console.log('Sync enabled:', syncStatus.enabled)
console.log('Platform:', syncStatus.platform)
console.log('Devices:', syncStatus.devices.length)
```

---

### `detectSyncCapabilities(): Promise<SyncCapabilities>`

Detect available platform sync capabilities (iCloud, Google, Microsoft).

**Returns:**

```typescript
interface SyncCapabilities {
  passkeysSync: boolean;                              // Can passkeys sync?
  platform: 'apple' | 'google' | 'microsoft' | 'none'; // Which platform?
  estimatedDevices: number;                           // Estimated synced devices
  syncEnabled: boolean;                               // Is sync currently enabled?
}
```

**Example:**

```typescript
const capabilities = await w3pk.detectSyncCapabilities()

if (capabilities.platform === 'apple') {
  console.log('iCloud Keychain available')
} else if (capabilities.platform === 'google') {
  console.log('Google Password Manager available')
}

console.log('Estimated devices:', capabilities.estimatedDevices)
```

---

### `exportForSync(): Promise<{ blob: Blob; filename: string; qrCode?: string }>`

Export wallet for syncing to another device.

Uses passkey encryption so it works on devices where the passkey is synced.

**Use case:** User wants to sync wallet to another device that has the same passkey.

**Returns:**

```typescript
{
  blob: Blob;        // Sync file as downloadable Blob
  filename: string;  // Suggested filename
  qrCode?: string;   // Optional QR code data URL
}
```

**Security:** Forces fresh authentication

**Example:**

```typescript
const { blob, filename, qrCode } = await w3pk.exportForSync()

// Download sync file
const url = URL.createObjectURL(blob)
const a = document.createElement('a')
a.href = url
a.download = filename
a.click()

// Or display QR code for scanning on another device
if (qrCode) {
  const img = document.createElement('img')
  img.src = qrCode
  document.body.appendChild(img)
}
```

---

### `importFromSync(syncData: string | Blob): Promise<{ ethereumAddress: string; success: boolean }>`

Import wallet from another device (sync wallet to this device).

**Use case:** User has passkey on both devices, wallet only on one.

**Parameters:**
- `syncData: string | Blob` - Sync file data

**Returns:**

```typescript
{
  ethereumAddress: string;
  success: boolean;
}
```

**Example:**

```typescript
// User must be logged in first
await w3pk.login()

// Import from sync file
const syncData = '...' // From file upload or QR scan

const result = await w3pk.importFromSync(syncData)
console.log('Wallet synced:', result.ethereumAddress)
```

---

### `syncWalletWithPasskey(backupData: string | Blob, password?: string): Promise<{ mnemonic: string; ethereumAddress: string }>`

Sync wallet to this device using an existing cloud-synced passkey and a backup file. No prior session required.

**Use case:** New device that already has a passkey synced via iCloud/Google Password Manager. The user provides their backup file; the SDK prompts them to select the passkey, decrypts the backup, stores wallet data locally, and starts a session.

**Parameters:**
- `backupData: string | Blob` - Backup file content (JSON string or Blob)
- `password?: string` - Password to decrypt the backup (required for `password` and `hybrid` encryption methods)

**Returns:** `{ mnemonic: string; ethereumAddress: string }`

**Supported encryption methods:** `password`, `passkey`, `hybrid`

**Example:**

```typescript
// Passkey-encrypted backup (no password needed)
const result = await w3pk.syncWalletWithPasskey(backupData)
console.log('Synced wallet address:', result.ethereumAddress)

// Password or hybrid backup
const result2 = await w3pk.syncWalletWithPasskey(backupData, 'MyPassword123!')
console.log('Synced wallet address:', result2.ethereumAddress)
```

**Throws:**
- `WalletError` if password is required but not provided
- `WalletError` if passkey public key is not available on this device
- `WalletError` if backup uses an unknown encryption method

**Note:** Differs from `importFromSync()` in that it does not require a prior `login()` call and accepts any backup encryption method, not just passkey-encrypted sync exports.

---

## Session Management

w3pk provides two types of sessions:

1. **In-Memory Sessions** (default): Cached in RAM, cleared on page refresh
2. **Persistent Sessions** (opt-in): Encrypted in IndexedDB, survives page refresh

**Security Modes & Persistence:**
- **STANDARD mode**: Persistent sessions allowed ✅
- **YOLO mode**: Persistent sessions allowed ✅
- **STRICT mode**: Persistent sessions NEVER allowed ❌ (always requires fresh authentication)

### `hasActiveSession(): boolean`

Check if there's an active session with cached mnemonic.

**Example:**

```typescript
if (w3pk.hasActiveSession()) {
  console.log('Session active - no auth needed')
  await w3pk.signMessage('Hello')
} else {
  console.log('Session expired - will prompt for auth')
}
```

---

### `getSessionRemainingTime(): number`

Get remaining session time in seconds.

**Returns:** `number` - Seconds remaining (0 if no session or expired)

**Example:**

```typescript
const remaining = w3pk.getSessionRemainingTime()
console.log(`Session expires in ${remaining} seconds`)

if (remaining < 300) {
  console.log('Session expiring soon - consider extending')
  w3pk.extendSession()
}
```

---

### `extendSession(): void`

Extend current session by the configured duration.

**Throws:** Error if no active session or session already expired

**Example:**

```typescript
try {
  w3pk.extendSession()
  console.log('Session extended by', w3pk.sessionDuration, 'hours')
} catch (error) {
  console.log('Cannot extend - session expired')
}
```

---

### `clearSession(): Promise<void>`

Manually clear the active session (removes cached mnemonic from memory and deletes persistent session).

**Example:**

```typescript
// Clear session for security
await w3pk.clearSession()
console.log('Session cleared - next operation will require auth')

// Next operation prompts for authentication
await w3pk.signMessage('Hello')
```

---

### `setSessionDuration(hours: number): void`

Update session duration for future sessions.

**Parameters:**
- `hours: number` - Session duration in hours (0 to disable sessions)

**Example:**

```typescript
// Set 2-hour sessions
w3pk.setSessionDuration(2)

// Disable sessions (most secure - prompt every time)
w3pk.setSessionDuration(0)

// Set 24-hour sessions (less secure but convenient)
w3pk.setSessionDuration(24)
```

---

### Persistent Sessions ("Remember Me")

Enable persistent sessions to maintain user login across page refreshes.

**How it works:**
1. On login, mnemonic is encrypted with WebAuthn-derived key
2. Encrypted session stored in IndexedDB
3. On page refresh, session is automatically restored (if not expired)
4. `requireReauth: true` prompts for biometric on refresh (more secure)
5. `requireReauth: false` silently restores session (more convenient)

**Security:**
- Sessions only persist for STANDARD and YOLO modes
- STRICT mode sessions are NEVER persisted
- Encrypted at rest with WebAuthn-derived key
- Requires valid WebAuthn credential to decrypt
- Time-limited expiration
- Origin-isolated via IndexedDB

**Example:**

```typescript
// Enable persistent sessions (secure defaults)
const w3pk = createWeb3Passkey({
  persistentSession: {
    enabled: true,           // Enable "Remember Me"
    duration: 168,           // 7 days (in hours)
    requireReauth: true      // Prompt on page refresh
  }
})

// Full "Remember Me" experience (auto-restore)
const w3pk = createWeb3Passkey({
  persistentSession: {
    enabled: true,
    duration: 30 * 24,       // 30 days
    requireReauth: false     // Silent restore
  }
})

// Disable persistent sessions (most secure, default)
const w3pk = createWeb3Passkey({
  persistentSession: {
    enabled: false           // RAM-only sessions
  }
})

// Using STRICT mode (persistent sessions blocked)
const wallet = await w3pk.deriveWallet('STRICT')
// Even with persistentSession.enabled = true,
// STRICT mode sessions are NEVER persisted
```

---

## Blockchain Utilities

### `getEndpoints(chainId: number): Promise<string[]>`

Get public RPC endpoints for a chain from chainlist.

**Parameters:**
- `chainId: number` - Chain ID (e.g., 1 for Ethereum, 137 for Polygon)

**Returns:** Array of RPC URLs (filtered for quality)

**Example:**

```typescript
// Get Ethereum mainnet endpoints
const endpoints = await w3pk.getEndpoints(1)
console.log('Ethereum RPC:', endpoints[0])

// Other chains
const optimismRPCs = await w3pk.getEndpoints(10)
const arbitrumRPCs = await w3pk.getEndpoints(42161)
const baseRPCs = await w3pk.getEndpoints(8453)
const polygonRPCs = await w3pk.getEndpoints(137)

// Use with ethers.js
import { ethers } from 'ethers'
const provider = new ethers.JsonRpcProvider(endpoints[0])
const blockNumber = await provider.getBlockNumber()
```

---

### `supportsEIP7702(chainId: number, options?: EIP7702Options): Promise<boolean>`

Check if network supports EIP-7702 (set code for EOAs).

**Parameters:**
- `chainId: number` - Chain ID
- `options?: EIP7702Options`
  ```typescript
  interface EIP7702Options {
    maxEndpoints?: number;  // Max endpoints to test (default: 3)
    timeout?: number;       // Timeout in ms (default: 10000)
  }
  ```

**Returns:** `boolean` - True if EIP-7702 is supported

**Example:**

```typescript
// Check Ethereum mainnet
const supported = await w3pk.supportsEIP7702(1)
console.log('EIP-7702 supported:', supported)

// Check with custom options
const supportedQuick = await w3pk.supportsEIP7702(999, {
  maxEndpoints: 2,
  timeout: 5000
})
```

---

## Standalone Utilities

These functions can be imported directly from the package without an SDK instance.

### Validation Utilities

```typescript
import {
  validateEthereumAddress,
  validateUsername,
  validateMnemonic,
  isStrongPassword,
  assertEthereumAddress,
  assertUsername,
  assertMnemonic
} from 'w3pk'
```

#### `validateEthereumAddress(address: string): boolean`

Validate Ethereum address format.

```typescript
const valid = validateEthereumAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5')
console.log('Valid address:', valid) // true
```

---

#### `validateUsername(username: string): boolean`

Validate username (3-50 characters, alphanumeric + underscore + hyphen). Must start and end with a letter or number.

```typescript
const valid = validateUsername('alice-123')
console.log('Valid username:', valid) // true

// Also valid: alice_123, web3-user, my-user_name
// Invalid: -alice, alice-, _alice, alice_
```

---

#### `validateMnemonic(mnemonic: string): boolean`

Validate BIP39 mnemonic (12 or 24 words).

```typescript
const mnemonic = 'witch collapse practice feed shame open despair creek road again ice least'
const valid = validateMnemonic(mnemonic)
console.log('Valid mnemonic:', valid) // true
```

---

#### `isStrongPassword(password: string): boolean`

Validate password strength for backups.

**Requirements:**
- 12+ characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character
- Not a common password

```typescript
const password = 'MyS3cur3!Password@2042'
const strong = isStrongPassword(password)
console.log('Strong password:', strong) // true
```

---

#### `assertEthereumAddress(address: string): void`

Assert Ethereum address is valid (throws if invalid).

```typescript
try {
  assertEthereumAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5')
  console.log('Valid address')
} catch (error) {
  console.error('Invalid address:', error.message)
}
```

---

#### `assertUsername(username: string): void`

Assert username is valid (throws if invalid).

---

#### `assertMnemonic(mnemonic: string): void`

Assert mnemonic is valid (throws if invalid).

---

### Build Verification Utilities

```typescript
import {
  getCurrentBuildHash,
  getW3pkBuildHash,
  verifyBuildHash,
  getPackageVersion
} from 'w3pk'
```

#### `getCurrentBuildHash(): Promise<string>`

Compute IPFS CIDv1 hash for the currently installed w3pk version from unpkg CDN.

```typescript
const hash = await getCurrentBuildHash()
console.log('Build hash:', hash)
// => bafybeiafdhdxz3c3nhxtrhe7zpxfco5dlywpvzzscl277hojn7zosmrob4
```

---

#### `getW3pkBuildHash(distUrl: string): Promise<string>`

Compute IPFS hash for w3pk build from any URL.

```typescript
// From unpkg
const hash = await getW3pkBuildHash('https://unpkg.com/w3pk@0.7.6/dist')

// From your CDN
const hash = await getW3pkBuildHash('https://cdn.example.com/w3pk/dist')

// From local dev server
const hash = await getW3pkBuildHash('http://localhost:3000/dist')
```

---

#### `verifyBuildHash(expectedHash: string): Promise<boolean>`

Verify if the current build matches an expected hash.

```typescript
const trustedHash = 'bafybeiafdhdxz3c3nhxtrhe7zpxfco5dlywpvzzscl277hojn7zosmrob4'
const isValid = await verifyBuildHash(trustedHash)

if (isValid) {
  console.log('✅ Build integrity verified!')
} else {
  console.error('⚠️  Build hash mismatch - possible tampering')
}
```

---

#### `getPackageVersion(): string`

Get the current w3pk package version.

```typescript
const version = getPackageVersion()
console.log('Version:', version) // => 0.7.6
```

See [Build Verification Guide](./BUILD_VERIFICATION.md) for detailed documentation and integration examples.

---

### Base64 Encoding Utilities

```typescript
import {
  base64UrlToArrayBuffer,
  base64UrlDecode,
  arrayBufferToBase64Url,
  base64ToArrayBuffer,
  safeAtob,
  safeBtoa
} from 'w3pk'
```

#### `base64UrlToArrayBuffer(base64url: string): ArrayBuffer`

Decode base64url string to ArrayBuffer with automatic padding.

```typescript
const buffer = base64UrlToArrayBuffer('SGVsbG8gV29ybGQ')
console.log(new Uint8Array(buffer)) // [72, 101, 108, 108, 111, ...]
```

---

#### `base64UrlDecode(base64url: string): ArrayBuffer`

Alias for `base64UrlToArrayBuffer()` - decodes base64url to ArrayBuffer.

```typescript
const buffer = base64UrlDecode('SGVsbG8gV29ybGQ')
// Same as base64UrlToArrayBuffer()
```

---

#### `arrayBufferToBase64Url(buffer: ArrayBuffer): string`

Encode ArrayBuffer to URL-safe base64url string (no padding).

```typescript
const buffer = new TextEncoder().encode('Hello World')
const base64url = arrayBufferToBase64Url(buffer)
console.log(base64url) // => SGVsbG8gV29ybGQ
```

---

#### `base64ToArrayBuffer(base64: string): ArrayBuffer`

Decode standard base64 string to ArrayBuffer.

```typescript
const buffer = base64ToArrayBuffer('SGVsbG8gV29ybGQ=')
console.log(new Uint8Array(buffer))
```

---

#### `safeAtob(input: string): string`

Safely decode base64/base64url with automatic padding and format handling.

```typescript
const decoded = safeAtob('SGVsbG8gV29ybGQ')  // Works with or without padding
console.log(decoded) // => Binary string
```

---

#### `safeBtoa(input: string): string`

Safely encode binary string to base64 with Unicode support.

```typescript
const encoded = safeBtoa('Hello World')
console.log(encoded) // => SGVsbG8gV29ybGQ=
```

---

### Cryptographic Utilities

```typescript
import { extractRS } from 'w3pk'
```

#### `extractRS(derSignature: Uint8Array): { r: string; s: string }`

Extract r and s values from DER-encoded ECDSA signature with low-s normalization.

This function parses WebAuthn's DER-encoded P-256 signatures and applies low-s normalization required for Ethereum compatibility.

**Parameters:**
- `derSignature: Uint8Array` - DER-encoded signature from WebAuthn

**Returns:**
```typescript
{
  r: string;  // Hex-encoded r value (0x-prefixed, 64 chars)
  s: string;  // Hex-encoded s value (0x-prefixed, 64 chars, low-s normalized)
}
```

**Example:**

```typescript
// Get WebAuthn signature
const assertion = await navigator.credentials.get({
  publicKey: { /* ... */ }
}) as PublicKeyCredential

const response = assertion.response as AuthenticatorAssertionResponse
const derSignature = new Uint8Array(response.signature)

// Extract r and s components
const { r, s } = extractRS(derSignature)

console.log('r:', r) // 0x1234...
console.log('s:', s) // 0x5678...

// Use with smart contract verification
await contract.verifySignature(messageHash, r, s, publicKey)
```

**Low-s Normalization:**

The function automatically applies low-s normalization using the P-256 curve order:
```
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

If s > n/2, then s = n - s
```

This ensures compatibility with Ethereum's signature malleability protection.

**Related:**
- Used internally by `signMessageWithPasskey()`
- See [EIP-7951 Implementation Guide](../docs/EIP-7951.md)

---

### Wallet Generation Utilities

```typescript
import {
  generateBIP39Wallet,
  createWalletFromMnemonic,
  deriveWalletFromMnemonic
} from 'w3pk'
```

#### `generateBIP39Wallet(): { address: string; mnemonic: string }`

Generate a new BIP39 wallet.

```typescript
const { address, mnemonic } = generateBIP39Wallet()
console.log('Address:', address)
console.log('Mnemonic:', mnemonic)
```

---

#### `createWalletFromMnemonic(mnemonic: string): HDNodeWallet`

Create ethers.js wallet from mnemonic.

```typescript
import { createWalletFromMnemonic } from 'w3pk'

const wallet = createWalletFromMnemonic(mnemonic)
console.log('Address:', wallet.address)
```

---

#### `deriveWalletFromMnemonic(mnemonic: string, index: number): { address: string; privateKey: string }`

Derive HD wallet at specific index.

```typescript
const wallet0 = deriveWalletFromMnemonic(mnemonic, 0)
const wallet1 = deriveWalletFromMnemonic(mnemonic, 1)

console.log('Account 0:', wallet0.address)
console.log('Account 1:', wallet1.address)
```

---

### Stealth Address Utilities

```typescript
import {
  deriveStealthKeys,
  generateStealthAddress,
  checkStealthAddress,
  computeStealthPrivateKey,
  canControlStealthAddress
} from 'w3pk'
```

#### `deriveStealthKeys(mnemonic: string): StealthKeys`

Derive ERC-5564 stealth keys from mnemonic.

```typescript
const keys = deriveStealthKeys(mnemonic)
console.log('Stealth meta-address:', keys.stealthMetaAddress)
```

---

#### `generateStealthAddress(stealthMetaAddress: string): StealthAddressResult`

Generate stealth address for a recipient (standalone).

```typescript
const announcement = generateStealthAddress(recipientMetaAddress)
console.log('Send to:', announcement.stealthAddress)
```

---

#### `checkStealthAddress(viewingKey: string, spendingPubKey: string, ephemeralPubKey: string, stealthAddress: string, viewTag?: string): ParseResult`

Check if stealth address belongs to you (standalone).

```typescript
const result = checkStealthAddress(
  viewingKey,
  spendingPubKey,
  announcement.ephemeralPublicKey,
  announcement.stealthAddress,
  announcement.viewTag
)

if (result.isForUser) {
  console.log('Private key:', result.stealthPrivateKey)
}
```

---

#### `computeStealthPrivateKey(viewingKey: string, spendingKey: string, ephemeralPubKey: string): string`

Compute stealth private key for spending.

```typescript
const stealthPrivateKey = computeStealthPrivateKey(
  viewingKey,
  spendingKey,
  ephemeralPubKey
)
```

---

#### `canControlStealthAddress(viewingKey: string, spendingKey: string, spendingPubKey: string, ephemeralPubKey: string, stealthAddress: string, viewTag?: string): boolean`

Verify that you can control a stealth address by checking if your keys can derive the correct private key.

**Parameters:**
- `viewingKey: string` - Your viewing private key
- `spendingKey: string` - Your spending private key
- `spendingPubKey: string` - Your spending public key (compressed)
- `ephemeralPubKey: string` - Ephemeral public key from announcement
- `stealthAddress: string` - The stealth address to verify control of
- `viewTag?: string` - Optional view tag for optimization

**Returns:** `boolean` - True if you can control the stealth address

**Use case:** Verify you can spend funds from a stealth address before attempting a transaction.

```typescript
import { canControlStealthAddress, deriveStealthKeys } from 'w3pk'

// Get your stealth keys
const keys = deriveStealthKeys(mnemonic)

// Check if you can control a stealth address
const canControl = canControlStealthAddress(
  keys.viewingKey,
  keys.spendingKey,
  keys.spendingPubKey,
  announcement.ephemeralPublicKey,
  announcement.stealthAddress,
  announcement.viewTag
)

if (canControl) {
  console.log('You can spend from this stealth address')
  // Proceed with transaction
} else {
  console.log('This stealth address is not yours')
}
```

---

### Chainlist Utilities

These utilities are available both as standalone functions and as SDK instance methods.

```typescript
// Import as standalone functions
import {
  getEndpoints,
  getAllChains,
  getChainById,
  clearCache
} from 'w3pk'

// OR use as SDK instance methods
const endpoints = await w3pk.getEndpoints(1)
const supported = await w3pk.supportsEIP7702(1)
```

#### `getEndpoints(chainId: number, options?: ChainlistOptions): Promise<string[]>`

Get RPC endpoints (standalone).

```typescript
const endpoints = await getEndpoints(1)
```

---

#### `getAllChains(options?: ChainlistOptions): Promise<Chain[]>`

Get all chains from chainlist.

```typescript
const chains = await getAllChains()
console.log(`Found ${chains.length} chains`)
```

---

#### `getChainById(chainId: number, options?: ChainlistOptions): Promise<Chain | undefined>`

Get specific chain info.

```typescript
const chain = await getChainById(1)
console.log('Chain name:', chain?.name)
```

---

#### `clearCache(): void`

Clear chainlist cache.

```typescript
clearCache()
```

---

## Security Inspection

The w3pk SDK includes built-in tools for analyzing web3 applications to identify transaction and signing methods. This helps developers and end-users understand the security posture of dApps.

### Browser Inspection

Browser-based inspection analyzes the currently running web application by fetching JavaScript sources and extracting transaction-related code.

#### `inspect(options?: BrowserInspectOptions): Promise<BrowserInspectResult>`

Analyzes the current web application and returns a security report via Rukh API.

**Note:** API calls are sponsored by the [W3HC (Web3 Hackers Collective)](https://w3hc.org).

**Import:**

```typescript
import { inspect } from 'w3pk'
```

**Parameters:**

```typescript
interface BrowserInspectOptions {
  appUrl?: string;      // App URL to inspect (default: window.location.origin)
  rukhUrl?: string;     // Rukh API endpoint (default: 'https://rukh.w3hc.org')
  context?: string;     // Context for analysis (default: 'w3pk')
  model?: 'anthropic' | 'mistral' | 'openai';  // AI model (default: 'anthropic')
  focusMode?: 'transactions' | 'all';  // Focus mode (default: 'transactions')
}
```

**Returns:**

```typescript
interface BrowserInspectResult {
  report: string;           // Security report markdown
  analyzedFiles: string[];  // JavaScript files analyzed
  appUrl: string;          // URL that was inspected
}
```

**Example:**

```typescript
import { inspect } from 'w3pk'

// Inspect current application
const result = await inspect({
  appUrl: window.location.origin,
  rukhUrl: 'https://rukh.w3hc.org',
  model: 'anthropic',
  focusMode: 'transactions'
})

console.log('Security Report:')
console.log(result.report)
console.log(`Analyzed ${result.analyzedFiles.length} files`)
```

---

#### `inspectNow(options?: BrowserInspectOptions): Promise<void>`

Quick inspection helper that logs the security report directly to the browser console. Perfect for end-users running inspections from DevTools.

**Example:**

```typescript
import { inspectNow } from 'w3pk'

// Quick console inspection
await inspectNow()

// With custom options
await inspectNow({
  rukhUrl: 'https://rukh.w3hc.org',
  model: 'anthropic'
})
```

**Browser Console Usage:**

```javascript
// End-users can run this directly in browser console
await w3pk.inspectNow()
```

---

### Node.js Inspection

Node.js-based inspection scans local application files for security analysis during development or CI/CD.

#### `gatherCode(options?: InspectOptions): Promise<InspectResult>`

Scans application source files and generates a markdown document with collected code.

**Import:**

```typescript
import { gatherCode } from 'w3pk/inspect/node'
```

**Parameters:**

```typescript
interface InspectOptions {
  appPath?: string;              // Root directory (default: process.cwd())
  includePatterns?: string[];    // File patterns to include (default: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx', '**/*.json'])
  excludeDirs?: string[];        // Directories to exclude (default: ['node_modules', 'dist', '.next', '.git', 'build', 'coverage'])
  maxFileSizeKB?: number;        // Max file size in KB (default: 500)
  focusMode?: 'transactions' | 'all';  // Focus mode (default: 'all')
}
```

**Returns:**

```typescript
interface InspectResult {
  markdown: string;           // Generated markdown with code
  includedFiles: string[];    // Files that were included
  totalSizeKB: number;       // Total size in KB
}
```

**Example:**

```typescript
import { gatherCode } from 'w3pk/inspect/node'

const result = await gatherCode({
  appPath: '../my-dapp',
  focusMode: 'transactions',
  maxFileSizeKB: 500
})

console.log(`Collected ${result.includedFiles.length} files`)
console.log(`Total size: ${result.totalSizeKB} KB`)

// Save to file
await fs.writeFile('app-code.md', result.markdown)
```

---

#### `inspect(appPath, rukhUrl?, context?, model?, focusMode?): Promise<string>`

Inspects an application and returns a security report via Rukh API.

**Import:**

```typescript
import { inspect } from 'w3pk/inspect/node'
```

**Parameters:**

- `appPath: string` - Path to the application to inspect
- `rukhUrl?: string` - Rukh API endpoint (default: 'https://rukh.w3hc.org')
- `context?: string` - Context name (default: 'w3pk')
- `model?: 'anthropic' | 'mistral' | 'openai'` - AI model (default: 'anthropic')
- `focusMode?: 'transactions' | 'all'` - Focus mode (default: 'transactions')

**Returns:**

- `Promise<string>` - Markdown-formatted security report

**Example:**

```typescript
import { inspect } from 'w3pk/inspect/node'

const report = await inspect(
  '../genji-passkey',          // App path
  'https://rukh.w3hc.org',     // Rukh API
  'w3pk',                       // Context
  'anthropic',                  // Model
  'transactions'                // Focus mode
)

console.log('Security Report:')
console.log(report)

// Save report
await fs.writeFile('security-report.md', report)
```

**CLI Usage:**

```bash
# Create a simple script
cat > inspect.ts << 'EOF'
import { inspect } from 'w3pk/inspect/node'
const report = await inspect('../my-dapp')
console.log(report)
EOF

# Run with tsx
npx tsx inspect.ts > report.md
```

---

## Error Types

All errors extend from `Web3PasskeyError`:

```typescript
import {
  Web3PasskeyError,
  AuthenticationError,
  RegistrationError,
  WalletError,
  CryptoError,
  StorageError,
  ApiError
} from 'w3pk'
```

### Error Hierarchy

- `Web3PasskeyError` - Base error class
  - `AuthenticationError` - Authentication failures (login, session)
  - `RegistrationError` - Registration failures
  - `WalletError` - Wallet operations (derivation, signing)
  - `CryptoError` - Cryptographic operations (encryption, decryption)
  - `StorageError` - Storage operations (IndexedDB)
  - `ApiError` - API/network errors (RPC, chainlist)

### Error Handling

```typescript
import { AuthenticationError, WalletError } from 'w3pk'

try {
  await w3pk.login()
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.error('Authentication failed:', error.message)
  } else if (error instanceof WalletError) {
    console.error('Wallet error:', error.message)
  } else {
    console.error('Unknown error:', error)
  }
}
```

---

## Type Definitions

Key types exported from the package:

```typescript
// Core types
import type {
  Web3PasskeyConfig,
  StealthAddressConfig,
  ZKProofConfig,
  UserInfo,
  WalletInfo,
  RegisterResult
} from 'w3pk'

// Stealth address types
import type {
  StealthKeys,
  StealthAddressResult,
  Announcement,
  ParseAnnouncementResult
} from 'w3pk'

// Backup & Recovery types
import type {
  BackupStatus,
  SecurityScore,
  ZipBackupOptions,
  QRBackupOptions,
  QRBackupResult,
  RecoveryResult,
  RecoveryScenario,
  SimulationResult
} from 'w3pk'

// Social recovery types
import type {
  Guardian,
  GuardianInvite,
  SocialRecoveryConfig,
  RecoveryShare
} from 'w3pk'

// Sync types
import type {
  SyncStatus,
  SyncCapabilities,
  DeviceInfo
} from 'w3pk'

// ZK types
import type {
  ZKProof,
  ProofType,
  MembershipProofInput,
  ThresholdProofInput,
  RangeProofInput,
  OwnershipProofInput,
  NFTOwnershipProofInput,
  VerificationResult
} from 'w3pk'

// Blockchain types
import type {
  Chain,
  ChainlistOptions,
  EIP7702Options
} from 'w3pk'
```

---

## Education & Recovery Testing

### `getEducation(topic: string): Promise<any>`

Get educational content by topic.

**Parameters:**
- `topic: string` - Topic name (e.g., "passkey-sync", "backup-methods", "social-recovery")

**Returns:** Educational content object for the specified topic

**Example:**

```typescript
const explainer = await w3pk.getEducation('passkey-sync')
console.log(explainer.title)
console.log(explainer.content)
console.log(explainer.examples)
```

**Available Topics:**
- Use `getAllTopics()` standalone function to get list of all topics
- Use `searchExplainers(query)` standalone function to search topics

---

### `simulateRecoveryScenario(scenario: RecoveryScenario): Promise<SimulationResult>`

Simulate recovery scenario to test backup preparedness.

**Parameters:**

```typescript
interface RecoveryScenario {
  type: "lost-device" | "lost-phrase" | "lost-both" | "switch-platform";
  description: string;
}
```

**Returns:**

```typescript
interface SimulationResult {
  canRecover: boolean;
  methods: string[];
  recommendations: string[];
  risks: string[];
}
```

**Example:**

```typescript
const result = await w3pk.simulateRecoveryScenario({
  type: 'lost-device',
  description: 'Phone dropped in water, device destroyed'
})

console.log('Can recover:', result.canRecover)
console.log('Recovery methods:', result.methods)
console.log('Recommendations:', result.recommendations)
```

---

### `runRecoveryTest(): Promise<{ scenarios: any[]; overallScore: number; feedback: string }>`

Run interactive recovery test across multiple scenarios.

Tests wallet recovery preparedness by simulating various disaster scenarios.

**Returns:**

```typescript
{
  scenarios: Array<{
    name: string;
    canRecover: boolean;
    methods: string[];
  }>;
  overallScore: number;    // 0-100
  feedback: string;        // Personalized recommendations
}
```

**Example:**

```typescript
const test = await w3pk.runRecoveryTest()

console.log('Overall Score:', test.overallScore, '/ 100')
console.log('Feedback:', test.feedback)

test.scenarios.forEach(scenario => {
  console.log(`${scenario.name}: ${scenario.canRecover ? '✅' : '❌'}`)
  if (scenario.canRecover) {
    console.log('  Methods:', scenario.methods.join(', '))
  }
})
```

---

## Additional Resources

- [Quick Start Guide](./QUICK_START.md) - Get started in 5 minutes
- [Recovery & Backup System](./RECOVERY.md) - Three-layer backup architecture
- [ERC-5564 Stealth Addresses](./ERC5564_STEALTH_ADDRESSES.md) - Complete guide
- [Security Architecture](./SECURITY.md) - Integration best practices
- [Browser Compatibility](./BROWSER_COMPATIBILITY.md) - Supported browsers

---

## Need Help?

- GitHub Issues: [github.com/w3hc/w3pk/issues](https://github.com/w3hc/w3pk/issues)
- Demo: [w3pk.w3hc.org](https://w3pk.w3hc.org)
