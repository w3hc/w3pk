# w3pk API Reference

Complete reference for all methods, types, and utilities in the w3pk SDK.

## Table of Contents

- [Installation & Initialization](#installation--initialization)
- [Core Authentication](#core-authentication)
- [Wallet Management](#wallet-management)
  - [Origin-Specific Address Derivation](#origin-specific-address-derivation)
- [Stealth Addresses (ERC-5564)](#stealth-addresses-erc-5564)
- [Zero-Knowledge Proofs](#zero-knowledge-proofs)
- [Backup & Recovery](#backup--recovery)
- [Cross-Device Sync](#cross-device-sync)
- [Session Management](#session-management)
- [Blockchain Utilities](#blockchain-utilities)
- [Standalone Utilities](#standalone-utilities)
  - [Validation Utilities](#validation-utilities)
  - [Build Verification Utilities](#build-verification-utilities)
  - [Wallet Generation Utilities](#wallet-generation-utilities)
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
  stealthAddresses?: StealthAddressConfig;  // Enable stealth addresses
  zkProofs?: ZKProofConfig;          // Enable ZK proofs
}
```

**Example:**

```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey({
  debug: false,
  sessionDuration: 2,
  onAuthStateChanged: (isAuthenticated, user) => {
    console.log('Auth state:', isAuthenticated, user)
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

### `deriveWallet(indexOrTag?: number | string, options?: { requireAuth?: boolean; origin?: string }): Promise<WalletInfo>`

Unified wallet derivation supporting three modes:

1. **By index (number)**: Classic BIP44 derivation at `m/44'/60'/0'/0/{index}`
2. **By tag (string)**: Origin-specific derivation with custom tag (auto-detects current origin)
3. **Auto-detect (undefined)**: Origin-specific with MAIN tag (no parameters)

**Parameters:**
- `indexOrTag?: number | string` - HD index (number), tag (string), or undefined for auto
- `options.requireAuth?: boolean` - Force fresh authentication (default: false)
- `options.origin?: string` - Override origin URL (only for tag/auto modes, default: current origin)

**Returns:**

```typescript
interface WalletInfo {
  address: string;      // Ethereum address
  privateKey?: string;  // Private key (if available)
  index?: number;       // BIP44 index (for tag/auto modes)
  origin?: string;      // Origin URL (for tag/auto modes)
  tag?: string;         // Tag name (for tag/auto modes)
}
```

**Security:** Uses active session or prompts for authentication if session expired.

**Example:**

```typescript
// Mode 1: Classic index-based derivation
const wallet0 = await w3pk.deriveWallet(0)
const wallet1 = await w3pk.deriveWallet(1)
console.log('Account 0:', wallet0.address)
console.log('Account 1:', wallet1.address)

// Mode 2: Origin-specific with custom tag (auto-detects current website)
const gamingWallet = await w3pk.deriveWallet('GAMING')
console.log('Gaming wallet:', gamingWallet.address)
console.log('Tag:', gamingWallet.tag) // 'GAMING'
console.log('Origin:', gamingWallet.origin) // e.g., 'https://example.com'

const tradingWallet = await w3pk.deriveWallet('TRADING')
console.log('Trading wallet:', tradingWallet.address) // Different address

// Mode 3: Origin-specific with MAIN tag (no params)
const mainWallet = await w3pk.deriveWallet()
console.log('Main wallet:', mainWallet.address)
console.log('Tag:', mainWallet.tag) // 'MAIN'

// Force fresh authentication
const secureWallet = await w3pk.deriveWallet('SECURE', { requireAuth: true })

// Override origin (advanced use case)
const customWallet = await w3pk.deriveWallet('GAMING', {
  origin: 'https://custom-domain.com'
})
```

**Benefits:**
- Same API for both classic and origin-specific derivation
- Auto-detects current website origin
- Privacy-preserving by default (each origin gets unique addresses)
- Deterministic (same origin + tag = same address every time)

---

### Origin-Specific Address Derivation

Generate deterministic addresses per origin/website with optional tag support for different use cases.

#### `getOriginSpecificAddress(mnemonic: string, origin: string, tag?: string): Promise<OriginWalletInfo>`

Derives an origin-specific address from mnemonic with optional tag support.

**Parameters:**
- `mnemonic: string` - The BIP39 mnemonic phrase
- `origin: string` - The origin URL (e.g., "https://example.com")
- `tag?: string` - Optional tag to generate different addresses for same origin (default: "MAIN")

**Returns:**

```typescript
interface OriginWalletInfo {
  address: string;    // Ethereum address
  privateKey: string; // Private key
  index: number;      // BIP44 derivation index
  origin: string;     // Normalized origin
  tag: string;        // Normalized tag (uppercase)
}
```

**How it works:**
1. Normalizes the origin URL (lowercase, removes trailing slash, handles standard ports)
2. Combines origin and tag: `${origin}:${TAG}`
3. SHA-256 hashes the combined string
4. Derives deterministic index from hash (0 to 2^31-1)
5. Derives wallet at BIP44 path: `m/44'/60'/0'/0/{index}`

**Example:**

```typescript
import { getOriginSpecificAddress } from 'w3pk'

const mnemonic = 'test test test test test test test test test test test junk'

// Get MAIN address (default tag)
const mainWallet = await getOriginSpecificAddress(
  mnemonic,
  'https://example.com'
)
console.log('Main:', mainWallet.address)
// Returns: { address, privateKey, index: 33906495, origin: 'https://example.com', tag: 'MAIN' }

// Get GAMING-specific address
const gamingWallet = await getOriginSpecificAddress(
  mnemonic,
  'https://example.com',
  'GAMING'
)
console.log('Gaming:', gamingWallet.address)
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

##### `deriveIndexFromOriginAndTag(origin: string, tag?: string): Promise<number>`

Derives deterministic index from origin and tag.

**Example:**
```typescript
import { deriveIndexFromOriginAndTag } from 'w3pk'

const index = await deriveIndexFromOriginAndTag('https://example.com', 'GAMING')
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

### `signMessage(message: string, options?: { requireAuth?: boolean }): Promise<string>`

Sign a message with the wallet using ECDSA (EIP-191 compliant).

**Parameters:**
- `message: string` - Message to sign
- `options.requireAuth?: boolean` - Force fresh authentication (default: false)

**Returns:** `string` - Ethereum signature (hex string)

**What happens:**
1. Checks for active session - uses cached mnemonic if available
2. If no session - prompts for biometric authentication
3. Derives private key from mnemonic
4. Signs message using ECDSA (EIP-191)
5. Returns hex signature

**Example:**

```typescript
// Using session
const signature = await w3pk.signMessage('Hello World')
console.log('Signature:', signature)

// Force authentication for sensitive operation
const highValueSig = await w3pk.signMessage(
  'Transfer $10000 to 0x...',
  { requireAuth: true }
)
```

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

### `createZipBackup(password: string, options?: ZipBackupOptions): Promise<Blob>`

Create password-protected ZIP backup containing encrypted wallet.

**Parameters:**
- `password: string` - Strong password to encrypt backup
- `options?: ZipBackupOptions`
  ```typescript
  interface ZipBackupOptions {
    includeInstructions?: boolean;  // Include recovery instructions (default: true)
    deviceBinding?: boolean;        // Bind to device fingerprint (default: false)
  }
  ```

**Returns:** `Blob` - ZIP file containing encrypted backup

**Security:**
- Forces fresh authentication
- Validates password strength
- AES-GCM-256 encryption

**Example:**

```typescript
import { isStrongPassword } from 'w3pk'

const password = 'MyS3cur3!Password@2042'
if (!isStrongPassword(password)) {
  throw new Error('Password too weak')
}

const zipBlob = await w3pk.createZipBackup(password, {
  includeInstructions: true
})

// Save to file system
const url = URL.createObjectURL(zipBlob)
const a = document.createElement('a')
a.href = url
a.download = 'w3pk-backup.zip'
a.click()
```

---

### `createQRBackup(password?: string, options?: QRBackupOptions): Promise<QRBackupResult>`

Create QR code backup for easy recovery.

**Parameters:**
- `password?: string` - Optional password to encrypt QR code
- `options?: QRBackupOptions`
  ```typescript
  interface QRBackupOptions {
    errorCorrection?: 'L' | 'M' | 'Q' | 'H';  // QR error correction level (default: 'M')
  }
  ```

**Returns:**

```typescript
interface QRBackupResult {
  qrCodeDataURL: string;  // Data URL for QR code image
  instructions: string;   // Recovery instructions text
}
```

**Security:** Forces fresh authentication

**Example:**

```typescript
const { qrCodeDataURL, instructions } = await w3pk.createQRBackup('password', {
  errorCorrection: 'H'
})

// Display QR code
const img = document.createElement('img')
img.src = qrCodeDataURL
document.body.appendChild(img)

console.log(instructions)
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

### `restoreFromBackup(backupData: string, password: string): Promise<RecoveryResult>`

Restore wallet from encrypted ZIP backup.

**Parameters:**
- `backupData: string` - Backup file contents (JSON string from ZIP)
- `password: string` - Password used to encrypt the backup

**Returns:**

```typescript
interface RecoveryResult {
  mnemonic: string;
  ethereumAddress: string;
}
```

**Example:**

```typescript
// Read backup file
const file = await fileInput.files[0].text()
const password = prompt('Enter backup password')

const { mnemonic, ethereumAddress } = await w3pk.restoreFromBackup(file, password)
console.log('Wallet restored:', ethereumAddress)

// Import the mnemonic
await w3pk.importMnemonic(mnemonic)
```

---

### `restoreFromQR(qrData: string, password?: string): Promise<RecoveryResult>`

Restore wallet from QR code backup.

**Parameters:**
- `qrData: string` - Scanned QR code data (JSON string)
- `password?: string` - Optional password if QR was encrypted

**Returns:**

```typescript
interface RecoveryResult {
  mnemonic: string;
  ethereumAddress: string;
}
```

**Example:**

```typescript
// Scan QR code
const qrData = '...' // From QR scanner

const { mnemonic, ethereumAddress } = await w3pk.restoreFromQR(qrData, 'password')
console.log('Wallet restored:', ethereumAddress)

// Import the mnemonic
await w3pk.importMnemonic(mnemonic)
```

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

## Session Management

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

### `clearSession(): void`

Manually clear the active session (removes cached mnemonic from memory).

**Example:**

```typescript
// Clear session for security
w3pk.clearSession()
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
// => bafybeifysgwvsyog2akxjk4cjky2grqqyzfehamuwyk6zy56srgkc5jopi
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
const trustedHash = 'bafybeifysgwvsyog2akxjk4cjky2grqqyzfehamuwyk6zy56srgkc5jopi'
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

```typescript
import {
  getEndpoints,
  getAllChains,
  getChainById,
  clearCache
} from 'w3pk/chainlist'
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
