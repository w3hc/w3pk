# w3pk API Reference

Complete reference for all methods, types, and utilities in the w3pk SDK.

## Table of Contents

- [Installation & Initialization](#installation--initialization)
- [Core Authentication](#core-authentication)
- [Wallet Management](#wallet-management)
  - [Origin-Specific Address Derivation](#origin-specific-address-derivation)
  - [`sendTransaction()`](#sendtransactiontx-options-promisetransactionresult)
  - [`getEIP1193Provider()`](#geteip1193provideroptions-eip1193providerinterface)
  - [`derivePrfSecret()`](#deriveprfsecrettag-string-promiseprfsecret)
  - [`getSemaphoreIdentity()`](#getsemaphoreidentitytag-string-promisesemaphoreidentity)
  - [`zkProve()`](#zkprovetag-artifacts-publicinputs-extrawitness-options-promisezkproveresult)
- [Stealth Addresses (ERC-5564)](#stealth-addresses-erc-5564)
- [Zero-Knowledge Proofs](#zero-knowledge-proofs)
- [Backup & Recovery](#backup--recovery)
- [Cross-Device Sync](#cross-device-sync)
  - [`getSyncStatus()`](#getsyncstatus-promisedevicesyncinfo--null)
  - [`syncWalletWithPasskey()`](#syncwalletwithpasskeybackupdata-string--blob-password-string-options--allowaddresschange-boolean--promise-ethereumaddress-string-)
- [Session Management](#session-management)
- [Blockchain Utilities](#blockchain-utilities)
- [Standalone Utilities](#standalone-utilities)
  - [Validation Utilities](#validation-utilities)
  - [Build Verification Utilities](#build-verification-utilities)
  - [Post-Quantum Cryptography](#post-quantum-cryptography)
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
  storage?: Storage;                  // Custom storage backend (default: localStorage)
  sessionDuration?: number;           // Session duration in hours (default: 1)
  persistentSession?: Partial<PersistentSessionConfig>;  // Enable "Remember Me" functionality
  stealthAddresses?: StealthAddressConfig;  // Enable stealth addresses
  zkProofs?: ZKProofConfig;          // Enable ZK proofs
  userVerification?: 'required' | 'preferred';  // WebAuthn user verification (default: 'required')
  rpcUrls?: Record<number, string[]>;  // RPC endpoints per chain ID; sendTransaction() requires one for the chain
  smartAccount?: { factoryAddress?: string; initCodeHash?: string };  // PRIMARY smart account factory (default: W3PK_ACCOUNT_FACTORY, W3PK_ACCOUNT_INIT_CODE_HASH)
}

interface PersistentSessionConfig {
  enabled: boolean;       // Enable persistent sessions (default: false)
  duration: number;       // Duration in hours (default: 168 = 7 days)
  requireReauth: boolean; // Require re-auth on page refresh (default: true)
}
```

**PRF requirement:** persistent sessions are encrypted under a key derived from the WebAuthn PRF extension, which the authenticator only releases during a user-verified assertion. On authenticators without PRF support, no persistent session is stored — the device falls back to in-memory sessions only (there is no weaker at-rest fallback). The session is re-keyed at every real (prompted) login; the configured `duration` is therefore also the renewal interval. With `requireReauth: true` the decryption key is never written to disk; with `requireReauth: false` it is stored next to the blob in localStorage to allow silent restore. See [SECURITY.md](./SECURITY.md#at-rest-encryption-what-it-protects-and-what-it-doesnt) for the full model.

**User verification:** `userVerification` sets the WebAuthn [user verification](https://www.w3.org/TR/webauthn-3/#user-verification) requirement for `register()` and `login()`; PRIMARY `signMessage()` always asks for `'required'`, since the account checks the UV flag. With `'required'` (the default), every prompt asks for a biometric or PIN. With `'preferred'`, authenticators that can skip the check, such as security keys and unlocked password managers, sign in with one click; the authenticator decides, not the app. Registration accepts any authenticator either way: a built-in one, a phone through a QR code, a security key or a password manager. PRF calls (`derivePrfSecret()`, PRF device sync) always require user verification, since an unverified assertion would return a different PRF output. A login whose assertion isn't user-verified gets an in-memory session only, never a persistent one.

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

// One-click sign-in where the authenticator allows it
const w3pkOneClick = createWeb3Passkey({
  userVerification: 'preferred'
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
  hasBackup: boolean;   // false for a new wallet: prompt for a backup now
  evictionRisk: boolean; // true where the browser may wipe the wallet (WebKit tab, storage not persisted)
}
```

**What happens:**
1. Generates BIP39 mnemonic (12 words) if no wallet exists
2. Creates WebAuthn credential (triggers biometric prompt)
3. Derives Ethereum wallet from mnemonic (path: m/44'/60'/0'/0/0)
4. Encrypts mnemonic using WebAuthn credential (AES-GCM-256)
5. Stores encrypted wallet in localStorage, next to the credential metadata
6. Starts 1-hour session with decrypted mnemonic in memory
7. Returns Ethereum address, username, whether a backup exists and whether the browser may wipe the wallet

**Example:**

```typescript
const { address, username, hasBackup, evictionRisk } = await w3pk.register({
  username: 'alice'
})
console.log('Registered:', username, 'with address:', address)

if (!hasBackup) {
  showBackupPrompt({ blocking: evictionRisk }) // see getBackupStatus()
}
```

---

### `login(): Promise<UserInfo>`

Authenticate user with WebAuthn (passwordless, usernameless).

**Returns:**

```typescript
interface UserInfo {
  username: string;        // Username
  ethereumAddress: string; // Ethereum address
  credentialId: string;    // Passkey credential ID
}
```

**What happens:**
1. Retrieves credential ID from localStorage
2. Triggers WebAuthn authentication (biometric prompt)
3. Retrieves encrypted wallet from localStorage
4. Decrypts mnemonic using WebAuthn signature
5. Starts new session (1 hour by default)
6. Returns user info
7. Subsequent operations use cached session - no repeated biometric prompts

**Throws:**
- `SyncRequiredError` if the passkey authenticated but this device has no credential metadata for it (carries `credentialId`); start a sync with `syncWalletWithPasskey()` and a password backup
- `WalletMissingError` if the credential metadata is here but the wallet record is gone (carries `credentialId` and `ethereumAddress`); restore with `syncWalletWithPasskey()` or `importFromSync()`

In both cases the user is not logged in and `onAuthStateChanged(true, …)` is not called.

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

### `storagePersisted: boolean | null` (property)

Whether the browser granted persistent storage. w3pk calls `navigator.storage.persist()` after each register, login and restore without waiting for it. `true` means the origin's storage is exempt from storage-pressure eviction. `null` until the browser answers (Firefox asks the user), or where the API is missing.

Persisted storage still doesn't survive Safari's 7-day cap, clearing site data or private browsing: see [SECURITY.md → Storage durability](./SECURITY.md#storage-durability-what-can-still-wipe-the-wallet).

**Example:**

```typescript
await w3pk.login()
if (w3pk.storagePersisted === false) {
  console.warn('Storage may be evicted: make sure the user has a backup')
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

Use `wallets.length > 0` to check whether the device has a wallet, and `wallets.length` to count them.

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

### `deriveWallet(mode?: SecurityMode, tag?: string, options?: { requireAuth?: boolean }): Promise<DerivedWallet>`

Origin-centric wallet derivation with three security modes:

**Security Modes:**
- **`STANDARD` (default)**: Address only (no private key), persistent sessions allowed
- **`STRICT`**: Address only (no private key), no persistent sessions (requires auth each time)
- **`YOLO`**: Full access (address + private key), persistent sessions allowed
- **`PRIMARY`**: Address of the passkey's P-256 smart account for the tag, deployed or not, and the passkey's `publicKey` (no private key)

**Parameters:**
- `mode?: SecurityMode` - Security mode: 'PRIMARY' | 'STANDARD' | 'STRICT' | 'YOLO' (default: 'STANDARD')
- `tag?: string` - Tag for derivation (default: 'MAIN')
- `options.requireAuth?: boolean` - Force fresh authentication (default: false)

**Returns:**

```typescript
interface DerivedWallet {
  address: string;       // Ethereum address
  privateKey?: string;   // Private key (only in YOLO mode)
  path?: string;         // BIP-32 derivation path
  origin?: string;       // Origin URL
  mode?: SecurityMode;   // Security mode used
  tag?: string;          // Tag name
  publicKey?: string;    // P-256 public key (PRIMARY mode)
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
```

**Security Benefits:**
- Origin-centric: Each origin gets unique addresses
- Mode-based private key access control
- STRICT mode prevents session-based attacks
- Deterministic (same origin + mode + tag = same address every time)
- Privacy-preserving by default

---

### `getAddress(mode?: SecurityMode, tag?: string): Promise<string>`

Lightweight method to get the public address for a specific security mode and tag without exposing private keys or creating full wallet objects.

**Parameters:**
- `mode?: SecurityMode` - Security mode: 'PRIMARY' | 'STANDARD' | 'STRICT' | 'YOLO' (default: 'STANDARD')
- `tag?: string` - Tag for derivation (default: 'MAIN')

**Returns:** `Promise<string>` - The Ethereum address for this mode/tag combination

**Example:**

```typescript
// Get default STANDARD + MAIN address
const mainAddr = await w3pk.getAddress()
console.log('Main address:', mainAddr)

// Get PRIMARY address (the passkey's P-256 smart account, one per tag)
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
  path: string;           // BIP-32 derivation path
  origin: string;         // Normalized origin
  mode: SecurityMode;     // Security mode used
  tag: string;            // Normalized tag (uppercase)
}
```

**How it works:**
1. Normalizes the origin URL (lowercase, removes trailing slash, handles standard ports)
2. Uppercases the tag
3. Builds the fully hardened path `m/13'/A'/B'/C'/D'/mode'/tag'` with `deriveOriginPath()`
4. Derives the wallet at that path from the mnemonic's root
5. Exposes private key only in YOLO mode

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

##### `deriveOriginPath(origin: string, mode?: SecurityMode, tag?: string): Promise<string>`

Derives the BIP-32 path of an origin, security mode and tag: `m/13'/A'/B'/C'/D'/mode'/tag'`, every level hardened.

- `A'/B'/C'/D'`: [SLIP-0013](https://github.com/satoshilabs/slips/blob/master/slip-0013.md) service identity of the normalized origin with index 0: the first 16 bytes of `SHA-256(LE32(0) ‖ origin)`, as four little-endian uint32
- `mode'`: `STANDARD`=0', `STRICT`=1', `YOLO`=2', `PRIMARY`=3'
- `tag'`: first 4 bytes of `SHA-256(TAG)` (tag uppercased), big-endian, low 31 bits

**Parameters:**
- `origin: string` - The origin URL (e.g., "https://example.com")
- `mode?: SecurityMode` - Security mode (default: 'STANDARD')
- `tag?: string` - Tag, case-insensitive (default: "MAIN")

**Returns:** `Promise<string>` - The derivation path

**Example:**
```typescript
import { deriveOriginPath } from 'w3pk'

const path = await deriveOriginPath('https://example.com', 'YOLO', 'GAMING')
console.log(path) // m/13'/645184497'/1329031'/2055466046'/1660046646'/2'/152488895'
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

No key controls this address. PRIMARY mode uses `getSmartAccountAddress()` instead.

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

---

##### `getSmartAccountAddress(publicKeySpki: string, tag?: string, config?: SmartAccountConfig): Promise<string>`

Counterfactual CREATE2 address of the passkey's `W3pkAccount` for a tag, as `W3pkAccountFactory.getAddress` returns it, deployed or not. No RPC call. `getAddress('PRIMARY', tag)` and `deriveWallet('PRIMARY', tag)` return it.

**Parameters:**
- `publicKeySpki: string` - Public key in SPKI format (base64url encoded)
- `tag?: string` - Account tag (default: 'MAIN')
- `config?: { factoryAddress?: string; initCodeHash?: string }` - Overrides of `W3PK_ACCOUNT_FACTORY` and `W3PK_ACCOUNT_INIT_CODE_HASH`

**Returns:** `Promise<string>` - Checksummed address

The salt is `getSmartAccountSalt(qx, qy, tag)`, `keccak256(abi.encode(qx, qy, keccak256(bytes(tag))))`, with `qx` and `qy` from `getP256Coordinates(publicKeySpki)`. Each tag gives its own account, and accounts of the same passkey are linkable onchain through their shared owner.

```typescript
import { getSmartAccountAddress } from 'w3pk'

const main = await getSmartAccountAddress(publicKeySpki)
const gaming = await getSmartAccountAddress(publicKeySpki, 'GAMING')
```

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

### `importMnemonic(mnemonic: string): Promise<void>`

Import a mnemonic phrase as the logged-in passkey's wallet, replacing the stored one.

**Parameters:**
- `mnemonic: string` - Valid BIP39 mnemonic (12 to 24 words, checksum checked)

**Behavior:**
- One passkey assertion with the logged-in passkey releases the key the wallet is stored under
- The imported wallet replaces the passkey's wallet record; the passkey, `user` and the session then point at its address. If pointing the passkey at it fails, the previous record is put back
- The previous wallet's persistent session is deleted before anything is stored, so a remember-me session can't restore the replaced mnemonic
- `onAuthStateChanged(true, user)` fires with the new address
- Replacing the wallet needs no `allowAddressChange`: importing is an explicit replace, so the app confirms it with the user before calling
- Make sure the previous wallet's recovery phrase or a backup is saved first: its encrypted mnemonic is deleted from this device

**Throws:**
- `WalletError` if not logged in, or the phrase isn't a valid BIP39 mnemonic (before any prompt), or another passkey answers the prompt
- `AuthenticationError` if the prompt is cancelled, `PrfUnsupportedError` if the authenticator returns no PRF output: the stored wallet and the passkey stay as they were

**Example:**

```typescript
const recoveredMnemonic = 'witch collapse practice feed shame open despair creek road again ice least'
await w3pk.importMnemonic(recoveredMnemonic)
console.log(w3pk.user?.ethereumAddress) // the imported wallet's address
```

---

### `signMessage(message: string | Uint8Array, options?: SignMessageOptions): Promise<SignatureResult>`

Sign a message with the wallet using ECDSA with configurable signing methods.

By default, signs with **STANDARD mode + MAIN tag** (origin-centric address) using **EIP-191**.
You can specify a different mode, tag, and signing method to customize the signature.

**Parameters:**
- `message: string | Uint8Array` - Message to sign (or hash for rawHash method, JSON for EIP712); bytes are signed as-is and only with EIP191
- `options.mode?: SecurityMode` - Security mode: 'PRIMARY' | 'STANDARD' | 'STRICT' | 'YOLO' (default: 'STANDARD')
- `options.tag?: string` - Tag for derivation (default: 'MAIN')
- `options.requireAuth?: boolean` - Force fresh authentication (default: false)
- `options.signingMethod?: SigningMethod` - Signing method: 'EIP191' | 'SIWE' | 'EIP712' | 'rawHash' (default: 'EIP191'; rawHash throws in PRIMARY mode)
- `options.chainId?: number` - PRIMARY mode: chain the signature is bound to. Required for EIP191; SIWE reads the message's `Chain ID` and EIP712 `eip712Domain.chainId` when it's not set
- `options.rpcUrl?: string` - PRIMARY mode: RPC endpoint used to check whether the account is deployed (default: the first `rpcUrls` endpoint for the chain)
- `options.eip712Domain?: TypedDataDomain` - EIP-712 domain separator (ethers' [`TypedDataDomain`](https://docs.ethers.org/v6/api/hashing/#TypedDataDomain)) (required for EIP712 method)
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
- The message's `domain` must match the current origin (host and port, and scheme when the domain names one), or `signMessage()` throws. The same check runs on an `EIP191` message, a string or UTF-8 bytes, that contains the SIWE header, including hex `personal_sign` and `eth_sign` data through the EIP-1193 provider; bytes that contain the header but aren't valid UTF-8 throw
- `validateSiweMessage()` always checks `Expiration Time` and `Not Before`, and requires RFC 3339 dates
- In PRIMARY mode, the chain comes from the message's `Chain ID`

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
- Always prompts for a fresh user-verified passkey assertion, even during an active session: the hash could be an EIP-7702 authorization digest

**PRIMARY mode:**

The passkey signs as its [P-256 smart account](./EIP-7951.md#primary-smart-account), whose address `result.address` is. There is no key to keep in a session, so every call prompts for a fresh user-verified passkey assertion.

- EIP-191 and SIWE messages are signed as an [ERC-7739](https://eips.ethereum.org/EIPS/eip-7739) `PersonalSign`, EIP-712 messages as a `TypedDataSign`, both under the account's EIP-712 domain (`W3pkAccount`, `1`, the chain, the account). A signature for one account or chain doesn't verify on another.
- The account checks them in `isValidSignature(hash, signature)` ([EIP-1271](https://eips.ethereum.org/EIPS/eip-1271)), with `hash` the message's EIP-191 or EIP-712 hash, as any verifier computes it.
- If the account isn't deployed, or no RPC endpoint is set for the chain, the signature is wrapped as [ERC-6492](https://eips.ethereum.org/EIPS/eip-6492): verifiers that support it deploy the account through the factory, then call `isValidSignature`. A contract calling `isValidSignature` directly needs the bare signature: deploy the account and set `rpcUrls` or `options.rpcUrl`.
- `rawHash` throws: a bare hash through EIP-1271 would skip ERC-7739's replay protection.

```typescript
const { signature, address } = await w3pk.signMessage('Hello World', { mode: 'PRIMARY', chainId: 1 })

const siwe = await w3pk.signMessage(siweMessage, { mode: 'PRIMARY', signingMethod: 'SIWE' })
```

**Verifying on a backend:** PRIMARY signatures come from a contract, so `ethers.verifyMessage()` and `verifySiweSignature()` can't recover them. viem's [`verifyMessage`](https://viem.sh/docs/actions/public/verifyMessage) and [`verifyTypedData`](https://viem.sh/docs/actions/public/verifyTypedData) on a public client verify EOA, ERC-1271 and ERC-6492 signatures alike, so one call covers every mode:

```typescript
import { createPublicClient, http } from 'viem'
import { mainnet } from 'viem/chains'

const client = createPublicClient({ chain: mainnet, transport: http() })

const valid = await client.verifyMessage({ address, message, signature })
const validTyped = await client.verifyTypedData({ address, domain, types, primaryType, message, signature })
```

Use a client for the chain the message was signed for: the signature doesn't verify on another chain.

**What happens:**
1. Derives wallet based on mode and tag (PRIMARY: see above)
2. Checks for active session (unless STRICT mode or rawHash forces auth)
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

### `signAuthorization(params: SignAuthorizationParams, options?: { mode?: SecurityMode; tag?: string }): Promise<EIP7702Authorization>`

Sign an EIP-7702 authorization for gasless transactions.

**Parameters:**

```typescript
params: {
  contractAddress: string;  // Contract to delegate to
  chainId?: number;         // Chain ID (default: 1)
  nonce?: bigint;           // Nonce (default: 0n)
}

options?: {
  mode?: SecurityMode;      // Signing wallet's mode: 'STANDARD' | 'STRICT' | 'YOLO' (default: 'STANDARD'; 'PRIMARY' is refused)
  tag?: string;             // Signing wallet's tag (default: 'MAIN')
}
```

**Returns:**

```typescript
interface EIP7702Authorization {
  chainId: bigint;     // Chain ID
  address: string;     // Delegated contract address (not the signer)
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

**Security:** Every call prompts for a fresh user-verified passkey assertion, even during an active session, and signs with the origin-specific derived key for `mode` and `tag` (the same address `sendTransaction()` uses), never the master key at `m/44'/60'/0'/0/0`. It takes no private key. `PRIMARY` mode is refused: its P-256 passkey address has no secp256k1 key.

YOLO keys are exposed by design: `deriveWallet('YOLO', tag)` returns the private key, so any script holding it can sign a delegation for that address without w3pk.

**Example (Origin-Derived Address):**

```typescript
// Sign with this origin's STANDARD MAIN address (prompts for the passkey)
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

**Example (Mode and Tag):**

```typescript
// Sign from this origin's YOLO GAMING address
const authorization = await w3pk.signAuthorization({
  contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
  chainId: 1
}, {
  mode: 'YOLO',
  tag: 'GAMING'
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

### `derivePrfSecret(tag: string): Promise<PrfSecret>`

Derive a 32-byte secret bound to the passkey, separate per origin and tag, for an identity in an anonymous protocol or a per-feature encryption key.

It uses the [WebAuthn PRF extension](https://w3c.github.io/webauthn/#prf-extension): the authenticator holds a per-credential secret and releases `PRF(input)` only on a live, user-verified assertion. The secret is never derived from or stored with the mnemonic.

**Parameters:**
- `tag: string` - Non-empty label without `:`, such as `"zk-identity"`. Case-sensitive.

**Returns:** `PrfSecret`

```typescript
interface PrfSecret {
  secret: Uint8Array;    // 32 bytes
  credentialId: string;  // passkey the secret is bound to
}
```

**What happens:**
1. Prompts for the passkey with `userVerification: "required"`; when logged in, only the current user's passkey is allowed, otherwise the user picks one
2. Evaluates the PRF at `SHA-256("w3pk-prf-v1:" + origin + ":" + tag)`, with `origin` the normalized current origin (the browser further hashes it with the `"WebAuthn PRF"` context)
3. Returns `HKDF-SHA256(PRF output, salt "w3pk-prf-secret-v1", info "w3pk-prf-v1:" + origin + ":" + tag)`, 32 bytes

The same passkey, origin and tag always give the same secret. A different tag, origin or passkey gives an unrelated one. Store `credentialId` next to whatever the secret protects: when it changes (a new passkey), so does the secret.

**Example:**

```typescript
import { PrfUnsupportedError } from 'w3pk'

try {
  const { secret, credentialId } = await w3pk.derivePrfSecret('zk-identity')
  // Use the secret, keep it in memory only
} catch (error) {
  if (error instanceof PrfUnsupportedError) {
    // This authenticator can't provide a passkey-bound secret
  }
}
```

**Throws:**
- `PrfUnsupportedError` (`code: 'PRF_UNSUPPORTED'`, with `credentialId`) if the authenticator returns no PRF output. There is no fallback.
- `AuthenticationError` if the prompt is cancelled or the passkey isn't available
- `CryptoError` if `tag` is empty or contains `:`

**Threat model:**
- **Not in backups.** The secret depends only on the authenticator's PRF, so backup files, recovery phrases, social recovery shares and sync exports don't contain it, and their leak doesn't leak it.
- **Not stored.** w3pk never writes the secret or the PRF output to localStorage or sessions, and zeroes its copy of the PRF output after the derivation. Each call prompts the user. If the app stores the secret, its storage is the weakest link.
- **Bound to the passkey, not the wallet.** Restoring the wallet from a backup with a different passkey gives a different secret. The secret survives only as long as the passkey: a synced passkey (iCloud Keychain, Google Password Manager) carries it to other devices, a deleted or device-bound passkey loses it. Anything encrypted under it must be recoverable another way.
- **Origin separation is w3pk's, not the browser's.** Passkeys are scoped to the RP ID (the hostname), so another origin on the same hostname (another port or scheme) can use the same passkey. The origin in the PRF input keeps `derivePrfSecret()` from giving one origin another's secret, but a script running on such an origin can evaluate the PRF itself with any input. Serve one app per hostname when that matters.
- **Script on the origin.** Code running on the page (XSS, a compromised dependency) can call `derivePrfSecret()` or the PRF directly and get the secret after the user approves a prompt. User verification bounds it to a user action, not to the app's intent.
- **Separate from the persistent session key.** That key uses a different PRF input, so no tag gives it.
- **Separate from Semaphore identities and `zkProve()`.** [`getSemaphoreIdentity()`](#getsemaphoreidentitytag-string-promisesemaphoreidentity) and [`zkProve()`](#zkprovetag-artifacts-publicinputs-extrawitness-options-promisezkproveresult) use different PRF inputs, so no tag gives their secrets.

---

### `getSemaphoreIdentity(tag: string): Promise<SemaphoreIdentity>`

Get the commitment of a [Semaphore v4](https://docs.semaphore.pse.dev/guides/identities) identity bound to the passkey, for anonymous voting, signalling or rate-limited posting. The identity's private key is a PRF secret that never leaves w3pk: it isn't returned, stored, or in backups.

Requires the optional dependency [`@semaphore-protocol/identity`](https://www.npmjs.com/package/@semaphore-protocol/identity), imported only when the method is called.

**Parameters:**
- `tag: string` - Non-empty label without `:`, such as `"voting"`. Case-sensitive.

**Returns:** `SemaphoreIdentity`

```typescript
interface SemaphoreIdentity {
  commitment: bigint;    // Poseidon(publicKey), the group member value
  credentialId: string;  // passkey the identity is bound to
}
```

**What happens:**
1. Loads `@semaphore-protocol/identity`
2. Derives a 32-byte private key as [`derivePrfSecret()`](#deriveprfsecrettag-string-promiseprfsecret) does, with the label `w3pk-semaphore-v1` instead of `w3pk-prf-v1`: PRF input `SHA-256("w3pk-semaphore-v1:" + origin + ":" + tag)`, then HKDF-SHA256 with salt `w3pk-prf-secret-v1` and the same string as info
3. Returns `new Identity(privateKey).commitment` and zeroes the private key

The same passkey, origin and tag always give the same commitment, equal to `@semaphore-protocol/identity`'s for that private key. A different tag, origin or passkey gives an unrelated identity.

**Rotation:** a new passkey gives a new commitment. Store `credentialId` with the commitment you add to a group; when a later call returns another `credentialId`, update the member (`group.updateMember`) or add the new commitment.

**Example:**

```typescript
import { Group } from '@semaphore-protocol/group'

const group = new Group()
const { commitment, credentialId } = await w3pk.getSemaphoreIdentity('voting')
group.addMember(commitment)
```

**Throws:**
- `PrfUnsupportedError` if the authenticator returns no PRF output
- `AuthenticationError` if the prompt is cancelled or the passkey isn't available
- `CryptoError` if `@semaphore-protocol/identity` isn't installed (before any prompt), or if `tag` is empty or contains `:`

**Threat model:** the same as `derivePrfSecret()`'s, plus:
- **Out of reach of `derivePrfSecret()`.** The label differs, so `derivePrfSecret(tag)` returns a different secret for every tag, and an app can't rebuild the identity through the public API. Code running on the origin can still evaluate the PRF directly with the identity's input.
- **Proofs use the secret inside w3pk.** This method returns the commitment only; [`zkProve()`](#zkprovetag-artifacts-publicinputs-extrawitness-options-promisezkproveresult) with `secret: 'semaphore'` proves with the identity's `secretScalar` without returning it.

---

### `zkProve(tag, artifacts, publicInputs, extraWitness?, options?): Promise<ZkProveResult>`

Make a Groth16 proof with a secret bound to the passkey, without the app ever seeing the secret, the values derived from it, or the proof's randomness. See [ZK.md](./ZK.md#proving-with-a-passkey-bound-secret) for the design.

Requires the optional dependency `snarkjs`, plus `poseidon-lite` when `options.derive` is set and `@semaphore-protocol/identity` when `options.secret` is `'semaphore'`.

**Parameters:**
- `tag: string` - Non-empty label without `:`, such as `"voting"`. Case-sensitive.
- `artifacts: ZkProveArtifacts` - `{ wasm, zkey, pins }`: the circuit's `.wasm` and `.zkey` as bytes or URLs, and their pinned CIDs (see [`verifyZkArtifacts`](./ZK.md#circuit-artifact-verification))
- `publicInputs: ZkInputs` - The circuit's public inputs, by signal name
- `extraWitness?: ZkInputs` - Other private inputs the app provides
- `options?: ZkProveOptions`

```typescript
type ZkSignal = bigint | number | string | ZkSignal[];
type ZkInputs = Record<string, ZkSignal>;

interface ZkProveOptions {
  secret?: 'zk' | 'semaphore';                 // default 'zk'
  secretInput?: string;                        // default 'secret'
  derive?: Record<string, (string | bigint)[]>; // name -> Poseidon terms
  random?: string[];                           // inputs filled with fresh random scalars
}

interface ZkProveResult {
  proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[]; protocol: string; curve: string };
  publicSignals: string[];
}
```

**What happens:**
1. Checks `tag`, the inputs and `options`; loads the dependencies; verifies the artifacts against `pins`; starts the proving worker. Any failure here comes before the prompt
2. Derives the secret: for `'zk'`, a 32-byte PRF secret as [`derivePrfSecret()`](#deriveprfsecrettag-string-promiseprfsecret) does but with the label `w3pk-zk-v1`, turned into a Baby Jubjub private key with `deriveBabyJubKeyPair()`; for `'semaphore'`, the `secretScalar` of the identity [`getSemaphoreIdentity(tag)`](#getsemaphoreidentitytag-string-promisesemaphoreidentity) commits to
3. Builds the witness: the caller's inputs, the secret under `secretInput`, a fresh scalar in `[1, l)` for each `random` name, then each `derive` entry as `Poseidon(terms)` in order
4. Proves with snarkjs in a Web Worker (in-thread where `Worker` doesn't exist or the worker can't start)
5. Refuses the proof if a public signal equals the secret or a random input; otherwise returns `{ proof, publicSignals }`

**Example:**

```typescript
const { proof, publicSignals } = await w3pk.zkProve(
  'voting',
  { wasm: wasmUrl, zkey: zkeyUrl, pins },
  { proposalId, root },
  { vote: 1 },
  { secret: 'semaphore', derive: { voteSecret: ['secret', 'proposalId', 1n] }, random: ['r'] }
)
```

**Throws:**
- `ZkArtifactMismatchError` if an artifact's CID differs from its pin (before any prompt)
- `PrfUnsupportedError` if the authenticator returns no PRF output
- `AuthenticationError` if the prompt is cancelled or the passkey isn't available
- `CryptoError` for an invalid tag, inputs or options, a missing dependency (all before any prompt), a failed proof, or a circuit that makes the secret or a random input public

**Threat model:** the same as `derivePrfSecret()`'s, plus:
- **Out of the API, not out of reach.** w3pk runs in the app's JavaScript context: an honest app can't leak the secret or keep a receipt of the randomness, but malicious code on the page can still evaluate the PRF with the same input or read the witness in memory. The [cross-origin wallet](https://github.com/w3hc/w3pk/issues/156) isolates it fully.
- **Out of reach of `derivePrfSecret()`.** Both secret sources use their own labels, so no tag returns them.
- **The circuit decides what's public.** Derived values may be public signals (e.g. a nullifier); w3pk only refuses proofs that publish the secret or a random input as is. A circuit can output any other function of the secret (its bits, `secret + 1`, a weak hash), the Semaphore `secretScalar` included, so only prove with circuits you trust: the pins guarantee which circuit runs, not that it keeps the secret private.

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
2. First endpoint set for the chain in the `rpcUrls` config
3. Otherwise throws `WalletError` naming `rpcUrls`, before any passkey prompt

chainid.network endpoints are never used to send: the chosen RPC supplies the nonce, gas estimate and fee data, so a public endpoint could make the user overpay or censor the transaction. Set `rpcUrls` to endpoints you trust:

```typescript
const w3pk = createWeb3Passkey({
  rpcUrls: { 1: ['https://eth.example.com'], 10: ['https://op.example.com'] }
})
```

**Sender address**

The transaction is always sent **from the address derived for the active mode, tag, and origin**. With no options the defaults are `mode: 'STANDARD'` and `tag: 'MAIN'`; the origin is always `window.location.origin`.

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
3. Resolves the RPC endpoint; throws if the app set none for the chain
4. STRICT mode forces fresh authentication; other modes use active session
5. Derives sender wallet from mnemonic at the mode/tag/origin-specific path — this is the `from` address
6. Connects wallet to `JsonRpcProvider` and calls `sendTransaction()`
7. Returns `{ hash, from, chainId, mode, tag, origin }`

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
| Not authenticated | `WalletError: Failed to send transaction: Must be authenticated to send transaction` |
| No `rpcUrls` or `rpcUrl` for chainId | `WalletError: Failed to send transaction: No RPC endpoint set for chainId <N>. Set rpcUrls in the config (rpcUrls: { <N>: ['https://...'] }) or pass options.rpcUrl.` |
| PRIMARY mode without rpcUrl | `WalletError: Failed to send transaction: PRIMARY mode requires options.rpcUrl pointing to a bundler...` |
| PRIMARY mode (any) | `WalletError: Failed to send transaction: PRIMARY mode sendTransaction is not yet supported.` |
| Node rejection | `WalletError: Failed to send transaction: <reason>` (original error in `originalError`) |

**Note on PRIMARY mode:** The P-256 WebAuthn key cannot produce a standard secp256k1 signature accepted by EVM nodes. Full PRIMARY support (via EIP-7702 delegation + bundler) is planned for a future release. Message signing works in PRIMARY mode: see `signMessage()`.

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
  rpcUrl?: string;      // RPC override passed to eth_sendTransaction (else rpcUrls for the active chain, required)
}
```

**Returns:** An object with:

```typescript
// import type { EIP1193ProviderInterface } from 'w3pk'
interface EIP1193ProviderInterface {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  // One overload per EIP-1193 event; removeListener takes the same pairs
  on(event: 'accountsChanged', handler: (accounts: string[]) => void): void;
  on(event: 'chainChanged', handler: (chainId: string) => void): void;
  on(event: 'connect', handler: (info: ProviderConnectInfo) => void): void;
  on(event: 'disconnect', handler: (error: ProviderRpcError) => void): void;
  on(event: 'message', handler: (message: ProviderMessage) => void): void;
}

// Also exported from 'w3pk'
interface ProviderConnectInfo { readonly chainId: string }
interface ProviderRpcError extends Error { code: number; data?: unknown }
interface ProviderMessage { readonly type: string; readonly data: unknown }
```

Only `chainChanged` is emitted, by `wallet_switchEthereumChain`.

**Supported JSON-RPC methods:**

| Method | Returns | Notes |
|--------|---------|-------|
| `eth_accounts` | `string[]` | Derived address for the configured mode + tag |
| `eth_requestAccounts` | `string[]` | Same as `eth_accounts` |
| `eth_chainId` | `string` (hex) | Active chainId; updated by `wallet_switchEthereumChain` |
| `eth_sendTransaction` | `string` (tx hash) | Delegates to `sendTransaction()`; hex params auto-converted; refused if `chainId` isn't the active chain |
| `personal_sign` | `string` (sig) | EIP-191; hex-encoded data signed as raw bytes |
| `eth_sign` | `string` (sig) | Legacy; same behaviour as `personal_sign` |
| `eth_signTypedData_v4` | `string` (sig) | EIP-712; `EIP712Domain` stripped automatically; refused if the domain `chainId` isn't the active chain |
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
- `personal_sign` data that arrives as a `0x`-prefixed hex string is signed as the bytes it encodes, matching MetaMask's behaviour.
- `eth_signTypedData_v4` throws a `WalletError` when the typed data's `domain.chainId` differs from the active chain, as [EIP-712](https://eips.ethereum.org/EIPS/eip-712) requires; switch chains first with `wallet_switchEthereumChain`.

---

## Stealth Addresses (ERC-5564)

Enable stealth addresses in configuration:

```typescript
const w3pk = createWeb3Passkey({
  stealthAddresses: {}  // Enable with default config
})
```

All stealth address methods are accessed via `w3pk.stealth.*`

Stealth keys are shared across origins: every app that enables stealth addresses gets the same meta-address and viewing key, so it can see every stealth payment to the user. w3pk never returns the spending private key or a stealth private key (a stealth private key plus the viewing key would give back the spending key); it signs from stealth addresses itself with `signTransaction()`. Each `signTransaction()` call runs a fresh passkey assertion, even with an active session. Still, only enable stealth addresses in apps you trust with stealth funds: the user approves a prompt, not the transaction the app asks w3pk to sign.

> **🔒 Security Note:** The ERC-5564 implementation properly reduces all scalars modulo the secp256k1 curve order to prevent unspendable funds. The same reduced scalar is used consistently in both public-key operations (`s_h × G`) and private-key operations (`spendingKey + s_h`) to ensure the derived stealth address always matches the derived private key.

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
  // Spend from it with stealth.signTransaction()
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
})
```

---

### `stealth.signTransaction(announcement: Announcement, tx: StealthTransaction): Promise<string>`

Sign an EIP-1559 transaction from a stealth address found for the current user. The stealth private key is derived and used inside w3pk, never returned. Every call runs a fresh passkey assertion, even with an active session. The transaction is signed, not sent: broadcast it with your own RPC (`eth_sendRawTransaction`).

> **Cross-origin risk:** stealth keys are the same for every origin, so any origin that enables `stealthAddresses` can sign any transaction from any of the user's stealth addresses. The passkey prompt shows the site, not the transaction, so the user can't tell what they approve. Tracked in [#147](https://github.com/w3hc/w3pk/issues/147).

**Parameters:**
- `announcement: Announcement` - The announcement of the stealth address to sign from
- `tx: StealthTransaction` - Fully populated transaction; nothing is fetched from an RPC

```typescript
interface StealthTransaction {
  to: string;
  value?: bigint;
  data?: string;                 // Default "0x"
  chainId: number;
  nonce: number;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}
```

**Returns:** The serialized signed transaction.

**Throws:** `Web3PasskeyError` with code `STEALTH_SIGN_ERROR` if the announcement isn't for the user or signing fails.

**Example:**

```typescript
import { JsonRpcProvider } from 'ethers'

const provider = new JsonRpcProvider('https://...')
const announcement = { stealthAddress: '0x...', ephemeralPublicKey: '0x02...', viewTag: '0xa4' }
const fees = await provider.getFeeData()

const signedTx = await w3pk.stealth.signTransaction(announcement, {
  to: '0x...',
  value: 1000000000000000n,
  chainId: 11155111,
  nonce: await provider.getTransactionCount(announcement.stealthAddress),
  gasLimit: 21000n,
  maxFeePerGas: fees.maxFeePerGas,
  maxPriorityFeePerGas: fees.maxPriorityFeePerGas
})

const tx = await provider.broadcastTransaction(signedTx)
```

---

### `stealth.getKeys(options?: { requireAuth?: boolean }): Promise<Omit<StealthKeys, 'spendingKey'>>`

Get ERC-5564 stealth keys: the meta-address, both public keys and the viewing key. The spending private key stays inside w3pk; use `signTransaction()` to spend from a stealth address.

**Parameters:**
- `options.requireAuth?: boolean` - Force fresh authentication

**Returns:**

```typescript
{
  stealthMetaAddress: string;   // 66 bytes (spending + viewing pubkeys)
  spendingPubKey: string;       // 33 bytes compressed public key
  viewingPubKey: string;        // 33 bytes compressed public key
  viewingKey: string;           // 32 bytes private viewing key
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

All ZK methods are accessed via `w3pk.zk.*` (typed `ZKMethods`). The first call loads `ZKProofModule` from `w3pk/zk`, so every `w3pk.zk` method returns a Promise, and the `isAvailable` property is read as `await w3pk.zk.isAvailable()`.

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
const wallet = await w3pk.deriveWallet('YOLO') // only YOLO returns the private key
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
  publicSignals: Record<string, string>;
  timestamp: string;
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

Create a Poseidon commitment `Poseidon(value, blinding)` for hiding values in ZK proofs. Returns the field element as a decimal string, the value the threshold and range circuits take as `commitment`.

**Example:**

```typescript
import { generateBlinding } from 'w3pk/zk/utils'

const value = 5000n
const blinding = generateBlinding()
const commitment = await w3pk.zk.createCommitment(value, blinding)
```

---

### `zk.computeMerkleRoot(leaf: string, pathIndices: number[], pathElements: string[]): Promise<string>`

Compute merkle root from a leaf and proof path, hashing each level with Poseidon. Returns the root as a decimal string, the same as `buildMerkleTree()`.

**Example:**

```typescript
const root = await w3pk.zk.computeMerkleRoot(leaf, pathIndices, pathElements)
```

---

### `zk.registerCircuit(type: ProofType, artifacts: CircuitArtifacts): Promise<void>`

Register a custom circuit for proof generation.

**Parameters:**

```typescript
interface CircuitArtifacts {
  wasmPath: string;           // Path to circuit WASM file
  zkeyPath: string;           // Path to zkey file
  verificationKey: unknown;   // Verification key JSON
}
```

**Example:**

```typescript
await w3pk.zk.registerCircuit('custom', {
  wasmPath: '/circuits/custom.wasm',
  zkeyPath: '/circuits/custom.zkey',
  verificationKey: customVKey
})
```

---

### `zk.isAvailable(): Promise<boolean>`

Check if ZK proofs are available. Resolves to `false` when `w3pk/zk` or its optional dependencies (snarkjs, circomlibjs) can't load. On a `ZKProofModule` from `w3pk/zk`, `isAvailable` is a `boolean` property.

**Example:**

```typescript
if (await w3pk.zk.isAvailable()) {
  console.log('ZK proofs enabled')
}
```

---

## Backup & Recovery

### `getBackupStatus(): Promise<BackupStatus>`

Get comprehensive backup status showing what protects the wallet.

**Returns:**

```typescript
type BackupMethod = 'file' | 'qr' | 'phrase' | 'prf';

interface BackupStatus {
  hasBackup: boolean;        // a backup that restores without a passkey exists: file, QR code or confirmed phrase
  recommendedMode?: 'password' | 'prf'; // next backup to make; undefined once both exist
  evictionRisk: boolean;     // the browser may wipe the wallet: WebKit outside a home-screen app, storage not persisted
  lastBackupAt?: string;     // ISO 8601 time of the latest backup
  methods: BackupMethod[];
  passkeySync: PasskeySyncStatus;
  recoveryPhrase: RecoveryPhraseStatus;
  securityScore: SecurityScore;
}
```

Browser storage can be wiped (eviction, Safari's 7-day cap, clearing site data), so a wallet without a backup can be lost for good. A lost device without a synced passkey can only be recovered from a backup that doesn't need the passkey, so `hasBackup` counts only those. A `prf` file from `exportForSync()` is recorded with method `prf` but doesn't count. While `hasBackup` is `false`, the security score is capped at 20 and its level is `vulnerable`. A password-only backup isn't penalized.

`recommendedMode` is `password` while no backup restores without a passkey: that's the backup that must exist. It's then `prf` until a PRF backup exists, for convenient sync to devices where the passkey synced.

`evictionRisk` is computed on each call from `navigator.storage.persisted()` and the display mode: `true` on WebKit (every iOS browser, Safari and other WebKit browsers on desktop) in a tab whose storage is not persisted, `false` in a home-screen app, once storage is persisted, and on Chromium and Firefox.

**Example:**

```typescript
const status = await w3pk.getBackupStatus()
if (!status.hasBackup && status.evictionRisk) {
  showBackupGate() // blocking; on iOS, suggest "Add to Home Screen"
} else if (!status.hasBackup) {
  showBackupWarning()
}
console.log('Security Score:', status.securityScore.total) // 0-70
console.log('Level:', status.securityScore.level)
console.log('Backup methods:', status.methods)
```

---

### `confirmRecoveryPhraseBackup(): Promise<void>`

Record that the user wrote down their recovery phrase. Call it once the user confirms, so `getBackupStatus()` reports `hasBackup: true` with the `phrase` method.

**Example:**

```typescript
await showRecoveryPhrase()
if (await userConfirmsPhraseWrittenDown()) {
  await w3pk.confirmRecoveryPhraseBackup()
}
```

---

### `createBackupFile(password: string): Promise<{ blob: Blob; filename: string }>`

Create a password backup (BackupFile v4): the backup that restores without a passkey. For a backup the passkey decrypts, use `exportForSync()` (PRF).

This backup can be used to:
- Restore wallet with existing passkey
- Register new passkey with this wallet
- Sync wallet across devices
- Split among guardians for social recovery

**Parameters:**
- `password: string` - Encrypts the backup through Argon2id (m=64 MiB, t=3, p=4, random 16-byte salt; NFC-normalized) and AES-256-GCM. It must have 15 to 256 characters (Unicode code points, after NFC normalization; spaces and any Unicode accepted, no composition rules) and not be a common password or a single repeated character (the rules of `isStrongPassword()`), or `WeakPasswordError` is thrown before the passkey prompt

The file holds no address. The default filename is `w3pk-backup-<date>.json`. Passing a second argument (the removed `encryptionType`) throws `WalletError`.

**File format (v4):**

```typescript
interface BackupFile {
  version: 4;
  createdAt: string;
  encryptedMnemonic: string;      // base64(iv || AES-256-GCM ciphertext)
  encryptionMethod: 'password' | 'prf';
  passwordEncryption?: { kdf: 'argon2id'; salt: string; memoryKiB: number; passes: number; parallelism: number };
  credential?: { id: string; publicKey: string };
  prfSalt?: string;               // prf
  username?: string;              // the owner's, when made while logged in
}
```

Every field but `encryptedMnemonic` is AES-GCM additional data (`backupAdditionalData()` in `src/backup/backup-file.ts`): editing any of them, or adding one, makes the restore fail. The encoding is the label `w3pk-backup-v4`, then `version`, `createdAt`, `encryptionMethod`, `passwordEncryption.kdf`, `.salt`, `.memoryKiB`, `.passes`, `.parallelism`, `credential.id`, `credential.publicKey`, `prfSalt`, `username`, in that order. An absent field is `0x00`; a string is `0x01`, its UTF-8 length as 4 bytes big-endian, then its bytes; an integer is `0x01` then 4 bytes big-endian.

Restoring a file that isn't v4 throws `UnsupportedBackupVersionError` (`code: 'BACKUP_VERSION_UNSUPPORTED'`, with `version`). For a v3 password file, its message names the [last offline tool that reads v3](https://github.com/w3hc/w3pk/blob/b14c32c658cc740aff78a1bbdb1cdb75c3b15a87/standalone/extract-mnemonic.html); for a v2 password file, the [v0.10.6 offline tool](https://github.com/w3hc/w3pk/blob/v0.10.6/standalone/extract-mnemonic.html). `passkey` and `hybrid` files throw `RemovedBackupMethodError`.

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
const { blob, filename } = await w3pk.createBackupFile('MyS3cure!Backup@2042')

// Download the backup
const url = URL.createObjectURL(blob)
const a = document.createElement('a')
a.href = url
a.download = filename
a.click()
```

---

## Social Recovery API

Social recovery splits a password-encrypted backup file into guardian shares using Shamir Secret Sharing. w3pk stores no share on the device: each guardian keeps theirs.

### `setupSocialRecovery(guardians: { name: string; email?: string }[], threshold: number, password: string): Promise<{ guardianShares: GuardianShare[]; setupComplete: boolean }>`

Encrypt the logged-in wallet into a password backup file and split it among guardians.

**Parameters:**
- `guardians` - Guardian names (and optional emails)
- `threshold: number` - Number of guardians required to recover (M in M-of-N, at least 2)
- `password: string` - Encrypts the backup the shares rebuild. Same rules as `createBackupFile()`: a weak password throws `WeakPasswordError`

**Returns:**

```typescript
{
  guardianShares: Array<{
    guardianId: string;
    guardianName: string;
    shareData: string;     // Hex-encoded Shamir share
    shareIndex: number;    // 1-based
    threshold: number;
    createdAt: string;
    walletAddress: string;
    splitId: string;       // Hex, 16 random bytes, the same for every share of one setup
    checksum: string;      // Hex SHA-256, see guardianShareChecksum() in src/recovery/backup-based-recovery.ts
  }>;
  setupComplete: boolean;
}
```

**Security:**
- Guardians receive fragments of an already-encrypted backup file
- Password is never shared with guardians
- Requires both threshold shares + password to recover
- Each share carries a checksum and its setup's `splitId`, so a corrupted, edited or mixed-up share is named before the shares are combined. The checksum is a plain SHA-256, not a MAC: a share edited on purpose with a recomputed checksum is refused by the backup's AES-GCM tag instead, without being named

**Example:**

```typescript
const { guardianShares } = await w3pk.setupSocialRecovery(
  [
    { name: 'Alice', email: 'alice@example.com' },
    { name: 'Bob' },
    { name: 'Charlie', email: 'charlie@example.com' },
    { name: 'Dave' },
    { name: 'Eve', email: 'eve@example.com' }
  ],
  3, // Need 3 guardians to recover
  'MyS3cure!Backup@2042'
);
```

---

### `generateGuardianInvite(guardianShare: GuardianShare, message?: string): Promise<{ qrCodeDataURL?: string; shareDocument: string; downloadBlob: Blob; filename: string }>`

Build what a guardian keeps: a share file, a printable document and, when the optional `qrcode` package is installed, a QR code of the share.

**Parameters:**
- `guardianShare` - One of the `guardianShares` from `setupSocialRecovery()`
- `message?: string` - Custom message for the guardian

**Example:**

```typescript
for (const share of guardianShares) {
  const { downloadBlob, filename, shareDocument, qrCodeDataURL } =
    await w3pk.generateGuardianInvite(share, 'Please keep this safe');

  // Send the share file, document or QR code to the guardian
}
```

---

### `recoverFromGuardians(shares: Array<string | GuardianShare>, password: string, options?: { allowAddressChange?: boolean }): Promise<{ ethereumAddress: string }>`

Combine guardian shares into the backup file, decrypt it and restore it as `restoreFromBackupFile()` restores a password backup. Logged out, the wallet stays in memory: call `register()` to create a passkey for it. Logged in, it replaces the stored wallet after one passkey assertion (`AddressChangeError` for another address unless `allowAddressChange: true`). The mnemonic is never returned.

**Parameters:**
- `shares` - At least `threshold` share files (JSON strings) or share objects
- `password: string` - Password set in `setupSocialRecovery()`
- `options.allowAddressChange?: boolean` - Allow the recovered wallet to replace the logged-in wallet with another address (default `false`)

**Throws:** `AddressChangeError` as in `restoreFromBackupFile()`; `InvalidGuardianShareError` (`code: 'GUARDIAN_SHARE_INVALID'`, with `shareIndex` and `guardianName`) for a share that is corrupted or edited (checksum mismatch), from another setup, given twice, or in an older format (share files `version: 1`, made by 0.11.x: combine them with w3pk v0.11.1, or set up social recovery again); `CryptoError` for a wrong password

**Example:**

```typescript
const shares = [aliceShareFile, bobShareFile, charlieShareFile]; // JSON strings

const { ethereumAddress } = await w3pk.recoverFromGuardians(
  shares,
  'MyS3cure!Backup@2042'
);
console.log('Wallet recovered:', ethereumAddress);

// Logged out: create a passkey for the recovered wallet
await w3pk.register({ username: 'alice' });
```

---

### `restoreFromBackupFile(backupData: string | Blob, password?: string, options?: { allowAddressChange?: boolean }): Promise<{ ethereumAddress: string }>`

Restore wallet from backup file with existing passkey.

**Use case:** User has passkey synced to this device and wants to restore wallet from backup.

A `prf` backup takes one assertion with its passkey and no password, then sets this device up for that passkey, as `importFromSync()` does (`SyncBootstrapError` with `reason: 'CREDENTIAL_MISMATCH'` when logged in with another passkey).

After restoring a password backup, the wallet is automatically associated with the current logged-in user. One passkey assertion releases the key the wallet is stored under: the stored wallet and the passkey's address change only once it succeeds, so a cancelled prompt or an authenticator without PRF leaves this device as it was. A backup of another address than the logged-in one replaces that wallet, so it throws `AddressChangeError` before any prompt unless the app confirms the replacement with the user and passes `{ allowAddressChange: true }`. The same applies to a `prf` backup, where the address is known only after the assertion.

If not logged in, the wallet stays in memory and you can either:
- Call `register()` to create a new passkey for this wallet (or `registerWithBackupFile()` with the file)
- Log in, then call `restoreFromBackupFile()` again to store it under that passkey

The mnemonic is never returned.

**Parameters:**
- `backupData: string | Blob` - Backup file (JSON string or Blob)
- `password?: string` - Password (required for password backups)
- `options.allowAddressChange?: boolean` - Allow the backup to replace the logged-in wallet with another address (default `false`)

**Returns:**

```typescript
{
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
const result = await w3pk.restoreFromBackupFile(backupData, 'MyS3cure!Backup@2042')
console.log('Wallet restored:', result.ethereumAddress)
// Wallet is automatically associated with current user

// A backup of another wallet replaces the logged-in one only once the user confirms
try {
  await w3pk.restoreFromBackupFile(backupData, password)
} catch (error) {
  if (error instanceof AddressChangeError && await confirmReplace(error.currentAddress, error.newAddress)) {
    await w3pk.restoreFromBackupFile(backupData, password, { allowAddressChange: true })
  }
}
```

**Throws:**
- `UnsupportedBackupVersionError` (`code: 'BACKUP_VERSION_UNSUPPORTED'`, with `version`) for a file that isn't BackupFile v4
- `RemovedBackupMethodError` (`code: 'BACKUP_METHOD_REMOVED'`, with `method`) for a `passkey` or `hybrid` backup
- `CryptoError` for a wrong password or an altered file, metadata included
- `AddressChangeError` (`code: 'ADDRESS_CHANGE_NOT_ALLOWED'`, with `currentAddress` and `newAddress`) for a backup of another address than the logged-in one, without `allowAddressChange`
- `AuthenticationError` if the passkey prompt is cancelled, `PrfUnsupportedError` if the authenticator returns no PRF output (logged in only; nothing stored changes)

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
  'MyS3cure!Backup@2042',
  'alice'
)

console.log('New passkey created for:', username)
console.log('Address:', address)
// User is now logged in and can use the wallet
```

**Note:** Only works with password-encrypted backups. For PRF backups, use `syncWalletWithPasskey()` or `importFromSync()` instead.

---

## Cross-Device Sync

### `getSyncStatus(): Promise<DeviceSyncInfo | null>`

Get this device's sync record: written when a wallet is imported from another device. Returns `null` when no wallet was synced to this device.

**Returns:**

```typescript
interface DeviceSyncInfo {
  deviceName: string;
  platform: 'ios' | 'android' | 'macos' | 'windows' | 'linux' | 'unknown';
  lastSyncTime: string;    // ISO 8601
  walletsSynced: string[]; // Ethereum addresses synced to this device
}
```

**Example:**

```typescript
const status = await w3pk.getSyncStatus()

if (status) {
  console.log(`Last sync on ${status.platform}: ${status.lastSyncTime}`)
}
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

### `exportForSync(password?: string): Promise<{ blob: Blob; filename: string; qrCode?: string }>`

Export wallet for syncing to another device.

Runs a fresh assertion restricted to the current passkey and encrypts the mnemonic with a key derived from its [WebAuthn PRF](https://w3c.github.io/webauthn/#prf-extension) output (`encryptionMethod: 'prf'`). Any device where the passkey synced restores the file with one prompt and no password, including a fresh device.

**Use case:** User wants to sync wallet to another device that has the same passkey.

**Parameters:**
- `password?: string` - Fallback when the authenticator has no PRF support: the file is then a password backup that names its passkey, to restore with `syncWalletWithPasskey(syncData, password)`. A weak password throws `WeakPasswordError` before the prompt, as in `createBackupFile()`

**Returns:**

```typescript
{
  blob: Blob;        // Sync file as downloadable Blob
  filename: string;  // Suggested filename
  qrCode?: string;   // Optional QR code data URL
}
```

**File format (`prf`, BackupFile v4):** `version: 4`, `encryptedMnemonic`, `prfSalt` (32 random bytes per file, base64url), `credential: { id, publicKey }`, `username`; no address. The default filename is `w3pk-sync-<date>.json`. The export is recorded in `getBackupStatus().methods` as `prf`. Key: HKDF-SHA256 over the PRF output evaluated at `SHA-256("w3pk-prf-sync-v1" || prfSalt)`, then AES-256-GCM, with every field but `encryptedMnemonic` as additional data. The public key doesn't decrypt the file; a fresh device needs it for `login()` and checks it against the assertion's signature.

**Security:** The PRF assertion is the fresh user verification; with an active session, export takes one prompt.

**Browser support:** PRF works in Chrome 108+ and Safari 17+ / iOS 17+, not in Firefox. Passkeys sync within one ecosystem only (Apple or Google); across ecosystems, use a password backup.

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

**Throws:**
- `WalletError` if not logged in
- `PrfUnsupportedError` if the authenticator returns no PRF output and no `password` was given
- `WeakPasswordError` if `password` is given and too weak
- `AuthenticationError` if the assertion fails or is cancelled

---

### `importFromSync(syncData: string | Blob, options?: { allowAddressChange?: boolean }): Promise<{ ethereumAddress: string; success: boolean }>`

Import a PRF sync file from `exportForSync()`. No prior `login()` and no password required: one assertion restricted to the file's passkey decrypts it.

**Use case:** User has the passkey on both devices (synced through iCloud Keychain or Google Password Manager) and the wallet on one. Works on a fresh device with no data for the passkey: the SDK checks the file's public key against the assertion's signature, saves the passkey's metadata, stores the wallet, starts a session and fires `onAuthStateChanged(true, user)`.

When this device already stores another wallet for the passkey, the file would replace it: that throws `AddressChangeError` after the assertion and before anything stored changes, unless the app confirms the replacement with the user and passes `{ allowAddressChange: true }`.

**Parameters:**
- `syncData: string | Blob` - Sync file data
- `options.allowAddressChange?: boolean` - Allow the file to replace the passkey's stored wallet with another address (default `false`)

**Returns:**

```typescript
{
  ethereumAddress: string;
  success: boolean;
}
```

**Example:**

```typescript
const syncData = '...' // From exportForSync(), by file upload or QR scan

const result = await w3pk.importFromSync(syncData)
console.log('Wallet synced:', result.ethereumAddress)
```

**Throws:**
- `WalletError` if the file isn't a PRF sync file (use `syncWalletWithPasskey()` for other backups, including `exportForSync(password)`'s fallback)
- `SyncBootstrapError` with `reason: 'CREDENTIAL_MISMATCH'` if logged in with another passkey than the file's
- `AddressChangeError` (`code: 'ADDRESS_CHANGE_NOT_ALLOWED'`, with `currentAddress` and `newAddress`) if the passkey has another wallet on this device, without `allowAddressChange`
- `SyncBootstrapError` with `reason: 'PUBLIC_KEY_MISMATCH'` if the file's public key doesn't match the passkey's signature
- `AuthenticationError` if the passkey isn't on this device or the prompt is cancelled
- `PrfUnsupportedError` if the authenticator returns no PRF output
- `CryptoError` or `Error` if the file was altered (ciphertext, address or address checksum)

---

### `syncWalletWithPasskey(backupData: string | Blob, password?: string, options?: { allowAddressChange?: boolean }): Promise<{ ethereumAddress: string }>`

Sync wallet to this device using an existing cloud-synced passkey and a backup file. No prior session required.

**Use case:** New device that already has a passkey synced via iCloud/Google Password Manager. The user provides their backup file; the SDK prompts them to select the passkey, decrypts the backup, saves the passkey's metadata if this device has none, stores wallet data locally, starts a session and fires `onAuthStateChanged(true, user)`.

A PRF sync file from `exportForSync()` takes no password: it's restored as `importFromSync()` does, with one assertion restricted to its passkey. On a device with no data for the passkey, the other backups that work are password backups made by a logged-in user: they name their passkey (`credential: { id, publicKey }`) and carry the username. The username comes from the passkey's user handle when the passkey was registered before 0.11.1, else from the backup; a backup without one, with one `register()` wouldn't accept, or with one another passkey already has on this device falls back to the wallet's address. Since 0.11.1 the user handle is 32 random bytes: WebAuthn requires it to hold no personal information. In both cases the backup's public key is checked against the assertion's signature. On a device that has the passkey's metadata, the assertion passes `login()`'s checks instead: its signature against the stored public key, and its counter, which is saved.

When this device already stores another wallet for the selected passkey, the backup would replace it: that throws `AddressChangeError` after the assertion and before anything stored changes, unless the app confirms the replacement with the user and passes `{ allowAddressChange: true }`.

**Parameters:**
- `backupData: string | Blob` - Backup file content (JSON string or Blob)
- `password?: string` - Password to decrypt the backup (required for `password` backups)
- `options.allowAddressChange?: boolean` - Allow the backup to replace the passkey's stored wallet with another address (default `false`)

**Returns:** `{ ethereumAddress: string }` (the mnemonic is never returned)

**Supported encryption methods:** `prf` and `password`

**Example:**

```typescript
const result = await w3pk.syncWalletWithPasskey(backupData, 'MyS3cure!Backup@2042')
console.log('Synced wallet address:', result.ethereumAddress)

// The passkey already has another wallet on this device
try {
  await w3pk.syncWalletWithPasskey(backupData, password)
} catch (error) {
  if (error instanceof AddressChangeError && await confirmReplace(error.currentAddress, error.newAddress)) {
    await w3pk.syncWalletWithPasskey(backupData, password, { allowAddressChange: true })
  }
}
```

**Throws:**
- `WalletError` if password is required but not provided
- `RemovedBackupMethodError` (`code: 'BACKUP_METHOD_REMOVED'`, with `method`) for a `passkey` or `hybrid` backup, before any prompt
- `UnsupportedBackupVersionError` (`code: 'BACKUP_VERSION_UNSUPPORTED'`) for a file that isn't BackupFile v4, before any prompt
- `Error` if backup uses an unknown encryption method
- `AuthenticationError` on a device with the passkey's metadata, if the assertion's signature or counter fails `login()`'s checks (nothing stored changes)
- `SyncBootstrapError` on a device with no data for the passkey (carries `reason` and `credentialId`):
  - `'NO_CREDENTIAL'`: password backup that doesn't name its passkey (made before 0.10.4)
  - `'CREDENTIAL_MISMATCH'`: the backup names another passkey than the one selected
  - `'PUBLIC_KEY_MISMATCH'`: the backup's public key doesn't match the passkey's signature
- `AddressChangeError` (`code: 'ADDRESS_CHANGE_NOT_ALLOWED'`, with `currentAddress` and `newAddress`) if the passkey has another wallet on this device, without `allowAddressChange` (the stored wallet is kept)
- `PrfUnsupportedError` if the passkey has another wallet on this device and the authenticator returns no PRF output to store the new one with (the stored wallet is kept)

**Note:** Differs from `importFromSync()` in that it also accepts password backups.

---

## Session Management

w3pk provides two types of sessions:

1. **In-Memory Sessions** (default): Cached in RAM, cleared on page refresh
2. **Persistent Sessions** (opt-in): Encrypted in localStorage, survives page refresh

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
  console.log('Session remaining:', w3pk.getSessionRemainingTime(), 'seconds')
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
2. Encrypted session stored in localStorage
3. On page refresh, session is automatically restored (if not expired)
4. `requireReauth: true` prompts for biometric on refresh (more secure)
5. `requireReauth: false` silently restores session (more convenient)

**Security (read the trade-off):**
- Sessions only persist for STANDARD and YOLO modes; STRICT mode is NEVER persisted
- Time-limited expiration; origin-isolated via localStorage
- ⚠️ The "WebAuthn-derived key" is derived from **public** credential metadata stored in the same browser profile, **not** from an authenticator-held secret. A persistent session is therefore **decryptable by anyone who can read this origin's storage** (malicious extension, XSS exfil, disk image), and it keeps the seed in that state for the whole duration it's enabled. This is a UX-for-security trade-off, not hardware-backed protection.
- Enabling "Remember Me" does not add a new trust dependency (you already trust your origin's code), it **widens the window** in which a compromise of your origin can reach the seed. Keep `duration` short for higher-value wallets; don't enable on shared/untrusted devices.
- Full threat model: **[SECURITY.md → At-Rest Encryption](./SECURITY.md#at-rest-encryption-what-it-protects-and-what-it-doesnt)**.

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

Get RPC endpoints for a chain: those set in the `rpcUrls` config first, then the public chainlist ones. For reading and discovery only: `sendTransaction()` never uses the chainlist ones.

**Parameters:**
- `chainId: number` - Chain ID (e.g., 1 for Ethereum, 137 for Polygon)

**Returns:** Array of RPC URLs; chainlist endpoints are HTTPS only, without API key placeholders

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

Validate password strength for backups. `createBackupFile()`, `setupSocialRecovery()` and `exportForSync(password)` apply the same rules and throw `WeakPasswordError` when they fail.

**Requirements** ([NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) §3.1.1.2):
- 15 to 256 characters, counted in Unicode code points after NFC normalization
- Any characters: spaces, accents and emoji are fine, and no mix of character types is required
- Not one of the 1,000 most common passwords of that length (whole-password match, any case, ignoring spaces, dots, dashes and underscores), and not a single repeated character

```typescript
const password = 'violet lantern under seven bridges'
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
// => bafybeicce26ztznqcdn6n6j6hhnoye37nb7nt7gtubelwk2ku4txbp7acy
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
- Used internally by PRIMARY `signMessage()`
- See [EIP-7951 Implementation Guide](../docs/EIP-7951.md)

---

### Post-Quantum Cryptography

w3pk provides hybrid post-quantum encryption (HPKE over ML-KEM-1024 + X25519, payload v3) both as instance methods (recommended) and standalone functions. See [POST_QUANTUM.md](./POST_QUANTUM.md#ml-kem-encryption) for the construction.

#### Instance Methods (Recommended)

Use these methods with your w3pk wallet instance - no private key exposure:

##### `w3pk.deriveMLKemPublicKey(options?): Promise<string>`

Derive your hybrid ML-KEM-1024 + X25519 public key for sharing with others.

**Parameters:**
```typescript
{
  context?: string;        // Domain separation (default: MLKEM_DEFAULT_CONTEXT, 'mlkem-v1')
  mode?: SecurityMode;     // 'STANDARD', 'STRICT', or 'YOLO' (default: 'STANDARD')
  tag?: string;            // Tag (default: 'MAIN')
  requireAuth?: boolean;   // Force re-auth (default: false, always true in STRICT)
}
```

The keypair is derived from the wallet's BIP-39 seed, the current origin, the mode, the tag and the context.

**Returns:** Base64-encoded hybrid public key (1600 bytes: ML-KEM-1024 encapsulation key || X25519 public key)

**Example:**
```typescript
const w3pk = createWeb3Passkey();
await w3pk.login();

const myPubKey = await w3pk.deriveMLKemPublicKey();
// Share myPubKey with others
```

**Note:** PRIMARY mode not supported.

---

##### `w3pk.mlkemEncrypt(plaintext: string, recipientPublicKeys: Array<string | Uint8Array>, options?): Promise<EncryptedPayload>`

Encrypt data for yourself and additional recipients.

**Parameters:**
```typescript
{
  context?: string;        // Domain separation (default: MLKEM_DEFAULT_CONTEXT, 'mlkem-v1')
  mode?: SecurityMode;     // Security mode (default: 'STANDARD')
  tag?: string;            // Tag (default: 'MAIN')
  requireAuth?: boolean;   // Force re-auth (default: false)
}
```

**Example:**
```typescript
const serverPubKey = await fetch('/api/mlkem-key').then(r => r.text());

const encrypted = await w3pk.mlkemEncrypt(
  'my secret data',
  [serverPubKey]  // You + server can both decrypt
);
```

**No sender authentication:** every recipient learns the shared data key, so any recipient can seal new content for the others. To prove you wrote the content, sign the plaintext, the recipients' public keys and a timestamp with `signMessage()`, encrypt the signed message, and have recipients verify the signature against your address after decrypting. Signing the ciphertext doesn't work: anyone can strip the signature and sign it as themselves. See [POST_QUANTUM.md](./POST_QUANTUM.md#no-sender-authentication).

---

##### `w3pk.mlkemDecrypt(payload: EncryptedPayload, options?): Promise<string>`

Decrypt v3 data encrypted for your wallet.

**Parameters:** Same options as `mlkemEncrypt`

**Example:**
```typescript
const plaintext = await w3pk.mlkemDecrypt(encrypted);
```

---

#### Standalone Functions

Low-level functions for direct key management:

```typescript
import { mlkemEncrypt, mlkemDecrypt, deriveMLKemKeypair, type EncryptedPayload } from 'w3pk'
```

##### `deriveMLKemKeypair(seed: Uint8Array, options: MLKemDerivationOptions): Promise<MLKemKeypair>`

Derive a deterministic hybrid keypair (ML-KEM-1024 + X25519) from a 64-byte BIP-39 seed: HKDF-SHA256 extracts with salt `w3pk-kem-keypair-v4`, then expands a 64-byte ML-KEM seed and a 32-byte X25519 secret key. Each info holds the purpose (`ml-kem-1024` or `x25519`), the normalized origin, the mode, the uppercased tag and the context, each prefixed with its 4-byte big-endian UTF-8 length. No secp256k1 key enters the derivation. See [POST_QUANTUM.md](./POST_QUANTUM.md#deterministic-key-derivation).

**Parameters:**
- `seed` - 64-byte BIP-39 seed (e.g. `getBytes(Mnemonic.fromPhrase(mnemonic).computeSeed())` with ethers)
- `options.origin` - Origin URL, normalized as for origin-specific addresses
- `options.mode` - Security mode (default: `'STANDARD'`)
- `options.tag` - Tag, uppercased (default: `'MAIN'`)
- `options.context` - Context string for domain separation (default: `MLKEM_DEFAULT_CONTEXT`, `'mlkem-v1'`, exported from `w3pk`)

**Returns:**
```typescript
{
  publicKey: Uint8Array;   // 1600 bytes: ML-KEM-1024 (1568) || X25519 (32)
  privateKey: Uint8Array;  // 3200 bytes: ML-KEM-1024 (3168) || X25519 (32)
}
```

**Example:**
```typescript
const keypair = await deriveMLKemKeypair(seed, { origin: 'https://example.com', context: 'my-app' });
```

---

##### `mlkemEncrypt(plaintext: string, publicKeys: (string | Uint8Array) | Array<string | Uint8Array>): Promise<EncryptedPayload>`

Encrypt data once with AES-256-GCM under a random data key, and seal that key to each recipient with HPKE over the hybrid ML-KEM-1024 + X25519 KEM.

**Parameters:**
- `plaintext: string` - The data to encrypt
- `publicKeys: (string | Uint8Array) | Array<string | Uint8Array>` - Single public key or array of hybrid public keys (1600 bytes each)

**Returns:**
```typescript
{
  version: 3;             // Payload format
  recipients: Array<{
    publicKey: string;    // Base64 recipient hybrid public key (1600 bytes)
    enc: string;          // Base64 ML-KEM-1024 ciphertext (1568) || X25519 ephemeral public key (32)
    ciphertext: string;   // Base64 HPKE-sealed data key (48 bytes)
  }>;
  encryptedData: string;  // Base64 AES-encrypted data (shared across all recipients)
  iv: string;             // Base64 initialization vector (12 bytes)
  authTag: string;        // Base64 authentication tag (16 bytes)
}
```

**Example:**

```typescript
import { mlkemEncrypt } from 'w3pk'

// Single recipient
const encrypted = await mlkemEncrypt('my secret data', publicKey1)

// Multiple recipients
const encrypted = await mlkemEncrypt('my secret data', [publicKey1, publicKey2, publicKey3])

console.log('Recipients:', encrypted.recipients.length)
```

**Security:**
- ✅ **Hybrid** - confidential unless both ML-KEM-1024 (NIST FIPS 203) and X25519 are broken
- ✅ **HPKE** - RFC 9180 key schedule, with each recipient entry bound to its recipient's public keys
- ✅ **Multi-recipient support** - Encrypt once for multiple recipients
- ✅ **Key zeroization** - All secrets securely wiped from memory
- ✅ **Authenticated encryption** - AES-256-GCM with 128-bit auth tag
- ⚠️ **No sender authentication** - every recipient learns the shared data key, so any recipient can seal new content for the others. Sign the content inside the payload (e.g. `w3pk.signMessage()`, or an ethers `Wallet`'s `signMessage()`) to prove who wrote it. See [POST_QUANTUM.md](./POST_QUANTUM.md#no-sender-authentication)

---

#### `mlkemDecrypt(payload: EncryptedPayload, privateKey: string | Uint8Array): Promise<string>`

Decrypt a v3 payload from `mlkemEncrypt()`. The recipient entry is found by the public key derived from `privateKey`; payloads of any other version throw `Unsupported payload version`.

**Parameters:**
- `payload: EncryptedPayload` - The encrypted payload from `mlkemEncrypt()`
- `privateKey: string | Uint8Array` - Hybrid private key (base64 or bytes, 3200 bytes)

**Returns:** `string` - Decrypted plaintext

**Example:**

```typescript
import { mlkemDecrypt } from 'w3pk'

const plaintext = await mlkemDecrypt(encrypted, privateKey)
```

**Throws:** Error if decryption fails (unsupported version, invalid key, no matching recipient, or a tampered `enc`, sealed key or payload)

Decryption doesn't prove who sent the payload: verify the sender's signature inside it (see `mlkemEncrypt()`).

**Related:**
- See [POST_QUANTUM.md](../docs/POST_QUANTUM.md) for full quantum readiness roadmap
- See [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) for ML-KEM specification

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

#### `deriveWalletFromPath(mnemonic: string, path: string): { address: string; privateKey: string }`

Derive HD wallet at a full BIP-32 path from the mnemonic's root, such as the path returned by `deriveOriginPath()`.

```typescript
const path = await deriveOriginPath('https://example.com')
const { address } = deriveWalletFromPath(mnemonic, path)
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
  console.log('Stealth address:', result.stealthAddress)
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

Get the HTTPS RPC endpoints of a chain from chainid.network, without those that need an API key (standalone).

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

Clear the chainlist cache of every `chainsJsonUrl`. Each URL is cached on its own, for `cacheDuration` (1 hour by default).

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
  ApiError,
  SyncRequiredError,
  WalletMissingError,
  SyncBootstrapError,
  PrfUnsupportedError,
  AddressChangeError,
  RemovedBackupMethodError,
  UnsupportedBackupVersionError,
  WeakPasswordError
} from 'w3pk'
```

### Error Hierarchy

- `Web3PasskeyError` - Base error class
  - `AuthenticationError` - Authentication failures (login, session)
  - `RegistrationError` - Registration failures
  - `WalletError` - Wallet operations (derivation, signing)
  - `CryptoError` - Cryptographic operations (encryption, decryption)
  - `StorageError` - Storage operations (localStorage)
  - `ApiError` - API/network errors (RPC, chainlist)
  - `SyncRequiredError` - `login()`: passkey authenticated, but this device has no credential metadata (`credentialId`)
  - `WalletMissingError` - `login()`: credential metadata found, but the wallet record is gone (`credentialId`, `ethereumAddress`)
  - `SyncBootstrapError` - `syncWalletWithPasskey()`, `importFromSync()`: the backup can't set this device up for the passkey (`reason`, `credentialId`)
  - `PrfUnsupportedError` - `derivePrfSecret()`, `getSemaphoreIdentity()`, `exportForSync()`, `importFromSync()`: the authenticator returned no WebAuthn PRF output (`credentialId`)
  - `AddressChangeError` - `restoreFromBackupFile()`, `recoverFromGuardians()`, `syncWalletWithPasskey()`, `importFromSync()`: the backup would replace the logged-in (or the passkey's stored) wallet with another address and `allowAddressChange` isn't set (`currentAddress`, `newAddress`)
  - `RemovedBackupMethodError` - `syncWalletWithPasskey()`, `restoreFromBackupFile()`, `importFromSync()`, `recoverFromGuardians()`: the backup uses the removed `passkey` or `hybrid` method (`method`); create a new `password` or `prf` backup
  - `UnsupportedBackupVersionError` - the same methods and `registerWithBackupFile()`: the file isn't BackupFile v4 (`version`); decrypt a v3 password file with the extractor at commit `b14c32c`, a v2 one with the v0.10.6 offline tool
  - `InvalidGuardianShareError` - `recoverFromGuardians()`: a share is corrupted, edited, from another setup, given twice or in an older format (`shareIndex`, `guardianName`)
  - `WeakPasswordError` - `createBackupFile()`, `setupSocialRecovery()`, `exportForSync(password)`: the password fails `isStrongPassword()` (`code: 'WEAK_PASSWORD'`, `feedback: string[]` gives each reason)

### Error Handling

```typescript
import {
  AuthenticationError,
  WalletError,
  SyncRequiredError,
  WalletMissingError
} from 'w3pk'

try {
  await w3pk.login()
} catch (error) {
  if (error instanceof SyncRequiredError) {
    // Passkey synced to this device, wallet data isn't: ask for the password backup
    await w3pk.syncWalletWithPasskey(backupFile, password)
  } else if (error instanceof WalletMissingError) {
    // Metadata here, wallet record gone: any backup of this passkey restores it
    await w3pk.syncWalletWithPasskey(backupFile, password)
  } else if (error instanceof AuthenticationError) {
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
  PersistentSessionConfig,
  StealthAddressConfig,
  ZKProofConfig,
  UserInfo,
  GeneratedWallet,
  DerivedWallet,
  RegisterResult,
  SecurityMode,
  SigningMethod,
  SignMessageOptions,
  EIP1193ProviderInterface
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
  GuardianShare,
  RecoveryScenario,
  SimulationResult
} from 'w3pk'

// Sync types
import type { SyncCapabilities, DeviceSyncInfo } from 'w3pk'

// ML-KEM types
import type { EncryptedPayload, MLKemKeypair } from 'w3pk'

// ZK types
import type {
  ZKMethods,
  ZKProof,
  ProofType,
  CircuitArtifacts,
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
  EIP7702Authorization
} from 'w3pk'
```

---

## Education & Recovery Testing

These are standalone exports. The simulator takes the backup status, so call `w3pk.getBackupStatus()` (requires authentication) and pass the result.

### `getExplainer(topic: string): EducationalModule | null`

Get educational content by topic. Returns `null` for an unknown topic.

**Parameters:**
- `topic: string` - Topic id (e.g., `"whatIsPasskey"`, `"howDoesSyncWork"`, `"whyBackupMatters"`)

**Returns:**

```typescript
interface EducationalModule {
  title: string;
  content: string;
  visual?: string;
  interactive?: string;
}
```

**Example:**

```typescript
import { getExplainer } from 'w3pk'

const explainer = getExplainer('howDoesSyncWork')
console.log(explainer?.title)
console.log(explainer?.content)
```

**Available Topics:**
- Use `getAllTopics()` standalone function to get list of all topics
- Use `searchExplainers(query)` standalone function to search topics

---

### `RecoverySimulator.simulateScenario(scenario: RecoveryScenario, status: BackupStatus): Promise<SimulationResult>`

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
  scenario: RecoveryScenario;
  success: boolean;
  availableMethods: RecoveryMethod[];
  timeEstimate: string;
  educationalNote: string;
}
```

**Example:**

```typescript
import { RecoverySimulator } from 'w3pk'

const result = await new RecoverySimulator().simulateScenario(
  { type: 'lost-device', description: 'Phone dropped in water, device destroyed' },
  await w3pk.getBackupStatus()
)

console.log('Can recover:', result.success)
console.log('Recovery methods:', result.availableMethods.map(m => m.method))
console.log('Note:', result.educationalNote)
```

---

### `RecoverySimulator.runInteractiveTest(status: BackupStatus)`

Run the predefined scenarios (`getScenarios()`) and score recovery preparedness.

**Returns:**

```typescript
Promise<{
  scenarios: SimulationResult[];
  overallScore: number;    // 0-100
  securityScore: number;
  feedback: string;        // Personalized recommendations
}>
```

**Example:**

```typescript
import { RecoverySimulator } from 'w3pk'

const test = await new RecoverySimulator().runInteractiveTest(
  await w3pk.getBackupStatus()
)

console.log('Overall Score:', test.overallScore, '/ 100')
console.log('Feedback:', test.feedback)

test.scenarios.forEach(result => {
  console.log(`${result.scenario.description}: ${result.success ? '✅' : '❌'}`)
})
```

---

## Additional Resources

- [Quick Start Guide](./QUICK_START.md) - Get started in 5 minutes
- [Recovery & Backup System](./RECOVERY.md) - Three-layer backup architecture
- [ERC-5564 Stealth Addresses](#stealth-addresses-erc-5564) - Stealth address API
- [Security Architecture](./SECURITY.md) - Integration best practices
- [Browser Compatibility](./BROWSER_COMPATIBILITY.md) - Supported browsers

---

## Need Help?

- GitHub Issues: [github.com/w3hc/w3pk/issues](https://github.com/w3hc/w3pk/issues)
- Demo: [w3pk.w3hc.org](https://w3pk.w3hc.org)
