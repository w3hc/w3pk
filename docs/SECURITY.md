# Security Architecture

This document explains the security model of w3pk and how wallet protection works.

## Overview

w3pk provides **multiple layers of security** to protect user wallets:

1. **WebAuthn authentication** - Biometric/PIN gating for wallet access **via the SDK**
2. **Application isolation** - Apps cannot access master mnemonic through the SDK API
3. **Origin-specific derivation** - Each website gets unique isolated addresses
4. **Mode-based access control** - STANDARD/STRICT modes are view-only, YOLO mode provides full access
5. **Encrypted storage** - AES-256-GCM at rest, under a key derived from the passkey's WebAuthn PRF output, which the authenticator releases only on a user-verified assertion
6. **Secure sessions** - In-memory and optional persistent sessions (disabled in STRICT mode)

> **Before you rely on any of this for a threat model, read [At-Rest Encryption: What It Protects, and What It Doesn't](#at-rest-encryption-what-it-protects-and-what-it-doesnt) immediately below.** Since [#179](https://github.com/w3hc/w3pk/issues/179), the wallet on disk can't be decrypted from storage alone: the key needs the passkey. What is still exposed is the live session, and a silent "Remember Me" session whose key is stored.

## At-Rest Encryption: What It Protects, and What It Doesn't

The short version: **the wallet on disk can only be decrypted with the passkey.** An attacker who reads this origin's browser storage gets ciphertext and no key. The real exposures are the live session, a silent "Remember Me" session (its key is stored), and code running as your origin.

### How the at-rest key is derived

The AES-256-GCM key that encrypts the wallet mnemonic is derived from the **WebAuthn PRF extension output**, a per-credential secret held by the authenticator:

```
prfOutput = HMAC(credential secret, SHA-256("WebAuthn PRF" || 0x00 || "w3pk-prf-input-v1"))
key       = HKDF-SHA256(prfOutput, salt = 0^32, info = "w3pk-prf-wallet-key-v1")
```

- The authenticator releases `prfOutput` only during a **user-verified** (biometric/PIN) assertion. Nothing stored on the device can recompute it.
- The input is fixed, so the output, and the key, are the same at every login with the passkey.
- The persistent-session key comes from the same PRF output under another HKDF `info`, so neither key reveals the other.
- The key is a non-extractable `CryptoKey`, never stored.

A malicious browser extension, a one-shot XSS that exfiltrates storage, a disk image or a profile backup gets `credentialId`, `publicKey` and the ciphertext, none of which yields the key. Before [#179](https://github.com/w3hc/w3pk/issues/179) the key was derived from `credentialId` and `publicKey` alone, and such an attacker could decrypt the seed offline.

**No PRF support** (older authenticators, some browser/OS combinations, unverified assertions with `userVerification: 'preferred'`): the wallet is **not stored on the device**. It lives in memory for the session and comes back from a backup on the next visit. There is deliberately no weaker fallback.

**Wallets stored before #179** are under the old key. `login()` re-encrypts one from a PRF persistent session when one exists; otherwise it throws `WalletMissingError` and the wallet is restored from a backup.

### "Remember Me" (persistent sessions): PRF-keyed, renewed at every real login

`persistentSession.enabled: true` stores the encrypted mnemonic in localStorage so the user isn't prompted on every page refresh. Like wallet storage, the persistent-session blob is encrypted under a key derived (HKDF-SHA256) from the **WebAuthn PRF extension output** — a per-credential secret the authenticator releases only during a user-verified (biometric/PIN) assertion. Nothing stored on disk can recompute it. Every real login re-evaluates the PRF (with a fixed input, so the output is deterministic per credential) and re-keys the blob; the session expiry *is* the renewal boundary.

The at-rest guarantee then depends on `requireReauth`:

- **`requireReauth: true` (default):** the key is **never stored**. Every restore re-derives it from a live assertion's PRF output. A storage-read attacker (extension, storage-exfiltrating XSS, disk image, cloud backup of the profile) gets ciphertext that cannot be decrypted without the physical authenticator — the blob is hardware-bound at rest.
- **`requireReauth: false` (silent "Remember Me"):** the PRF-derived key is stored as base64url next to the blob, so restore works without a prompt; it is re-imported as a non-extractable `CryptoKey` before use. Anyone who can read this origin's localStorage (XSS, an extension, a disk image or profile backup) can decrypt the blob. This is less of a change than it sounds: when the key was a non-extractable `CryptoKey` in IndexedDB, script on the origin could already *use* it to decrypt, and the browser wrote its raw bytes to the profile on disk. Silent restore fundamentally requires a usable key at rest. The [cross-origin wallet](https://github.com/w3hc/w3pk/issues/156) moves this storage out of the host app's origin, so script on the host page can no longer read it.
- **No PRF support** (older authenticators, some browser/OS combos): persistent sessions are **not stored at all** — the device gets in-memory sessions only. There is deliberately no fallback to weaker encryption.

What "Remember Me" still changes is the **exposure window**, not the trust model: a compromise of the already-trusted origin (XSS, a malicious npm dependency, a compromised script/CDN) can use the live session *any time within the configured duration*, including while the tab is idle and across browser restarts — instead of only while the wallet is actively in use.

**Reasonable to accept** for a hot wallet on a user's own device — it's the same bargain as "stay logged in" everywhere. **Guidance:**

- Leave it disabled (the default) if every unlock should require a biometric/PIN prompt.
- Keep the duration short for higher-value wallets. `sessionDuration: 0` keeps nothing in memory, so every operation prompts; the persistent session still follows `persistentSession`.
- `requireReauth: true` (default) still prompts on page refresh and keeps the blob hardware-bound; `requireReauth: false` restores silently for the whole duration.
- Do not enable it on shared or untrusted devices.

### Storage durability: what can still wipe the wallet

The encrypted wallet, persistent sessions and backup metadata live in localStorage, next to the credential metadata. Browsers evict or clear an origin's storage as a whole or by storage type, so they are either all there or all gone: a passkey is never left logging in to a missing wallet. Before v0.10.3 the wallet lived in IndexedDB, and Chrome's storage-pressure eviction could delete it while keeping the credential in localStorage, leaving a wallet that could not be rebuilt from the passkey.

After register, login and restore, w3pk calls `navigator.storage.persist()`. `w3pk.storagePersisted` reports the answer (`null` until the browser answers, or where the API is missing). Persisted storage is exempt from storage-pressure eviction.

What still wipes localStorage, and with it the wallet:

- **Safari's 7-day cap** on script-writable storage: Safari (macOS and iOS) deletes localStorage for a site the user hasn't interacted with for 7 days of browser use. Web apps added to the Home Screen are exempt.
- **Clearing site data**: "Clear browsing data", site settings, or developer tools.
- **Private browsing**: storage is discarded when the private window closes.
- **Storage-pressure eviction** in browsers that don't grant persistence: Chrome grants it from engagement heuristics and Firefox asks the user, so `storagePersisted` may be `false`.

The mnemonic is random, so it cannot be rebuilt from the passkey. Users need a backup file or the recovery phrase to survive any of the above (see [RECOVERY.md](./RECOVERY.md)).

### Origin / hostname / URL scoping

What the credential and stored data are bound to — three *different* scopes, and none of them is the full URL:

| Bound to | Scope | Enforced by |
|---|---|---|
| Stored session / wallet / credentials | **Origin** = scheme + host + port | Browser storage partitioning |
| WebAuthn passkey (RP ID) | **Hostname** (exact host) | Browser WebAuthn API, re-checked on every assertion |

- **Path and query are irrelevant.** `https://app.example.com/wallet` and `https://app.example.com/x?y=1` are the same origin; a remembered session works on every page of the site, not one URL.
- A different scheme (`http:`), port (`:3000`), or host (`other.example.com`) is a **different origin** with separate storage, and a passkey bound to one exact hostname won't work on another. This is the anti-phishing guarantee — see [Credential Scoping and Domain Isolation](#credential-scoping-and-domain-isolation).
- **The hole to understand:** origin isolation walls the data off from *other origins*, not from code running *inside* your origin. XSS, a malicious dependency, or a compromised CDN on your own site runs *as* your origin and can use the session exactly like your legitimate code. **"Only this origin" is not "only my code."**

### Backup files (the "floppy disk")

A backup file is portable and independent of any device. What an attacker who obtains **only the file** can do depends on its type:

| Backup type | Decrypts with | Is the file alone enough? |
|---|---|---|
| `password` | User password (Argon2id, 64 MiB, 3 passes, random per-file salt) | ❌ Needs the password |
| `prf` | Key derived (HKDF) from the passkey's WebAuthn PRF output, random per-file salt | ❌ Needs a fresh assertion with the passkey |

A backup file on its own is not decryptable in either variant. **For a backup that leaves the device (cloud, USB, guardians), `password` is the one that restores without the passkey.**

Backup files are BackupFile v4 (`version: 4`). They hold no address, in clear or hashed. v2 stored the address in clear and as `addressChecksum`, an unsalted truncated SHA-256 that hashing every onchain address reverses. A salted hash wouldn't help: the salt sits in the file, and onchain addresses can be enumerated. So a stolen file doesn't give the wallet's address. A backup made while logged in carries the username in clear, so a fresh device can restore it: whoever holds the file learns the username, not the address. Restores derive the address from the decrypted mnemonic, and AES-GCM rejects a wrong key or an altered ciphertext. Every other field (`credential`, `username`, `prfSalt`, `createdAt`, the Argon2id parameters) is AES-GCM additional data, in a fixed-order, length-prefixed encoding: in v3 only the mnemonic was authenticated, so whoever could edit the file could swap the passkey a fresh device trusts or the username it registers. Editing or adding a field now makes the restore fail. Files that aren't v4 throw `UnsupportedBackupVersionError`.

Guardian shares carry their setup's random `splitId` and a SHA-256 checksum over the share and its labels, so a corrupted, edited or mixed-up share throws `InvalidGuardianShareError` naming it before the shares are combined. The checksum is unkeyed: it catches mistakes, not a guardian who edits a share and recomputes it; that share passes, and the backup's AES-GCM tag refuses the rebuilt file.

The `passkey` and `hybrid` types were removed in 0.11.0: their key came from `credentialId` and the credential's public key, with no WebAuthn ceremony, so a `passkey` file decrypted from public data alone and a `hybrid` file was only as strong as its password. Restoring one throws `RemovedBackupMethodError`; users who have one should create a new `password` or `prf` backup.

## Enhanced Security Model (v0.8.0+)

### Security Modes

w3pk now uses **origin-centric security modes** for wallet derivation. `STANDARD`, `STRICT` and `YOLO` derive secp256k1 keys from the mnemonic; `PRIMARY` is the passkey's [P-256 smart account](#primary-mode-the-p-256-smart-account):

**STANDARD mode (default):**
- ✅ Address only (no private key)
- ✅ Persistent sessions allowed
- ✅ Best for most applications

**STRICT mode:**
- ✅ Address only (no private key)
- ❌ Persistent sessions NOT allowed
- ✅ Requires biometric/PIN authentication every time
- ✅ Best for high-security applications

**YOLO mode:**
- ✅ Full access (address + private key)
- ✅ Persistent sessions allowed
- ⚠️ Use only when private key access is required

**PRIMARY mode:**
- ✅ Address only: the passkey's P-256 smart account, no private key anywhere
- ✅ Every signature asks for a fresh user-verified passkey assertion
- ❌ No stealth addresses, ML-KEM, Semaphore/ZK or EIP-7702 authorizations

### Application Security Guarantees

**What applications CANNOT access:**
- ❌ Master mnemonic (no method returns it: restores return only the address)
- ❌ Private keys in STANDARD mode
- ❌ Private keys in STRICT mode
- ❌ Private keys from other origins
- ❌ Private keys from other modes
- ❌ Direct backup/recovery manager access

**What applications CAN access:**
- ✅ Origin-specific address (all modes)
- ✅ Private keys in YOLO mode only
- ✅ Signatures via `signMessage()` (no key exposure)
- ✅ Encrypted backups via SDK methods

### Origin keys use hardened derivation

Every origin address is derived at `m/13'/A'/B'/C'/D'/mode'/tag'`, every level hardened:

- `A'/B'/C'/D'`: the [SLIP-0013](https://github.com/satoshilabs/slips/blob/master/slip-0013.md) service identity of the normalized origin (index 0): the first 16 bytes of `SHA-256(LE32(0) ‖ origin)`, read as four little-endian uint32
- `mode'`: `STANDARD`=0', `STRICT`=1', `YOLO`=2', `PRIMARY`=3'
- `tag'`: the first 4 bytes of `SHA-256(TAG)`, big-endian, low 31 bits

The origin levels hold 124 bits of SHA-256 that only the origin controls, so no mode or tag chosen by one origin can reach another origin's subtree. Every level is hardened, so under [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#security) a leaked YOLO-mode private key reveals neither its parents nor any other origin's key. Purpose `13'` also keeps every origin key away from the registration address at `m/44'/60'/0'/0/0`.

Before v0.11.2, origin keys were non-hardened children at `m/44'/60'/0'/0/{index}` with a 31-bit `index` from `SHA-256(origin:mode:tag)`: an app could search about 2^31 tags to find one that gave another origin's key ([#262](https://github.com/w3hc/w3pk/issues/262)). Every origin address changed with the fix.

### Mode-Based Security Examples

```typescript
// STANDARD mode (default) - Address only, persistent sessions
const wallet = await w3pk.deriveWallet()
// Returns: { address, path, origin, mode: 'STANDARD', tag: 'MAIN' }
// ✅ Safe for display
// ❌ No privateKey in response
// ✅ Uses cached session (no repeated auth)

// STRICT mode - Address only, NO persistent sessions
const strictWallet = await w3pk.deriveWallet('STRICT')
// Returns: { address, path, origin, mode: 'STRICT', tag: 'MAIN' }
// ✅ Safe for display
// ❌ No privateKey in response
// ⚠️ Requires biometric/PIN authentication EVERY time

// YOLO mode - Full access with private key
const yoloWallet = await w3pk.deriveWallet('YOLO')
// Returns: { address, privateKey, path, origin, mode: 'YOLO', tag: 'MAIN' }
// ✅ Full access for transactions
// ⚠️ Application has access to private key

// YOLO mode with custom tag for specific features
const gamingWallet = await w3pk.deriveWallet('YOLO', 'GAMING')
// Returns: { address, privateKey, path, origin, mode: 'YOLO', tag: 'GAMING' }
// ✅ Different address from MAIN
// ✅ Full access for gaming transactions
```

### Multiple Wallet Management

w3pk supports multiple wallets on a single device, but applications should implement safeguards to prevent accidental wallet creation:

**Detection Methods:**

```typescript
// List all wallets with metadata
const wallets = await w3pk.listExistingCredentials()
// Returns: [{ username, ethereumAddress, createdAt, lastUsed }, ...]

// Check if any wallets exist
const hasWallet = wallets.length > 0

// Get count of wallets
const count = wallets.length
```

**Security Implications:**

1. **Platform Behavior (iOS/macOS):**
   - Multiple passkeys sync via iCloud Keychain
   - Can cause user confusion if not properly managed
   - Each passkey has its own mnemonic (different wallets)

2. **UX Best Practices:**
   - Always check for existing wallets before registration
   - Show warning if user attempts to create multiple wallets
   - List existing wallets and allow selection during login

3. **Valid Use Cases for Multiple Wallets:**
   - Different personas (personal vs business)
   - Testing and development
   - Family members on shared device
   - Migration scenarios

**Recommended Pattern:**

```typescript
// Before registration
const wallets = await w3pk.listExistingCredentials()
const count = wallets.length
if (count > 0) {
  // Show warning: "You have {count} wallet(s). Creating a new one will generate
  // a DIFFERENT address. Funds sent to different addresses won't be accessible."
  // Offer: [Login to Existing] [Create New Anyway] [Cancel]
}
```

See [Integration Guidelines](./INTEGRATION_GUIDELINES.md#check-for-existing-wallet-first) for complete implementation patterns.

## PRIMARY Mode: the P-256 Smart Account

In `PRIMARY` mode the passkey owns `W3pkAccount`, an ERC-4337 account (EntryPoint v0.9) on OpenZeppelin 5.7.0 that verifies WebAuthn assertions onchain. `W3pkAccountFactory` deploys each account as an ERC-1167 clone of one implementation, salted with the passkey's public key and the tag. Factory and implementation are deployed through the deterministic deployment proxy, for now only on Ethereum Sepolia, verified on Etherscan and Sourcify; Ethereum, OP Mainnet, Base, Arbitrum One and their Sepolia testnets will follow at the same addresses ([how to deploy](./DEPLOYMENT.md)). `pnpm check:deployments` checks the deployments against `W3PK_ACCOUNT_FACTORY` and `W3PK_ACCOUNT_INIT_CODE_HASH`. Addresses and links are in [EIP-7951.md](./EIP-7951.md#primary-smart-account).

**Not upgradeable.** The account has no proxy, no upgrade function and no admin. Nobody, w3hc included, can change the code that holds a `PRIMARY` account's funds: an upgrade key would be one key over every account, and an address would no longer tell what code runs behind it. A bug can't be patched in place: a fixed version is a new factory at new addresses, and users move their funds. ERC-7579 modules add behavior without new account code; only the account can install one, through a UserOperation the passkey signs, and an installed validator or executor can act for the account.

**Two trust models.** In `STRICT`, `STANDARD` and `YOLO`, whoever holds the mnemonic spends: the SDK decrypts it in the page, a session caches it (except in `STRICT`), backups carry it, and `YOLO` exports keys. The account is an EOA, so no contract is trusted. In `PRIMARY`, whoever gets a user-verified assertion from the passkey spends: the key never leaves the authenticator or the passkey provider, and nothing in the page can sign without a prompt. In exchange, funds depend on `W3pkAccount`, OpenZeppelin's code, the EntryPoint and the P-256 verifier, a bundler can delay or drop a UserOperation (not alter it), and recovery is the passkey provider's sync: a lost, unsynced passkey loses the account unless a recovery module is installed. A synced passkey is as safe as the provider account it syncs through.

**STANDARD-only features.** Stealth addresses (ERC-5564), ML-KEM encryption and Semaphore/ZK proofs compute with a secret in the page's memory: stealth and ML-KEM keys come from the mnemonic, Semaphore and ZK secrets from the passkey's PRF output. An authenticator only signs WebAuthn challenges with its P-256 key, so it can't do secp256k1 stealth arithmetic, decapsulate ML-KEM or feed a Groth16 witness, and running them as `PRIMARY` would bring back a secret outside the authenticator. They stay on the `STANDARD` side; `rawHash` signing and EIP-7702 authorizations are refused in `PRIMARY` too. The full table is in [EIP-7951.md](./EIP-7951.md#standard-and-primary-features).

## Message Signing with Mode Selection

The `signMessage()` method supports **multiple signing methods**, **mode and tag selection**, allowing developers to choose the appropriate signing approach for their use case.

### Signing Methods

w3pk supports four signing methods:

1. **EIP-191 (default)**: Standard Ethereum signed messages
2. **SIWE (EIP-4361)**: Sign-In with Ethereum (Web3 authentication)
3. **EIP-712**: Structured typed data (permits, voting, meta-transactions)
4. **rawHash**: Pre-computed 32-byte hashes (Safe multisig, custom schemes); always prompts for the passkey

### Default Behavior

By default, `signMessage()` uses **STANDARD mode + MAIN tag + EIP-191** (origin-centric):

```typescript
// Default: Sign with STANDARD + MAIN address using EIP-191
const result = await w3pk.signMessage("Hello World")

console.log(result.signature)  // The signature
console.log(result.address)    // Origin-specific STANDARD+MAIN address
console.log(result.mode)       // 'STANDARD'
console.log(result.tag)        // 'MAIN'
console.log(result.origin)     // Current origin
```

### Mode-Based Signing

Choose the appropriate security mode for each signing operation:

```typescript
// STANDARD mode: View-only, persistent sessions
const standard = await w3pk.signMessage("Display balance", {
  mode: 'STANDARD'
})

// STRICT mode: View-only, requires auth every time
const strict = await w3pk.signMessage("Transfer $10000", {
  mode: 'STRICT'
})
// User will be prompted for biometric/PIN authentication

// YOLO mode: Sign from address with private key access
const yolo = await w3pk.signMessage("Gaming transaction", {
  mode: 'YOLO',
  tag: 'GAMING'
})
```

### Multi-Address Signing

Sign from different addresses for different purposes:

```typescript
// Different tags for different features
const mainSig = await w3pk.signMessage("msg", {
  tag: 'MAIN'
})

const gamingSig = await w3pk.signMessage("msg", {
  mode: 'YOLO',
  tag: 'GAMING'
})

const tradingSig = await w3pk.signMessage("msg", {
  mode: 'YOLO',
  tag: 'TRADING'
})

// Each signature comes from a different address!
console.log(mainSig.address !== gamingSig.address)      // true
console.log(gamingSig.address !== tradingSig.address)   // true
```

### Choosing the Right Signing Method

**Security implications of each method:**

| Method | Use Case | Security Level | Verifiable By |
|--------|----------|----------------|---------------|
| EIP-191 | General signatures | Standard | `ethers.verifyMessage()` |
| SIWE | Web3 authentication | High | `ethers.verifyMessage()` + message validation |
| EIP-712 | Typed data (permits) | High | `TypedDataEncoder` + domain validation |
| rawHash | Custom schemes | Advanced | `recoverAddress()` + custom validation |

**When to use each method:**

- **EIP-191**: Default choice for simple message signing
- **SIWE**: Authentication flows, login, session management
- **EIP-712**: Token permits, DAO voting, NFT minting, gasless transactions
- **rawHash**: Safe multisig, pre-computed hashes, custom cryptographic schemes

**Security best practices:**

1. **Validate message content**: Always validate what the user is signing
2. **Domain binding**: For EIP-712 and SIWE, ensure domain matches your application
3. **Expiration times**: Use expiration for time-sensitive signatures
4. **Nonce management**: Prevent replay attacks with unique nonces (especially SIWE)
5. **Chain ID validation**: Always include and validate the correct chain ID

### Security Best Practices for Modes

**When to use each mode:**

| Mode | Use Case | Private Key Exposed | Sessions |
|------|----------|---------------------|----------|
| STANDARD | Most applications | ❌ No | ✅ Yes |
| STRICT | Banking, high-value | ❌ No | ❌ No |
| YOLO | Gaming, low-value | ✅ Yes | ✅ Yes |

**Examples:**

```typescript
// Financial application: Use STRICT mode
async function signTransfer(amount: number, recipient: string) {
  const result = await w3pk.signMessage(
    `Transfer ${amount} to ${recipient}`,
    { mode: 'STRICT' }  // Always requires auth
  )
  return result.signature
}

// Gaming application: Use YOLO mode with custom tag
async function signGameAction(action: string) {
  const result = await w3pk.signMessage(action, {
    mode: 'YOLO',
    tag: 'GAMING'
  })
  return {
    signature: result.signature,
    fromAddress: result.address  // Gaming-specific address
  }
}

// Display/view operations: Use STANDARD mode (default)
async function signProof() {
  const result = await w3pk.signMessage("Prove ownership")
  return result.signature
}
```

### Address Verification

Always verify which address signed a message:

```typescript
const result = await w3pk.signMessage("Important message", {
  mode: 'YOLO',
  tag: 'TRADING'
})

// Verify the signature is from the expected address
const wallet = await w3pk.deriveWallet('YOLO', 'TRADING')
console.assert(
  result.address === wallet.address,
  "Signature must be from trading address"
)

// Use ethers to verify the signature
import { verifyMessage } from 'ethers'
const recovered = verifyMessage("Important message", result.signature)
console.assert(
  recovered.toLowerCase() === result.address.toLowerCase(),
  "Signature verification failed"
)
```

## Traditional Security Guarantees

### ✅ Protected Against

1. **Cross-origin / cross-site access** - Another origin cannot read this origin's storage or use its passkey (browser-enforced)
2. **Phishing** - Passkey is bound to the exact hostname; a look-alike domain cannot use it
3. **Browser-storage read access** - The stored wallet's key needs the passkey's PRF output; storage alone doesn't decrypt it (except a silent "Remember Me" session, whose key is stored)
4. **Remote network attacks** - No secret is transmitted; decryption needs the authenticator
5. **Signature replay** - Fresh WebAuthn challenge each time

### ⚠️ NOT Protected Against

1. **Silent "Remember Me" sessions** - With `requireReauth: false`, the session key is stored next to the blob, so storage read access decrypts it (see [At-Rest Encryption](#at-rest-encryption-what-it-protects-and-what-it-doesnt))
2. **Compromised origin code** - XSS, a malicious dependency, or a compromised CDN runs *as* your origin and can use an active or persistent session
3. **Physical coercion** - Forcing the user to authenticate
4. **Compromised authenticator** - If the hardware is backdoored
5. **Unlocked-device / active-session theft** - Wallet reachable while a session is live

## Threat Model

Understanding w3pk's security boundaries is critical for proper deployment. The security model relies on **multiple layers of protection**, not just encryption. The first boundary to understand is the one that doesn't exist:

### The Host App Is Trusted, by Construction

w3pk runs inside the host app's page, as code the host serves, in the host's origin. The host's JavaScript picks every challenge the passkey signs. The WebAuthn prompt shows "use your passkey for example.com" and the account — never what is being signed. **The user approves a prompt, not a transaction.** A rogue host can put "send everything to me" behind a prompt the user thinks is for something else.

This holds for **every signing path** — `signMessage()`, `sendTransaction()`, `signAuthorization()`, stealth signing, and `PRIMARY` UserOperations alike. WebAuthn attests *which origin asked*, never *what is being signed*, and any "review your transaction" UI drawn inside the host's page is drawn by the host. It cannot be fixed while the signing code runs in the host's origin. [Build verification](./BUILD_VERIFICATION.md) lets an honest host prove which w3pk build it serves; it doesn't protect anyone from a dishonest host.

Two things bound the damage:

- **The wallet is per-app.** The passkey is bound to the host's RP ID and every key is derived per origin, so a rogue host can only steal from the wallet that exists because of that host — closer to "the app custodies its own wallet" than "the app can rob your wallet".
- **In `PRIMARY`, theft needs the user present.** The host can't extract a key or sign once the user has left: it has to put the malicious operation behind a live prompt, per user, and the result is visible onchain and attributable to the app. That is strictly better than a custodial operator, who can take everything at once, silently.

**What this trust model is for.** w3pk competes with custodial and embedded wallets, not with hardware wallets. It fits where the host is the counterparty anyway, or where little is at stake: authentication (SIWE), Semaphore/ZK identities, encryption keys, attestations, assets the app itself issues, closed-loop payments, session funds for games, mints and micro-payments, and receiving (a stealth meta-address can receive at any size; only the spend path is exposed). It is an onboarding ramp, not a vault: once a balance matters, move it to a wallet the host doesn't control (see [PORTABILITY.md](./PORTABILITY.md)).

**What it is not for:** anything the user would not hand to the app itself — DeFi positions, savings, a treasury. **Fund it like a transit card, not a savings account**, and say so in your app wherever it suggests funding the wallet.

### Security Layers (Strongest to Weakest)

#### 1. WebAuthn Authentication (Strongest Boundary) ✅

**What it protects:**
- Unauthorized access via w3pk SDK
- Remote attacks without physical device access
- Phishing attacks (domain-scoped credentials)
- Cross-site attacks (origin isolation)

**How it works:**
- Browser enforces biometric/PIN authentication
- Cannot be bypassed without physical access + user authentication
- User sees domain in authentication prompt
- Credentials are cryptographically bound to domain

**Limitations:**
- Requires user interaction (can be socially engineered)
- User must verify domain in prompt (many users don't)
- Doesn't protect against session hijacking after authentication

#### 2. PRF-Keyed Encryption (Strong Protection) ✅

**What it protects:**
- File system and browser-storage access (encrypted at rest)
- Copied browser profiles, disk images and backups
- Storage exfiltration by an extension or a one-shot XSS, when no session is live

**How it works:**
- Wallet encrypted with AES-256-GCM
- Key derived (HKDF-SHA256) from the passkey's PRF output, released only on a user-verified assertion
- Authenticators without PRF keep no wallet on the device

**Limitations:**
- Doesn't protect the mnemonic while a session holds it in memory
- A silent "Remember Me" session (`requireReauth: false`) stores its own key; storage read access decrypts that blob
- An attacker who can make the user authenticate (XSS prompting a login) gets a fresh PRF output

**Honest assessment:**
```typescript
// What an attacker with file access CAN'T do:
const key = deriveWalletKey(???)   // ❌ the PRF output never leaves the authenticator unprompted
// The stored credentialId and publicKey don't help

// What they CAN do (with code running in the origin):
await w3pk.login()  // ⚠️ Prompts the user, who may accept
```

**Device security still matters:**
- Use device encryption (FileVault, BitLocker)
- Use strong device passwords
- Don't leave device unlocked

#### 3. Session Management (Moderate Protection) ⚠️

**What it protects:**
- Time-limited exposure after authentication
- Automatic expiration of cached credentials
- Cleared on browser close

**How it works:**
- Decrypted mnemonic cached in memory only
- Expires after configured duration (default: 1 hour)
- Never written to disk

**Limitations:**
- **Active session = mnemonic in memory**
- Code injection during session can access wallet
- `requireAuth` flag can be bypassed by attacker with JS execution
- Session is in the same JavaScript context as page code

**Attack window:**
```typescript
// Attacker with XSS access during active session:
if (w3pk.hasActiveSession()) {
  const { privateKey } = await w3pk.deriveWallet('YOLO', 'MAIN', { requireAuth: false })
  // ⚠️ SUCCESS - Session allows access, requireAuth is bypassable
  sendToAttacker(privateKey)
}

// After session expires:
await w3pk.deriveWallet('YOLO', 'MAIN', { requireAuth: false })
// ❌ BLOCKED - Session expired, triggers authentication prompt
```

**Mitigation:**
- Use short sessions (`sessionDuration: 0.1` = 6 minutes)
- Or disable sessions entirely (`sessionDuration: 0`)
- Prevent XSS (CSP, input sanitization)

#### 4. `requireAuth` Flag (Weak - UX Only) ❌

**What it protects:**
- User mistakes (accidental clicks)
- Application-level policy enforcement
- User experience (confirmation for sensitive actions)

**How it works:**
- Developer sets `requireAuth: true` for sensitive operations
- SDK triggers fresh authentication prompt

**Limitations:**
- **NOT a security boundary**
- Can be trivially bypassed by code injection:
  ```typescript
  // Attacker bypasses requireAuth
  await w3pk.deriveWallet('YOLO', 'MAIN', { requireAuth: false })  // ✅ Bypassed
  ```
- Only protects against honest mistakes, not malicious attacks
- Think: seatbelt reminder, not bulletproof vest

**When it helps:**
- Preventing accidental high-value transactions
- Compliance requirements (audit trails showing authentication)
- User education (prompting awareness of sensitive operations)

**When it doesn't help:**
- XSS attacks (attacker controls the JavaScript)
- Malicious browser extensions
- Compromised dependencies
- Any scenario where attacker has code execution

### Threat Scenarios Matrix

| Threat | Layer 1 (WebAuthn) | Layer 2 (Encryption) | Layer 3 (Session) | Layer 4 (requireAuth) | Overall |
|--------|-------------------|---------------------|------------------|----------------------|---------|
| **File system access** | ✅ Blocks SDK use | ✅ Needs the passkey | N/A | N/A | ✅ Protected (⚠️ silent "Remember Me") |
| **Malware (no session)** | ✅ Blocks SDK | ✅ Needs the passkey | ✅ No cache | N/A | ✅ Protected (⚠️ silent "Remember Me") |
| **Malware (active session)** | ✅ Blocks new auth | ✅ Needs the passkey | ❌ Cache accessible | ❌ Bypassable | ❌ Full access |
| **XSS (no session)** | ⚠️ Phishable | ✅ Needs the passkey | ✅ No cache | N/A | ⚠️ Needs auth prompt |
| **XSS (active session)** | ⚠️ Phishable | ✅ Needs the passkey | ❌ Cache accessible | ❌ Bypassable | ❌ Full access |
| **Phishing attack** | ✅ Domain isolation | ✅ Different RP ID | N/A | N/A | ✅ Protected |
| **Database theft only** | ✅ No metadata | ✅ Need metadata | N/A | N/A | ✅ Protected |
| **Credential theft only** | ✅ Need encrypted wallet | ✅ No wallet | N/A | N/A | ✅ Protected |
| **Physical coercion** | ❌ Can force auth | N/A | ❌ Can establish session | ❌ Bypassable | ❌ Vulnerable |
| **Device theft (locked)** | ✅ Need device unlock | ✅ Device encryption helps | N/A | N/A | ✅ Protected |
| **Device theft (unlocked)** | ⚠️ Can auth | ⚠️ Can access files | ⚠️ May have session | ❌ Bypassable | ❌ Vulnerable |
| **Remote network attack** | ✅ Need physical access | ✅ Need physical access | ✅ Not over network | N/A | ✅ Protected |

### Key Takeaways

**What w3pk IS:**
- ✅ Protection against remote attacks without device access
- ✅ Protection against credential theft from other domains (phishing)
- ✅ Protection against storage theft (encryption at rest, keyed by the passkey)
- ✅ Protection against keyloggers (no password needed)
- ✅ Better than password-based wallets for online threats

**What w3pk IS NOT:**
- ❌ Protection against a malicious host app — the host is trusted by construction, in every mode, `PRIMARY` included (see [The Host App Is Trusted, by Construction](#the-host-app-is-trusted-by-construction))
- ❌ Protection against storage theft with a silent "Remember Me" session (its key is stored)
- ❌ Protection against code injection with active session (XSS during session)
- ❌ Protection against physical device compromise (need device encryption + strong password)
- ❌ Immune to social engineering (user can be tricked into authenticating)

**Comparison to other approaches:**

| Security Model | w3pk | MetaMask | Hardware Wallet |
|---------------|------|----------|-----------------|
| Remote attack protection | ✅ Strong | ⚠️ Password-dependent | ✅ Strong |
| Local file access | ✅ Cannot decrypt (PRF) | ⚠️ Password-dependent | ✅ Cannot decrypt |
| Active session compromise | ❌ Vulnerable | ❌ Vulnerable | ⚠️ Per-tx approval |
| Physical theft (locked) | ✅ Protected | ⚠️ Password-dependent | ✅ Protected |
| User experience | ✅ Biometric | ⚠️ Password typing | ⚠️ Hardware required |

**Recommendation:** w3pk is best suited for:
- Applications where user convenience is important
- Scenarios where remote attacks are the primary threat
- Use cases with short sessions or disabled sessions for sensitive operations
- Combined with device encryption and strong device passwords
- Not as a replacement for hardware wallets for high-value holdings (>$10k)

---

## EIP-7702 Authorization Security

EIP-7702 allows EOAs to delegate code execution to smart contracts through authorization signatures. This is a powerful feature that enables gasless transactions, but requires careful security considerations.

### What is EIP-7702?

EIP-7702 authorizations allow an EOA to **permanently delegate** its code execution to a contract until explicitly revoked. This enables:
- Gasless transactions (sponsor pays gas)
- Smart contract wallet features on regular EOAs
- Account abstraction without deployment

**Critical: Authorizations are PERSISTENT** - they remain active until revoked, not just for a single transaction.

### Security Model

#### Authorization Lifecycle

1. **Sign Authorization (Offline)** - User signs authorization with `signAuthorization()`
2. **First Transaction** - Authorization included in transaction, establishes permanent delegation
3. **All Future Transactions** - Delegation persists, no new authorization needed
4. **Revocation (Manual)** - User must explicitly sign new authorization to revoke

#### Threat Analysis

**✅ Protected Against:**
- Silent `signAuthorization()` calls (every call needs a fresh passkey assertion; an active session is not enough)
- Silent `signMessage(hash, { signingMethod: 'rawHash' })` calls on an authorization digest (rawHash always needs a fresh passkey assertion, since a bare hash can't be told apart from `keccak256(0x05 || rlp([chain_id, address, nonce]))`)
- Master key delegation (signs with the origin-specific derived key, never `m/44'/60'/0'/0/0`)
- Phishing (authorization bound to specific contract address + chain ID)
- Replay attacks (nonce-based protection)
- Cross-chain attacks (chain ID binding)

**⚠️ Requires Careful Handling:**
- **Permanent delegation** - User authorizes contract INDEFINITELY
- **Contract security** - If contract is malicious/buggy, user's EOA is compromised
- **No automatic expiration** - Delegation persists until manual revocation
- **Contract upgrades** - If delegated contract is upgradeable, consider upgrade risks

**❌ NOT Protected Against:**
- Malicious contracts (user must verify contract is trustworthy)
- Social engineering (user can be tricked into authorizing bad contracts)
- XSS that tricks the user into approving the passkey prompt for an attacker's contract
- A script holding a YOLO key: YOLO keys are exposed by design (`deriveWallet('YOLO', tag)` returns the private key), so a delegation for that address can be signed without w3pk

### Security Best Practices

#### 1. Contract Verification (CRITICAL)

**DO:**
- ✅ Only authorize audited, verified contracts
- ✅ Verify contract address matches expected contract
- ✅ Check contract is not upgradeable, or understand upgrade mechanism
- ✅ Understand what the contract can do with your account
- ✅ Test with small amounts first
- ✅ Monitor authorization usage on-chain

**DON'T:**
- ❌ Authorize unknown or unaudited contracts
- ❌ Sign authorizations from untrusted UIs
- ❌ Assume authorization is "temporary" or "one-time"
- ❌ Ignore warnings about permanent delegation

**Example - Safe Authorization:**

```typescript
// GOOD: Verify contract before authorizing
const VERIFIED_GOV_CONTRACT = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1'
const AUDIT_REPORT = 'https://audits.example.com/gov-v1.pdf'

// Show user what they're authorizing
console.log(`
⚠️  AUTHORIZATION WARNING
You are about to PERMANENTLY delegate your account to:
Contract: ${VERIFIED_GOV_CONTRACT}
Purpose: Gasless governance voting
Audit: ${AUDIT_REPORT}

This delegation will persist until you explicitly revoke it.
`)

// Only proceed with user confirmation
if (await getUserConfirmation()) {
  const auth = await w3pk.signAuthorization({
    contractAddress: VERIFIED_GOV_CONTRACT,
    chainId: 11155111
  })  // Always prompts for the passkey
}
```

#### 2. Fresh Authentication and Signing Key

`signAuthorization()` never uses the session cache: every call triggers a passkey assertion (user-verified with the default `userVerification: 'required'`), so it cannot be called silently during an active session. It takes no private key, and `signMessage()` with `signingMethod: 'rawHash'` gets the same fresh assertion. It signs with the origin-specific derived key for `mode` and `tag` (default `STANDARD` / `MAIN`, the same address `sendTransaction()` uses), never the master key. `PRIMARY` mode is refused.

```typescript
const authorization = await w3pk.signAuthorization({
  contractAddress: govContract,
  chainId: 1
}, {
  mode: 'STRICT',
  tag: 'GOV'
})
```

#### 3. Monitoring and Revocation

**Check if account is already authorized:**

```typescript
import { publicClient } from 'viem'

// Check if EOA has delegated code
const code = await publicClient.getCode({ address: userAddress })
const isAuthorized = code && code.length > 2

if (isAuthorized) {
  console.log('⚠️  Account already has active delegation')
  // Show user current delegation details
  // Offer to revoke if desired
}
```

**Revoke delegation when no longer needed:**

```typescript
// Revoke by delegating to zero address
const revocation = await w3pk.signAuthorization({
  contractAddress: '0x0000000000000000000000000000000000000000',
  chainId: 11155111,
  nonce: currentNonce + 1n
})

await walletClient.sendTransaction({
  to: userAddress,
  value: 0n,
  authorizationList: [revocation]
})
```

#### 4. Private Key Handling

**For derived and stealth addresses:**

```typescript
// GOOD: Let the SDK sign; the key never reaches the app
const auth = await w3pk.signAuthorization(
  { contractAddress: govContract, chainId: 1 },
  { mode: 'STANDARD', tag: 'GOVERNANCE' }
)

// Stealth payments are signed inside the SDK too
const rawTx = await w3pk.stealth.signTransaction(announcement, tx)

// BAD: Store private keys long-term (e.g. a YOLO key)
localStorage.setItem('privateKey', yoloWallet.privateKey)  // ❌ NEVER DO THIS
```

#### 5. User Education

**Always inform users about permanent delegation:**

```typescript
// Show clear warning before authorization
const WARNING = `
⚠️  PERMANENT DELEGATION WARNING

You are signing an EIP-7702 authorization that will:
• PERMANENTLY delegate your account to a smart contract
• Allow the contract to execute transactions on your behalf
• Persist until you explicitly revoke it
• Cannot be automatically expired or cancelled

Only proceed if you trust this contract and understand the risks.

Contract: ${contractAddress}
Chain: ${chainId}
`

console.warn(WARNING)
await displayWarningModal(WARNING)
```

### Integration Security

#### Recommended Pattern

```typescript
import { createWeb3Passkey } from 'w3pk'

async function authorizeGovernanceContract() {
  const sdk = createWeb3Passkey({
    sessionDuration: 15,  // Short sessions for security
    onError: (error) => {
      logSecurityEvent('authorization_error', error)
    }
  })

  try {
    // 1. Verify contract (offchain)
    const contractInfo = await fetchContractInfo(GOV_CONTRACT)
    if (!contractInfo.verified || !contractInfo.audited) {
      throw new Error('Contract not verified')
    }

    // 2. Check if already authorized
    const code = await publicClient.getCode({ address: userAddress })
    if (code && code.length > 2) {
      console.log('Already authorized')
      return
    }

    // 3. Show warning to user
    const confirmed = await showAuthorizationWarning(contractInfo)
    if (!confirmed) return

    // 4. Sign (always prompts for biometric/PIN)
    const authorization = await sdk.signAuthorization({
      contractAddress: GOV_CONTRACT,
      chainId: CHAIN_ID,
      nonce: 0n
    })

    // 5. Submit first transaction
    const hash = await walletClient.sendTransaction({
      to: GOV_CONTRACT,
      data: firstActionData,
      authorizationList: [authorization]
    })

    // 6. Monitor transaction
    const receipt = await publicClient.waitForTransactionReceipt({ hash })

    // 7. Log successful authorization
    logSecurityEvent('authorization_success', {
      contract: GOV_CONTRACT,
      chainId: CHAIN_ID,
      txHash: hash
    })

    // 8. Store authorization record for user
    await storeAuthorizationRecord({
      contract: GOV_CONTRACT,
      chainId: CHAIN_ID,
      timestamp: Date.now(),
      txHash: hash
    })

  } catch (error) {
    logSecurityEvent('authorization_failed', error)
    throw error
  }
}
```

### Comparison to Other Signing Methods

| Security Aspect | `signMessage()` | `signAuthorization()` |
|----------------|-----------------|----------------------|
| **Scope** | One message | Permanent delegation |
| **Duration** | Single use | Until revoked |
| **Risk level** | Low | High |
| **Requires fresh auth** | Optional | Always |
| **Contract verification** | N/A | Critical |
| **Can be phished** | Signature only | Entire account |
| **Revocation needed** | N/A | Yes |

### Key Takeaways

1. **EIP-7702 is NOT temporary** - Delegation persists indefinitely
2. **Always verify contracts** - Malicious contract = compromised account
3. **Fresh authentication is enforced** - Every authorization prompts for the passkey
4. **Monitor authorizations** - Check on-chain code regularly
5. **Educate users** - Make delegation persistence crystal clear
6. **Implement revocation** - Provide easy way to revoke when needed
7. **Log security events** - Track authorizations for security monitoring

**For more details, see:**
- [EIP-7702 Complete Guide](./EIP_7702.md)
- [signAuthorization() API Reference](./API_REFERENCE.md#signauthorizationparams-signauthorizationparams-options--mode-securitymode-tag-string--promiseeip7702authorization)
- [EIP-7702 Specification](https://eips.ethereum.org/EIPS/eip-7702)

---

## Security Changelog

This section tracks major security-related changes to w3pk's implementation.

### Unreleased - PRF-keyed wallet storage ([#179](https://github.com/w3hc/w3pk/issues/179))

**Impact:** Fixes offline decryption of the wallet stored on the device

**What changed:**
- The stored wallet is encrypted under `deriveWalletKey(prfOutput)`: HKDF-SHA256 of the passkey's PRF output, info `w3pk-prf-wallet-key-v1`
- `deriveEncryptionKeyFromWebAuthn()` (key from `credentialId` and `publicKey`) and the deprecated `deriveEncryptionKey()` are removed
- Authenticators without PRF keep no wallet on the device: in-memory sessions only
- Restore flows evaluate the wallet's PRF input in the assertion they already run
- `VaultSync.createSyncPackage()` / `restoreFromSync()` and the `SyncVault` type are removed: they used the same weak key
- No compatibility layer: an old record is re-encrypted from a PRF persistent session at login, or restored from a backup

### v0.7.0+

#### PRF-based Encryption (Optional Enhancement)
**Impact:** Security improvement when available

**What changed:**
- Added `deriveEncryptionKeyFromWebAuthn()` function for PRF-based encryption
- Added `deriveEncryptionKeyAuto()` helper with automatic PRF detection and fallback
- Implements random unique salts when using PRF
- Added `generateSalt()` helper for creating cryptographic random salts

**Security improvements (when PRF available):**
- ✅ Key material derived from authenticator secret (PRF output), not public credentialId/publicKey
- ✅ Uses random 32-byte salts stored with ciphertext
- ✅ Eliminates offline decryption vulnerability
- ✅ Prevents precomputation attacks

**Current implementation:**
```typescript
// SDK automatically uses PRF when available
const key = await deriveEncryptionKeyAuto(
  prfOutput,      // undefined if PRF not available
  salt,           // undefined if PRF not available
  credentialId,   // used in fallback mode
  publicKey       // used in fallback mode
);
```

**Status:**
- ✅ PRF support added for Chrome 108+, Safari 17+
- ⚠️ **Legacy fallback active**: Uses credentialId/publicKey when PRF unavailable (removed in [#179](https://github.com/w3hc/w3pk/issues/179))
- ⚠️ **Known vulnerability**: Legacy encryption vulnerable to offline decryption attacks (fixed in [#179](https://github.com/w3hc/w3pk/issues/179))
- 🔴 **Firefox not supported**: Firefox does not implement PRF extension yet
- 📖 See [BROWSER_COMPATIBILITY.md](BROWSER_COMPATIBILITY.md) for details

**Recommendation:**
- Backup files use password-based encryption (portable across devices)
- Local device storage uses PRF when available, legacy fallback otherwise
- Users should create password-protected backups for security

### v0.7.0 - RP ID Auto-Detection (Security Hardening)

**What changed:**
- Removed manual `rpId` configuration option
- RP ID now automatically set to `window.location.hostname`
- Cannot be overridden by developers

**Why this improves security:**
- Prevents misconfiguration that could lead to security vulnerabilities
- Enforces domain isolation (credentials can't be shared across origins)
- Eliminates risk of developers setting overly broad RP IDs
- Simplifies API and reduces surface for errors

**Migration:**
```typescript
// v0.6.0 (old - REMOVED)
const w3pk = createWeb3Passkey({
  rpId: 'example.com',  // Manual configuration (now removed)
})

// v0.7.0+ (current - REQUIRED)
const w3pk = createWeb3Passkey({
  // rpId is auto-detected from window.location.hostname
  // Cannot be overridden
})
```

**Impact:** Breaking change for v0.6.0 users. Credentials created with custom RP IDs may not work. Users must re-register or import mnemonic.

### Backup Encryption Standards

#### Current: WebAuthn PRF for the wallet, Argon2id for backup files

**Wallet encryption:** HKDF-SHA256 of the passkey's PRF output
- The PRF output is 32 bytes of full-entropy key material held by the authenticator, so there is nothing to stretch
- Storage alone can't decrypt the wallet

**Backup file encryption (BackupFile v4):** Argon2id, m=64 MiB, t=3, p=4
- Primary threat: Offline attacks (backups may be on USB/cloud)
- PBKDF2 isn't memory-hard, so GPUs run it massively in parallel. Argon2id makes each guess fill 64 MiB, which caps a GPU's parallelism by its memory rather than its cores
- RFC 9106's second recommendation. It takes about 1 to 2 s in pure JavaScript (`@noble/hashes`, Node 24, Apple Silicon), so the offline extractor can run it in a browser. Each file records its parameters, so backups made before v0.11.1 at OWASP's minimum (19 MiB, t=2, p=1) still restore

**Why different?**
Different threat models require different protections. Password backups may be stored offline and face brute force attacks, while the wallet on the device is bound to the passkey.

### Password Validation Enhancement

**Added:** `isStrongPassword()` utility
- 15 to 256 characters, counted in Unicode code points after NFC normalization
- Any characters: spaces, accents and emoji are fine, and no mix of character types is required
- Not one of the 1,000 most common passwords of that length (whole-password match, any case, ignoring spaces, dots, dashes and underscores), and not a single repeated character

**Location:** `src/utils/validation.ts` (exported from main package)

**Usage:**
```typescript
import { isStrongPassword } from 'w3pk'

if (!isStrongPassword(userPassword)) {
  throw new Error('Password too weak')
}
```

**Note:** Password validation is client-side only. Applications should implement server-side validation for production use.

### Known Limitations & Future Improvements

#### Current Limitations

1. **Session Security**
   - Current: Mnemonic cached in JavaScript memory during sessions
   - Limitation: XSS during session can access wallet
   - Mitigation: Short sessions, XSS prevention (CSP)

#### Under Consideration

1. **Web Workers for Session Isolation**
   - Investigate running wallet operations in dedicated Web Worker
   - Would isolate mnemonic from page JavaScript context
   - Challenge: WebAuthn API not available in Workers (requires postMessage)

2. **Rate Limiting**
   - Add built-in rate limiting for authentication attempts
   - Track failed attempts, exponential backoff
   - Protection against brute force via authentication

### Reporting Security Issues

If you discover a security vulnerability in w3pk, please report it responsibly:

**Do NOT:**
- Open a public GitHub issue
- Discuss on social media or public forums
- Attempt to exploit in production systems

**Do:**
- Report privately via [GitHub Security Advisories](https://github.com/w3hc/w3pk/security/advisories/new)
- Provide detailed reproduction steps
- Wait for confirmation before public disclosure
- Follow responsible disclosure timeline (typically 90 days)

**We will:**
- Acknowledge receipt within 48 hours (within 24 hours for a vulnerability reported as actively exploited)
- Investigate and provide updates
- Work on a fix and coordinate disclosure
- Credit you in security advisories (if desired)

### Coordinated Disclosure and Downstream Compliance (EU Cyber Resilience Act)

w3pk is FOSS (GPL-3.0) published outside the course of a commercial activity, which keeps it outside direct CRA "manufacturer" obligations. Applications that embed w3pk and are placed on the EU market commercially are generally the "manufacturer" under the CRA, and carry its vulnerability-handling duties — including the 24-hour early warning and 72-hour report to ENISA/CSIRTs for an actively exploited vulnerability, once the relevant CRA provisions apply.

The acknowledgment timeline above exists to support that: a fast, accurate advisory from us is what lets a downstream integrator meet their own reporting clock. If you are shipping a commercial product built on w3pk, treat our GitHub Security Advisories as your upstream source and don't wait on us past those windows — file your own report on the timeline the CRA requires and update it as we provide details.

**Outside the EU:** no direct equivalent imposes the same fixed vulnerability-reporting clock on a wallet SDK. The US has no mandatory product-security law comparable to the CRA — the closest analogue, the FCC's Cyber Trust Mark, is a voluntary IoT label; sector-specific rules (the SEC's 4-business-day incident disclosure, CISA's CIRCIA reporting) apply to public companies and critical-infrastructure operators, not FOSS maintainers or typical wallet integrators. China's amended Cybersecurity Law (effective January 1, 2026) tightens incident-reporting timelines and adds personal liability for responsible officers, but it is a data/incident-security regime, not a CRA-style product certification, and applies to entities operating in China rather than to this project. Integrators distributing into those markets should check their own obligations under those regimes separately; this section covers the EU CRA specifically because it is the one with reporting deadlines that reach this project's disclosure process.

## How It Works

### 1. Encryption Key Derivation

**The encryption key is derived from the passkey's WebAuthn PRF output:**

```typescript
// Registration asks the authenticator to evaluate the PRF at a fixed input
const credential = await navigator.credentials.create({
  publicKey: {
    // ...
    extensions: { prf: { eval: { first: PRF_INPUT } } }
  }
})

// Platforms that don't evaluate the PRF at creation get one assertion instead
const prfOutput =
  credential.getClientExtensionResults().prf?.results?.first ??
  (await evaluatePrf(PRF_INPUT, credential.id)).output

// HKDF-SHA256, info "w3pk-prf-wallet-key-v1" → non-extractable AES-256-GCM key
const key = await deriveWalletKey(prfOutput)
const encryptedWallet = await encryptData(mnemonic, key)
```

At `login()`, the same assertion that authenticates evaluates the PRF at the same input, so it releases the same output and the same key.

**Important security properties:**

- The key is **deterministic per passkey** - the fixed input gives the same PRF output at every assertion.
- Its only input is the PRF output, which the authenticator releases **only during a user-verified assertion**. `credentialId` and `publicKey` in localStorage don't help derive it.
- The prompt is now a **cryptographic** boundary for the wallet at rest, not only an SDK control-flow gate.
- Without PRF support, the wallet is never stored on the device.

**What an attacker with storage read access can do:**

```typescript
// Attacker has copied this origin's localStorage
const stolenCredentialId  = "..."   // from w3pk_wallet_<credentialId>
const stolenPublicKey     = "..."   // from w3pk_credential_<id>
const stolenEncryptedSeed = "..."   // from w3pk_wallet_<credentialId>

// No key can be derived from these: the PRF output stays in the authenticator
// ❌ seed not recoverable offline
```

**Trade-off: usability.** After a successful `login()`, the SDK caches the decrypted mnemonic in memory (and, if persistent sessions are enabled, in a PRF-keyed blob on disk) so operations don't re-prompt. A silent "Remember Me" session (`requireReauth: false`) stores its key next to the blob, which brings back storage-read exposure for that blob (see [At-Rest Encryption → "Remember Me"](#at-rest-encryption-what-it-protects-and-what-it-doesnt)).

### 2. What's Stored

> None of the values below decrypts the wallet: its key needs the passkey's PRF output (see the key derivation above). A silent "Remember Me" session is the exception: its stored key decrypts its own blob.

#### LocalStorage (Credentials)
```json
{
  "id": "credential-abc123",
  "publicKey": "MFkw...EwYH...AQAB",  // PUBLIC key only
  "username": "alice",
  "ethereumAddress": "0x1234...5678",
  "createdAt": 1234567890
}
```

#### LocalStorage (Encrypted Wallet, `w3pk_wallet_<credentialId>`)
```json
{
  "ethereumAddress": "0x1234...5678",
  "encryptedMnemonic": "v1kT...x3Zp",  // AES-GCM encrypted
  "credentialId": "credential-abc123",
  "createdAt": 1234567890
}
```

**No *individually* secret values are stored:**
- No private keys
- No challenge values
- No stored decryption key *object*

**But** the stored public identifiers (`credentialId` + `publicKey`) are exactly the key-derivation inputs, so possessing both stores is equivalent to possessing the decryption key. The absence of a stored key object is not a security boundary here.

### 3. Credential Metadata in LocalStorage

Credential metadata is stored in plain text, under `w3pk_credential_<hash>`, where `<hash>` is the base64url SHA-256 of `"w3pk-cred-id:" + credentialId`, with the credential IDs listed in `w3pk_credential_index`:

```json
{
  "id": "credential-abc123",
  "publicKey": "MFkw...AQAB",
  "username": "alice",
  "ethereumAddress": "0x1234...5678",
  "createdAt": "2026-11-03T10:00:00Z",
  "lastUsed": "2026-11-03T10:00:00Z",
  "signCount": 12
}
```

**Any script on the page can read the username and Ethereum address**, and so can extensions with access to the site and anyone who can read the browser profile. `login()` reads this list before any passkey prompt to build `allowCredentials`, so the metadata can't be encrypted under a key that isn't already on the device. None of it unlocks the wallet: the mnemonic is encrypted under a key from the passkey's PRF output (see above).

From v0.7.4 to v0.11.0, the username and address were encrypted under a key derived from `SHA-256("w3pk-metadata-v1:" + credentialId)`, with the credential ID stored in clear in the index, so the encryption hid nothing. Entries stored by v0.11.0 and earlier are treated as absent: after upgrading, `login()` throws `SyncRequiredError` and the wallet is restored from a backup.

### 4. Storage Architecture

Understanding where w3pk stores data and how browser security mechanisms protect it is critical for threat modeling.

#### Storage Layers

```
┌─────────────────────────────────────────────────────────────┐
│ Browser (Origin: https://example.com)                       │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ localStorage (Origin-Scoped)                           │ │
│  │ Key: w3pk_credential_<hashed credentialId>             │ │
│  │                                                          │ │
│  │ {                                                        │ │
│  │   "id": "credential-abc123",          // PUBLIC        │ │
│  │   "publicKey": "MFkw...AQAB",         // PUBLIC        │ │
│  │   "username": "alice",                 // PUBLIC        │ │
│  │   "ethereumAddress": "0x1234...",     // PUBLIC        │ │
│  │   "createdAt": 1234567890              // PUBLIC        │ │
│  │ }                                                        │ │
│  │                                                          │ │
│  │ ⚠️  All data here is PUBLIC - no secrets               │ │
│  │ ⚠️  Can be read by JavaScript on same origin           │ │
│  │ ⚠️  Stored in plaintext on disk                         │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ localStorage (Origin-Scoped)                           │ │
│  │ Key: w3pk_wallet_<credentialId>                        │ │
│  │                                                          │ │
│  │ {                                                        │ │
│  │   "ethereumAddress": "0x1234...",     // PUBLIC        │ │
│  │   "encryptedMnemonic": "v1kT...x3Zp", // ENCRYPTED     │ │
│  │   "credentialId": "credential-abc123", // PUBLIC        │ │
│  │   "createdAt": 1234567890              // PUBLIC        │ │
│  │ }                                                        │ │
│  │                                                          │ │
│  │ ✅  Encrypted mnemonic requires decryption key          │ │
│  │ ✅  Key needs the passkey's PRF output                  │ │
│  │ ✅  Nothing in storage derives it                       │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Memory (JavaScript Heap) - During Active Session       │ │
│  │                                                          │ │
│  │ Session Object {                                        │ │
│  │   mnemonic: "word1 word2 ... word12",  // PLAINTEXT    │ │
│  │   expiresAt: 1234567890,               // Timestamp    │ │
│  │   credentialId: "credential-abc123"    // Reference    │ │
│  │ }                                                        │ │
│  │                                                          │ │
│  │ ⚠️  Plaintext mnemonic in JavaScript memory             │ │
│  │ ⚠️  Accessible to all JavaScript in same context        │ │
│  │ ⚠️  Dropped on logout or expiration (not zeroed: JS     │ │
│  │     strings are immutable, so it stays until GC)       │ │
│  │ ⚠️  Never written to disk (unless OS swap/hibernate)    │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Operating System / Hardware                                  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Secure Enclave / TPM / Hardware Authenticator          │ │
│  │                                                          │ │
│  │ WebAuthn Credential {                                   │ │
│  │   privateKey: <HARDWARE_PROTECTED>,    // SECRET       │ │
│  │   rpId: "example.com",                  // Bound       │ │
│  │   credentialId: "credential-abc123",    // PUBLIC      │ │
│  │   userHandle: <32 random bytes>         // PUBLIC      │ │
│  │ }                                                        │ │
│  │                                                          │ │
│  │ ✅ Private key CANNOT be exported                       │ │
│  │ ✅ Operations happen inside secure hardware             │ │
│  │ ✅ Requires biometric/PIN for each signature            │ │
│  │ ✅ Survives OS reinstall (on some platforms)            │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ File System (Browser Profile Directory)                │ │
│  │                                                          │ │
│  │ ~/Library/Application Support/Google/Chrome/Default/   │ │
│  │   └─ Local Storage/                                    │ │
│  │       └─ https_example.com_0.localstorage              │ │
│  │           → Credential metadata and encrypted wallet   │ │
│  │                                                          │ │
│  │ ⚠️  Files stored on disk (not encrypted by browser)     │ │
│  │ ⚠️  OS-level encryption (FileVault/BitLocker) needed    │ │
│  │ ⚠️  Attacker with file access can copy all of it        │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Browser Security Mechanisms

**Origin Isolation:**
- localStorage is **automatically scoped** to origin
- `https://example.com` cannot access `https://attacker.com` storage
- Even subdomains are isolated: `app.example.com` ≠ `example.com`
- Protocol matters: `http://example.com` ≠ `https://example.com`

**WebAuthn Security:**
- Credentials are **cryptographically bound** to RP ID (domain)
- Browser enforces that credentials for `example.com` can only be used on `example.com`
- Even with stolen credential metadata, cannot use on different domain
- User sees domain in authentication prompt

**JavaScript Context:**
- All w3pk code runs in the same JavaScript context as page code
- No process isolation (unlike browser extensions)
- XSS or code injection has full access to w3pk API
- This is why XSS prevention is critical
- `zkProve()` and `getSemaphoreIdentity()` keep their secrets out of the API, not out of reach of code on the same page; the [cross-origin wallet](https://github.com/w3hc/w3pk/issues/156) isolates them fully
- `zkProve()` only refuses public signals equal to the secret or a random input: a circuit can output any function of the secret, the Semaphore secret included, so apps must only prove with circuits they trust
- Stealth keys are shared across origins: every app that enables `stealthAddresses` gets the same meta-address and viewing key, so it can see every stealth payment to the user. w3pk never returns the spending private key or a stealth private key, since the viewing key and any stealth private key are enough to compute the spending key; `stealth.signTransaction()` signs from stealth addresses inside the SDK. Each call runs a fresh passkey assertion, even with an active session, but the user approves a prompt, not the transaction — true of every signing path, not just stealth (see [The Host App Is Trusted, by Construction](#the-host-app-is-trusted-by-construction)) — so only enable `stealthAddresses` in apps you trust with stealth funds. Tracked in [#147](https://github.com/w3hc/w3pk/issues/147). Scoping the keys per origin would change the meta-address and strand funds already sent to it

#### Security Boundaries

**Strong Boundaries (Browser-Enforced):**
1. ✅ **Origin isolation** - Cannot access other domains' storage
2. ✅ **WebAuthn RP ID binding** - Credentials domain-locked
3. ✅ **Secure hardware** - Private keys cannot be exported

**Weak Boundaries (Application-Enforced):**
1. ⚠️ **SDK authentication gating** - Requires honest JavaScript
2. ⚠️ **Session management** - Can be bypassed by code injection
3. ⚠️ **requireAuth flag** - Trivially bypassable

#### Attack Surface by Storage Layer

| Storage Layer | What's Stored | Protection | Attack Surface |
|---------------|---------------|------------|----------------|
| **localStorage** | Credential metadata (public) | Origin isolation | ⚠️ XSS, file access |
| **localStorage** | Encrypted wallet, persistent sessions | Origin isolation + AES-256-GCM | ⚠️ XSS, file access + decryption |
| **Memory** | Plaintext mnemonic (during session) | Process isolation (weak) | ❌ XSS, memory dumps |
| **Secure Enclave** | WebAuthn private key | Hardware protection | ✅ Very strong (HW attacks only) |
| **File System** | Browser profile directory | OS permissions | ⚠️ Malware, physical access |

#### Data Flow

**Registration:**
```
1. User clicks "Register"
2. SDK calls navigator.credentials.create()
3. Browser shows WebAuthn prompt → User provides biometric
4. Secure Enclave generates key pair
5. Browser returns: credentialId, publicKey
6. SDK generates mnemonic
7. SDK derives encryption key from the PRF output (creation, or one assertion)
8. SDK encrypts mnemonic with AES-256-GCM (no PRF: nothing is stored)
9. SDK stores:
   - localStorage: credentialId, publicKey, address (plaintext)
   - localStorage: encryptedMnemonic (ciphertext)
10. Secure Enclave stores: privateKey (hardware-protected)
```

**Login (First Time):**
```
1. User clicks "Login"
2. SDK calls navigator.credentials.get()
3. Browser shows WebAuthn prompt → User provides biometric
4. Secure Enclave signs challenge with privateKey
5. Browser returns: signature
6. SDK verifies signature matches publicKey
7. SDK derives encryption key from the assertion's PRF output
8. SDK decrypts wallet from localStorage
9. SDK stores plaintext mnemonic in memory (session)
10. Session expires after configured duration
```

**Login (With Active Session):**
```
1. User clicks "Sign Transaction"
2. SDK checks: hasActiveSession() → true
3. SDK retrieves mnemonic from memory (no prompt)
4. SDK derives private key from mnemonic
5. SDK signs transaction
6. Transaction sent to network
(No biometric prompt - session is active)
```

**Login (Session Expired):**
```
1. User clicks "Sign Transaction"
2. SDK checks: hasActiveSession() → false
3. SDK triggers WebAuthn authentication
4. Browser shows prompt → User provides biometric
5. SDK decrypts wallet, creates new session
6. SDK signs transaction
```

#### File System Locations by Browser

**Chrome/Chromium (macOS):**
```
~/Library/Application Support/Google/Chrome/Default/
  └─ Local Storage/leveldb/
      └─ https_example.com_0.localstorage
```

**Chrome/Chromium (Windows):**
```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\
  └─ Local Storage\leveldb\
```

**Firefox (macOS):**
```
~/Library/Application Support/Firefox/Profiles/<profile>/
  └─ storage/default/https+++example.com/ls/  (localStorage)
```

**Safari (macOS):**
```
~/Library/Safari/LocalStorage/
~/Library/Safari/Databases/
```

**Security Implications:**
- Browser profile directories are **user-accessible** (not encrypted by browser)
- An attacker with user-level file access can copy these directories
- OS-level encryption (FileVault, BitLocker) is essential
- Malware running as user can access these files
- Cloud backup of browser profiles may expose data

#### Defense in Depth

**Layer 1: Browser Security**
- Origin isolation (strong)
- WebAuthn RP ID binding (strong)
- Process sandboxing (moderate)

**Layer 2: w3pk SDK**
- Authentication gating (moderate - requires honest JS)
- AES-256-GCM encryption (strong - but key is derivable)
- Session management (weak - bypassable)

**Layer 3: Operating System**
- File system permissions (moderate)
- Full disk encryption (strong - FileVault, BitLocker)
- User authentication (moderate - password quality varies)

**Layer 4: Hardware**
- Secure Enclave / TPM (very strong)
- Physical security (depends on user)

**Recommendation:**
- ✅ Enable full disk encryption (FileVault on macOS, BitLocker on Windows)
- ✅ Use strong device password (not just PIN)
- ✅ Lock device when away (auto-lock enabled)
- ✅ Keep browser updated (security patches)
- ✅ Use Content Security Policy to prevent XSS
- ✅ Consider dedicated browser profile for financial apps
- ✅ Don't sync browser profile to cloud for high-security use

### 4. Attack Scenario Analysis

#### ❌ Attack: Copy files and decrypt offline

```javascript
// Attacker steals browser storage
const stolen = {
  encryptedMnemonic: "v1kT...x3Zp",
  credentialId: "credential-abc123",
  publicKey: "MFkw...EwYH...AQAB"
}

// The key is HKDF(PRF output): the PRF output never left the authenticator
const key = deriveWalletKey(???)
//          ❌ BLOCKED - nothing stolen derives the key
```

**Result:** ❌ **Attack fails** - the wallet at rest is bound to the passkey

**Exception:** a silent "Remember Me" session (`requireReauth: false`) stores its key next to its blob. Copying storage then decrypts that blob, for as long as the session lasts.

**Mitigation:** Leave `requireReauth: true` (the default), and use device encryption (FileVault, BitLocker) and strong device passwords as an additional layer.

#### ❌ Attack: JavaScript injection to read wallet

```javascript
// Malicious script tries to access wallet via SDK
const w3pk = new Web3Passkey()

// Try to login and access wallet
await w3pk.login()
//         ^^^^^^
//         BLOCKED: Browser shows WebAuthn authentication prompt
//         User sees requesting domain in the prompt
//         If domain is malicious, user should deny
//         User must explicitly provide biometric/PIN

// Even if user authenticates (phished), credentials are domain-scoped
// The attacker's malicious.com credential cannot decrypt
// wallets encrypted with legitimate.com credentials
```

**Result:** ❌ **Attack fails** - WebAuthn is domain-scoped, preventing cross-origin attacks

**However, if attack happens on the SAME domain (XSS):**

```javascript
// XSS attack on legitimate.com
if (w3pk.hasActiveSession()) {
  // If session is active, attacker can use the wallet
  const { privateKey } = await w3pk.deriveWallet('YOLO')
  sendToAttacker(privateKey)  // ⚠️ SUCCESS during active session
}
```

**Result:** ⚠️ **Attack succeeds if session is active** - This is why:
- Short session durations are critical (`sessionDuration: 0.1` for 6 minutes)
- XSS prevention is essential (CSP, input sanitization)
- The `requireAuth` flag is important but not a security boundary (can be bypassed by XSS)

#### ❌ Attack: Steal credential metadata from another domain

```javascript
// Attacker creates phishing site: examp1e.com (note the "1")
// User has legitimate credential on: example.com

// Attacker steals credential metadata from example.com
const stolenCredentialId = "..."
const stolenPublicKey = "..."
const stolenEncryptedWallet = "..."

// Attacker can't derive the key: it needs the passkey's PRF output

// BUT: To use via WebAuthn, attacker tries to authenticate on examp1e.com
await navigator.credentials.get({
  publicKey: {
    challenge: randomChallenge,
    rpId: "examp1e.com",  // Attacker's domain
    allowCredentials: [{
      id: stolenCredentialId,
      type: "public-key"
    }]
  }
})
//  ❌ BLOCKED: Browser enforces RP ID matching
//  Credential created for "example.com" cannot be used on "examp1e.com"
//  WebAuthn will not find any matching credentials
```

**Result:** ❌ **Attack fails** - WebAuthn credentials are cryptographically bound to the domain (RP ID)

## Encryption Strength

### Wallet Encryption (At Rest)

**Key Derivation:**
- **Algorithm:** HKDF-SHA256
- **Key Material:** WebAuthn PRF output at the fixed input `w3pk-prf-input-v1` (32 bytes, held by the authenticator)
- **Salt:** 32 zero bytes (the key material is uniformly random, so no salt is needed)
- **Info:** `w3pk-prf-wallet-key-v1`
- **Output:** 256-bit AES key, non-extractable

**Encryption:**
- **Algorithm:** AES-256-GCM
- **Key Size:** 256 bits
- **IV:** Random 12 bytes per encryption
- **Authentication Tag:** 16 bytes (automatic with GCM)
- **Additional Authenticated Data:** none — integrity comes from the GCM authentication tag above; no AAD is bound to the ciphertext

**Entropy Analysis:**
- The PRF output is HMAC-SHA256 under a credential secret: 256 bits, never exposed outside a user-verified assertion
- No stretching: there is no low-entropy secret to brute-force

### Backup Encryption (User-Controlled)

**Key Derivation (BackupFile v4, `password`):**
- **Algorithm:** Argon2id (RFC 9106), `@noble/hashes` `argon2idAsync`
- **Parameters:** m=65536 KiB (64 MiB), t=3 passes, p=4 lanes (RFC 9106's second recommendation), stored in the file. v3 backups made before v0.11.1 used m=19456 KiB, t=2, p=1; a v4 file with those parameters still restores
- **Bounds on restore:** at most 64 MiB, 3 passes and 4 lanes, so a crafted file can't freeze the page
- **Salt:** Random 16 bytes per backup
- **Key Material:** User-chosen password, NFC-normalized, UTF-8 encoded
- **Output:** 256-bit AES key

| Parameters | Time (pure JS, Node 24, Apple Silicon) |
|---|---|
| 19 MiB, t=2, p=1 (before v0.11.1) | ~415 ms |
| 46 MiB, t=1, p=1 (OWASP alternative) | ~505 ms |
| 64 MiB, t=3, p=4 (RFC 9106, chosen and the restore bound) | ~1.2 to 2 s |

**Encryption:**
- **Algorithm:** AES-256-GCM
- **Key Size:** 256 bits
- **IV:** Random 12 bytes per encryption, prepended to the ciphertext (`encryptedMnemonic` is `base64(iv || ciphertext)`)
- **Authentication Tag:** 16 bytes (automatic with GCM)
- **Additional Authenticated Data:** none — integrity comes from the GCM authentication tag above; no AAD is bound to the ciphertext

**Password Requirements:**
Enforced on every new password backup (`createBackupFile()`, `setupSocialRecovery()`, `exportForSync(password)`), which throws `WeakPasswordError` with the missing rules in `feedback`. `isStrongPassword()` checks the same rules:
- 15 to 256 characters, counted in Unicode code points after NFC normalization
- Any characters: spaces, accents and emoji are fine, and no mix of character types is required
- Not one of the 1,000 most common passwords of that length (whole-password match, any case, ignoring spaces, dots, dashes and underscores), and not a single repeated character

**Why a Memory-Hard KDF for Backups:**
Backups are designed for offline storage and face different threat models:
- Wallet encryption: Protected by device security + SDK authentication
- Backup encryption: May be stored on USB drives, cloud, paper - offline brute force is the primary threat
- Argon2id's memory cost limits how many guesses a GPU or ASIC runs at once, which PBKDF2's iteration count doesn't

**Brute Force Resistance:**
Argon2id slows each guess but doesn't save a weak password. A random 4+ word passphrase, or a password-manager password, is what makes a stolen file safe.

## Session Management

### How Sessions Work

w3pk implements **secure in-memory sessions** for better UX. After initial authentication, the decrypted mnemonic is cached in memory for a configurable duration.

```typescript
// Configure session duration (default: 1 hour)
const w3pk = new Web3Passkey({
  sessionDuration: 1 // hours
})

// After login, operations work without repeated authentication
await w3pk.login()                   // ✅ Requires biometric
await w3pk.deriveWallet()            // ✅ Uses session (no prompt)
await w3pk.signMessage('Hello')      // ✅ Uses session (no prompt)
await w3pk.stealth.getKeys()         // ✅ Uses session (no prompt)

// Session expires after 1 hour - next operation will prompt
await w3pk.deriveWallet('STANDARD', 'GAMING') // ✅ Prompts for biometric (session expired)
```

### Session Security

w3pk supports **two types of sessions** (v0.8.2+):

1. **In-Memory Sessions** (default): RAM-only, cleared on page refresh
2. **Persistent Sessions** (opt-in): Encrypted in localStorage, survives page refresh

**In-Memory Session (default):**
- ✅ Decrypted mnemonic cached in RAM only
- ✅ Session expiration timestamp
- ✅ Credential ID
- ✅ Cleared on page refresh
- ✅ Cleared on logout
- ✅ Cleared when browser tab closes

**Logout drops the session, it doesn't wipe memory.** The mnemonic is a JavaScript string, and strings are immutable: `clearSession()` overwrites the session's field, which only drops that reference. The original string stays in the heap until the garbage collector reclaims it, along with any copy derived from it (ethers wallet objects, the app's own variables). JavaScript gives no way to zero it, so a heap dump or a memory-reading exploit taken shortly after logout can still find the mnemonic. Closing the tab ends the process's copy.

**Persistent Session (opt-in — "Remember Me"):**
- Mnemonic encrypted in localStorage under a **WebAuthn-PRF-derived key** (HKDF-SHA256 of the authenticator's per-credential PRF secret); survives page refresh for the configured duration
- Re-keyed at every real (prompted) login — the session expiry is the renewal boundary
- `requireReauth: true`: the key is never stored; every restore re-derives it from a live user-verified assertion (blob is hardware-bound at rest)
- `requireReauth: false`: the key is stored as base64url next to the blob for silent restore — readable by anything that can read this origin's localStorage, until the [cross-origin wallet](https://github.com/w3hc/w3pk/issues/156) moves it out of the host app's origin
- Requires a PRF-capable authenticator; without PRF, no persistent session is stored (in-memory only, no weaker fallback)
- Only for STANDARD and YOLO modes; **NEVER** persisted for STRICT mode
- Time-limited expiration; cleared on logout / `clearSession()`

**What's NOT cached:**
- ❌ Private keys (derived on-demand)
- ❌ WebAuthn signatures (fresh each time)

**Security properties:**
- Default (in-memory) sessions exist **only in RAM** - never written to disk
- Persistent sessions are keyed to the authenticator hardware via the PRF extension — a storage-read attacker cannot recompute the key from anything on disk (except with `requireReauth: false`, where the key is stored next to the blob; see [At-Rest Encryption → "Remember Me"](#at-rest-encryption-what-it-protects-and-what-it-doesnt))
- Automatically cleared after expiration; cleared on logout (both RAM and persistent)
- STRICT mode **always** requires fresh authentication (no persistence)

### Session Management API

```typescript
// Configure persistent sessions
const w3pk = createWeb3Passkey({
  sessionDuration: 1,        // In-memory session (1 hour)
  persistentSession: {
    enabled: true,           // Enable "Remember Me"
    duration: 168,           // 7 days (in hours)
    requireReauth: true      // Prompt on page refresh
  }
})

// Check if session is active
const hasSession = w3pk.hasActiveSession()

// Get remaining time (in seconds)
const remaining = w3pk.getSessionRemainingTime()

// Extend session by configured duration
w3pk.extendSession()

// Manually clear session (clears both RAM and persistent)
await w3pk.clearSession()

// Update session duration
w3pk.setSessionDuration(2) // 2 hours

// Disable sessions entirely (most secure)
const w3pkNoSessions = createWeb3Passkey({
  sessionDuration: 0,
  persistentSession: { enabled: false }
})

// Use STRICT mode to disable persistent sessions
const strictWallet = await w3pk.deriveWallet('STRICT')
// STRICT mode ALWAYS bypasses persistent sessions
```

### Force Authentication Option

Developers can require fresh authentication for specific operations, even when a session is active:

```typescript
// Force authentication for sensitive operations
await w3pk.signMessage('Transfer $1000', { requireAuth: true })
await w3pk.deriveWallet('STANDARD', 'SAVINGS', { requireAuth: true })
await w3pk.stealth.getKeys({ requireAuth: true })

// Example: Context-based security
async function transferFunds(amount: number, recipient: string) {
  // Use STRICT mode for high-value transactions
  const mode = amount > 100 ? 'STRICT' : 'STANDARD'

  const result = await w3pk.signMessage(
    `Transfer ${amount} to ${recipient}`,
    { mode }
  )

  // ... submit transaction with result.signature
}

// Example: Backup exports always prompt, even during a session
async function exportBackup(password: string) {
  const { blob, filename } = await w3pk.createBackupFile(password)

  // ... let the user save the file
}
```

**Use cases for `requireAuth: true`:**
- High-value transactions (amount-based)
- Exporting recovery phrases
- Changing critical settings
- Administrative operations
- Time-sensitive operations after long idle

### ⚠️ Important: `requireAuth` is NOT a Security Boundary

**Can `requireAuth` be bypassed?**
**Yes** - An attacker with JavaScript execution in your app can bypass this flag:

```javascript
// Attacker bypasses requireAuth
await w3pk.signMessage('Steal funds', { requireAuth: false })
```

**What `requireAuth` actually protects:**
- ✅ Honest users making mistakes (accidental clicks)
- ✅ Application-level policy enforcement
- ✅ User experience (confirmation for sensitive actions)
- ✅ Compliance requirements (audit trails)

**What `requireAuth` does NOT protect:**
- ❌ Code injection attacks (XSS)
- ❌ Malicious browser extensions
- ❌ Compromised dependencies
- ❌ Active attackers with JS execution

**The REAL security boundaries are:**

1. **WebAuthn Browser Prompt** (Strongest)
   - Cannot be bypassed without physical biometric/PIN
   - Browser-enforced, origin-bound
   - User sees requesting domain

2. **Session Expiration** (Strong)
   - Limits attack window to session duration
   - Attacker must act within time limit
   - Shorter sessions = smaller attack surface

3. **Signature-Based Encryption** (Strong)
   - Protects wallet at rest
   - File system access useless without authentication
   - Cannot decrypt without fresh signature

4. **`requireAuth` Flag** (Weak - UX/Policy Only)
   - Can be bypassed by code injection
   - Not a security boundary
   - Think: seatbelt, not bulletproof vest

**Example Attack Scenarios:**

```typescript
// Scenario: Malicious browser extension active session
// Attacker can steal YOLO keys during session window
setInterval(async () => {
  if (w3pk.hasActiveSession()) {
    const { privateKey } = await w3pk.deriveWallet('YOLO', 'MAIN', { requireAuth: false })
    sendToAttacker(privateKey) // ❌ Stolen!
  }
}, 1000)

// Mitigation: Very short sessions
const w3pk = new Web3Passkey({ sessionDuration: 0.1 }) // 6 minutes

// Scenario: XSS attack + expired session
await w3pk.deriveWallet('YOLO', 'MAIN', { requireAuth: false })
// ✅ Session expired - user sees authentication prompt
// ⚠️  User might authenticate thinking it's legitimate

// Mitigation: User education + short sessions
```

**Recommendations for High Security:**

```typescript
// 1. Minimal session duration
const w3pk = new Web3Passkey({ sessionDuration: 0.1 }) // 6 min

// 2. Or disable sessions entirely
const w3pk = new Web3Passkey({ sessionDuration: 0 })

// 3. Combine with defense in depth:
// - Content Security Policy (prevent XSS)
// - Subresource Integrity (prevent CDN attacks)
// - Dependency auditing (prevent supply chain)
// - User education (recognize suspicious prompts)
```

### Session Threat Model

#### ✅ Session protected against:
1. **Disk access** - Session never written to storage
2. **Browser restart** - Session cleared automatically
3. **Tab close** - Memory freed immediately
4. **Automatic expiration** - Sessions timeout after configured duration

#### ⚠️ Session vulnerable to:
1. **Active browser exploitation** - If attacker has code execution in the same tab
2. **Memory dumps** - If attacker can dump browser process memory (requires elevated privileges)
3. **Physical access** - If device unlocked and session active

**Recommendation:** For maximum security, set `sessionDuration: 0` to require authentication for every operation. For better UX, use the default 1 hour session.

## Integration Best Practices

Since `requireAuth` and sessions can be bypassed by code execution, here are **essential security measures** to prevent attacks:

### 1. Build Verification

Verify the integrity of the w3pk package before using it in production by querying the DAO-maintained onchain registry:

```typescript
import { getCurrentBuildHash } from 'w3pk'
import { ethers } from 'ethers'
import fs from 'fs'
import path from 'path'

// W3PK Version Registry on OP Mainnet
const REGISTRY_ADDRESS = '0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a'
const REGISTRY_ABI = [
  'function getCidByVersion(string version) view returns (string)',
]

// Get installed w3pk version from package.json
const getInstalledW3pkVersion = (): string => {
  const packageJsonPath = path.join(__dirname, '../package.json')
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'))
  const w3pkVersion = packageJson.dependencies['w3pk']
  return w3pkVersion.replace(/^[~^]/, '') // Remove ^ or ~ prefix
}

async function verifyW3pkIntegrity() {
  try {
    const currentHash = await getCurrentBuildHash()
    const installedVersion = getInstalledW3pkVersion()

    // Query onchain registry for the specific installed version
    const provider = new ethers.JsonRpcProvider('https://mainnet.optimism.io')
    const registry = new ethers.Contract(REGISTRY_ADDRESS, REGISTRY_ABI, provider)
    const onchainCid = await registry.getCidByVersion(`v${installedVersion}`)

    const isValid = currentHash === onchainCid

    if (!isValid) {
      console.error('⚠️  W3PK build verification failed!')
      console.error('Installed version:', installedVersion)
      console.error('Expected CID:', onchainCid)
      console.error('Got:', currentHash)

      if (process.env.NODE_ENV === 'production') {
        throw new Error('W3PK package integrity check failed')
      }
    } else {
      console.log('✅ W3PK build verified against onchain registry')
      console.log('Version:', installedVersion)
    }
  } catch (error) {
    console.error('Build verification error:', error)
  }
}

await verifyW3pkIntegrity()
```

**Best practices:**
- ✅ Query the DAO-maintained onchain registry as the source of truth
- ✅ Verify the specific installed version from `package.json` (not just latest)
- ✅ Verify on application startup
- ✅ Fail securely in production if verification fails
- ✅ Use reliable RPC endpoints for onchain queries
- ✅ Use HTTPS when fetching build files
- ✅ Cache verification results to reduce RPC calls

**Onchain Registry:**
- **Contract:** [`0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a`](https://optimistic.etherscan.io/address/0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a)
- **Network:** OP Mainnet (Chain ID: 10)
- **Governance:** DAO-controlled via contract ownership
- **Version Format:** Use `v` prefix (e.g., `v0.12.0`, `v0.12.1`)

See [Build Verification Guide](./BUILD_VERIFICATION.md) for detailed documentation.

---

### 2. Prevent XSS Attacks

#### Content Security Policy (CSP)

Add strict CSP headers to prevent script injection:

```html
<!-- In your HTML -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               script-src 'self' 'nonce-{RANDOM}';
               style-src 'self' 'nonce-{RANDOM}';
               object-src 'none';
               base-uri 'self';
               form-action 'self';">
```

Or via HTTP headers:
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; object-src 'none'
```

**Best practices:**
- ❌ Avoid `unsafe-inline` and `unsafe-eval`
- ✅ For zk features, allow WebAssembly with `'wasm-unsafe-eval'` rather than `'unsafe-eval'` (see [ZK.md](./ZK.md#installation))
- ✅ Use nonces for inline scripts
- ✅ Whitelist only trusted domains
- ✅ Use `strict-dynamic` for modern browsers

#### Input Sanitization

```typescript
// Sanitize all user inputs
import DOMPurify from 'dompurify'

function displayUsername(username: string) {
  // ❌ NEVER do this:
  element.innerHTML = username

  // ✅ DO this:
  element.textContent = username

  // ✅ OR if HTML needed:
  element.innerHTML = DOMPurify.sanitize(username)
}
```

#### Output Encoding

```typescript
// Encode data before display
function showTransaction(recipient: string) {
  // ✅ Use proper encoding
  const encoded = encodeURIComponent(recipient)

  // ✅ Or use framework escaping (React, Vue, etc.)
  return <div>{recipient}</div> // React auto-escapes
}
```

#### Framework-Specific Protection

**React:**
```typescript
// ✅ React auto-escapes by default
<div>{userInput}</div>

// ❌ Dangerous - only use for trusted content
<div dangerouslySetInnerHTML={{__html: userInput}} />
```

**Vue:**
```vue
<!-- ✅ Vue auto-escapes -->
<div>{{ userInput }}</div>

<!-- ❌ Dangerous -->
<div v-html="userInput"></div>
```

### 3. Defend Against Malicious Browser Extensions

#### Extension Isolation Strategies

```typescript
// 1. Detect suspicious extension behavior
function detectExtensionInjection() {
  const originalFetch = window.fetch
  let fetchModified = false

  setTimeout(() => {
    if (window.fetch !== originalFetch) {
      console.warn('Fetch API modified - possible extension interference')
      fetchModified = true
    }
  }, 100)

  return fetchModified
}

// 2. Protect sensitive operations with iframe isolation
function createIsolatedContext() {
  const iframe = document.createElement('iframe')
  iframe.sandbox = 'allow-same-origin allow-scripts'
  iframe.style.display = 'none'
  document.body.appendChild(iframe)

  // Use iframe's clean window context
  return iframe.contentWindow
}

// 3. Short sessions limit exposure
const w3pk = new Web3Passkey({
  sessionDuration: 0.1 // 6 minutes - limits extension attack window
})
```

#### User Education

Display warnings when detecting extensions:

```typescript
// Check for common wallet extension conflicts
const hasMetaMask = typeof window.ethereum !== 'undefined'
const hasExtensions = detectExtensionInjection()

if (hasExtensions) {
  showWarning(
    'Browser extensions detected. ' +
    'For maximum security, use a dedicated browser profile ' +
    'without extensions when accessing your wallet.'
  )
}
```

#### Browser Profile Recommendation

```typescript
// In your UI/documentation
const securityMessage = `
🔒 Security Recommendation:
- Create a dedicated browser profile for wallet operations
- Disable all browser extensions in this profile
- Use this profile only for financial transactions
`
```

### 4. Prevent Compromised Dependencies (Supply Chain)

#### Package Auditing

```bash
# Regular security audits
npm audit
npm audit fix

# Use audit in CI/CD
npm audit --audit-level=high

# Alternative: use pnpm or yarn for better security
pnpm audit
```

#### Lock File Integrity

```bash
# Always commit lock files
git add package-lock.json
git commit -m "Lock dependencies"

# Verify lock file in CI
npm ci  # Fails if package.json and lock mismatch
```

#### Subresource Integrity (SRI)

For CDN-loaded scripts:

```html
<!-- ✅ Use SRI hashes -->
<script
  src="https://cdn.example.com/w3pk.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
  crossorigin="anonymous">
</script>
```

Generate SRI hashes:
```bash
# Generate hash
curl https://cdn.example.com/w3pk.js | openssl dgst -sha384 -binary | openssl base64 -A
```

#### Dependency Monitoring

```json
{
  "scripts": {
    "postinstall": "npm audit",
    "security-check": "npx snyk test"
  }
}
```

Use security services:
- [Snyk](https://snyk.io/)
- [Socket](https://socket.dev/)
- [Dependabot](https://github.com/dependabot) (GitHub)

#### Minimal Dependencies

```typescript
// ❌ Avoid kitchen-sink libraries
import _ from 'lodash' // 70KB

// ✅ Import only what you need
import debounce from 'lodash.debounce' // 2KB
```

Review dependencies regularly:
```bash
# List dependency tree
npm list
pnpm list --depth=1

# Check package size
npx bundlephobia lodash
```

### 5. Prevent Code Injection

#### Secure Build Pipeline

```typescript
// In your build config (vite.config.ts, webpack.config.js)
export default {
  build: {
    // Minify and obfuscate
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true, // Remove console logs in production
      }
    },

    // Enable source maps only in development
    sourcemap: process.env.NODE_ENV === 'development',

    // Rollup security options
    rollupOptions: {
      external: ['crypto', 'buffer'], // Don't bundle Node.js modules
    }
  }
}
```

#### Runtime Integrity Checks

```typescript
// Detect if code has been tampered with
class IntegrityChecker {
  private checksum: string

  constructor() {
    // Store checksum of critical code at build time
    this.checksum = this.calculateChecksum()
  }

  private calculateChecksum(): string {
    // Calculate hash of critical functions
    const criticalCode = [
      w3pk.signMessage.toString(),
      w3pk.sendTransaction.toString(),
    ].join('')

    return this.hash(criticalCode)
  }

  verify(): boolean {
    const currentChecksum = this.calculateChecksum()
    return currentChecksum === this.checksum
  }

  private hash(str: string): string {
    // Simple hash (use crypto.subtle.digest in production)
    let hash = 0
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i)
      hash = hash & hash
    }
    return hash.toString(36)
  }
}

// Use in critical operations
const checker = new IntegrityChecker()
if (!checker.verify()) {
  throw new Error('Code integrity check failed - possible tampering')
}
```

#### Freeze Critical Objects

```typescript
// Prevent prototype pollution and tampering
Object.freeze(Object.prototype)
Object.freeze(Array.prototype)
Object.freeze(String.prototype)

// Freeze critical SDK methods
Object.freeze(w3pk.signMessage)
Object.freeze(w3pk.sendTransaction)
Object.freeze(w3pk.deriveWallet)
```

#### Secure Coding Patterns

```typescript
// ❌ Don't use eval or Function constructor
eval(userInput) // NEVER
new Function(userInput)() // NEVER

// ❌ Don't use innerHTML with user content
element.innerHTML = userInput // DANGEROUS

// ✅ Use safe alternatives
element.textContent = userInput
element.setAttribute('data-value', userInput)

// ❌ Don't trust client-side validation only
if (amount > 0) { // Can be bypassed
  transfer(amount)
}

// ✅ Always validate on both sides
async function transfer(amount: number) {
  // Server-side validation
  const response = await fetch('/api/validate', {
    method: 'POST',
    body: JSON.stringify({ amount })
  })

  if (response.ok) {
    // Proceed with transfer
  }
}
```

### 5. Defense in Depth Strategy

Combine multiple layers:

```typescript
const w3pk = new Web3Passkey({
  // 1. Short sessions (limit attack window)
  sessionDuration: 0.1, // 6 minutes

  // 2. Callbacks for security events
  onError: (error) => {
    // Log security events
    reportSecurityEvent({
      type: 'error',
      message: error.message,
      timestamp: Date.now()
    })
  }
})

// 3. Rate limiting sensitive operations
const rateLimiter = new RateLimiter({ maxAttempts: 3, windowMs: 60000 })

async function secureSignMessage(message: string) {
  // Check integrity
  if (!integrityChecker.verify()) {
    throw new Error('Code tampering detected')
  }

  // Rate limit
  if (!rateLimiter.attempt()) {
    throw new Error('Too many attempts')
  }

  // Detect extensions
  if (detectExtensionInjection()) {
    console.warn('Extension interference detected')
  }

  // Always require auth for high-value
  const requireAuth = parseAmount(message) > 100

  return w3pk.signMessage(message, { requireAuth })
}
```

### 6. Monitoring and Alerting

```typescript
// Monitor suspicious behavior
class SecurityMonitor {
  private attemptCounts = new Map<string, number>()

  trackOperation(operation: string) {
    const count = (this.attemptCounts.get(operation) || 0) + 1
    this.attemptCounts.set(operation, count)

    // Alert on suspicious patterns
    if (count > 10) {
      this.alert(`Suspicious: ${operation} called ${count} times`)
    }
  }

  private alert(message: string) {
    // Log to monitoring service
    console.error('[SECURITY]', message)

    // Optional: Send to backend
    fetch('/api/security-alert', {
      method: 'POST',
      body: JSON.stringify({ message, timestamp: Date.now() })
    })
  }
}

const monitor = new SecurityMonitor()
monitor.trackOperation('createBackupFile')
```

### Summary: Security Checklist

Before deploying w3pk in production:

- [ ] ✅ Content Security Policy configured (strict, no unsafe-inline)
- [ ] ✅ Input sanitization on all user inputs
- [ ] ✅ Output encoding for display
- [ ] ✅ XSS protection via framework defaults
- [ ] ✅ Extension detection implemented
- [ ] ✅ User warnings for security risks
- [ ] ✅ Short session duration configured (< 15 minutes)
- [ ] ✅ Dedicated browser profile recommended to users
- [ ] ✅ npm audit passing with no high/critical issues
- [ ] ✅ Lock files committed and verified
- [ ] ✅ Subresource Integrity for CDN scripts
- [ ] ✅ Dependency monitoring enabled (Snyk/Dependabot)
- [ ] ✅ Minimal dependency tree
- [ ] ✅ Secure build pipeline (minification, no source maps)
- [ ] ✅ Object.freeze on critical prototypes
- [ ] ✅ No eval/Function constructor in codebase
- [ ] ✅ Server-side validation for critical operations
- [ ] ✅ Rate limiting implemented
- [ ] ✅ Security monitoring and alerting
- [ ] ✅ User education materials prepared

## Credential Scoping and Domain Isolation

### Credentials are Domain-Specific

**Important:** Credentials created on one web application **cannot be used on another web application**, even for the same username. This is a fundamental WebAuthn security feature.

### How It Works

When you register a credential, it is cryptographically bound to the domain:

```typescript
// Registration on example.com
const registrationOptions = {
  challenge,
  rp: {
    name: "w3pk",
    id: window.location.hostname,  // "example.com"
  },
  user: {
    id: username,
    name: username,
    displayName: username,
  },
  // ...
}

// Authentication on example.com
const authOptions = {
  challenge,
  rpId: window.location.hostname,  // Must be "example.com"
  userVerification: "required",
  // ...
}
```

**Key Points:**

1. **RP ID is auto-detected**: The Relying Party ID (RP ID) is automatically set to `window.location.hostname`
2. **Cannot be configured**: Manual RP ID configuration was removed in v0.7.0 to enforce security
3. **Cryptographically bound**: The WebAuthn credential private key is tied to the RP ID
4. **Browser-enforced**: The browser's WebAuthn API enforces this isolation

### Why Credentials Don't Work Across Domains

**Example scenario:**

```typescript
// Step 1: Register on app1.com
// User visits: https://app1.com
await w3pk.register({ username: 'alice' })
// → RP ID: "app1.com"
// → Credential created and bound to "app1.com"
// → Stored in browser with origin: "https://app1.com"

// Step 2: Try to login on app2.com
// User visits: https://app2.com
await w3pk.login()
// → RP ID: "app2.com" (different!)
// → Browser WebAuthn API: "No credential found for RP ID 'app2.com'"
// → Login fails ❌

// Step 3: Must register separately on app2.com
await w3pk.register({ username: 'alice' })
// → Creates NEW credential for "app2.com"
// → This is a completely separate credential
```

### Security Guarantees

This domain isolation provides critical security guarantees:

#### ✅ Protection Against Phishing

```typescript
// Legitimate site: example.com
await w3pk.register({ username: 'alice' })
// RP ID: "example.com"

// Phishing site: examp1e.com (note the "1")
await w3pk.login()
// RP ID: "examp1e.com" (different!)
// ❌ Credential not found - phishing attempt blocked
```

The attacker **cannot** use your `example.com` credential even if they:
- Copy your localStorage data
- Trick you into visiting their site
- Use an identical UI

The browser enforces that credentials for `example.com` can only be used on `example.com`.

#### ✅ Origin-Based Storage Isolation

```typescript
// Browser storage is automatically scoped by origin
localStorage  // Scoped to "https://example.com"

// A different origin cannot access this storage
// - https://attacker.com → different origin
// - https://subdomain.example.com → different origin (unless RP ID configured for parent)
// - http://example.com → different origin (different protocol)
```

> **Caveat:** origin isolation only walls the data off from *other* origins. It does **not** protect against code running *inside* your own origin — XSS, a malicious dependency, or a compromised script/CDN on `example.com` runs *as* `example.com` and can read this storage and use the session. "Scoped to this origin" is not "only my code." See [At-Rest Encryption → Origin scoping](#at-rest-encryption-what-it-protects-and-what-it-doesnt).

#### ✅ No Cross-Site Credential Replay

```typescript
// Even if attacker intercepts network traffic
const stolenSignature = interceptFromNetwork()

// They cannot replay it on their site
await navigator.credentials.get({
  publicKey: {
    challenge: stolenChallenge,
    rpId: "attacker.com",  // Different RP ID!
    // ...
  }
})
// ❌ Browser rejects: "RP ID mismatch"
```

### Subdomain Considerations

**By default, credentials are scoped to the exact hostname:**

```typescript
// Registered on: app.example.com
// RP ID: "app.example.com"

// Cannot use on: api.example.com (different subdomain)
// Cannot use on: example.com (parent domain)
```

**Note:** The WebAuthn standard allows setting RP ID to a parent domain, but w3pk uses auto-detection which sets it to the exact hostname for maximum security.

### Localhost and Development

During development, credentials are scoped to `localhost`:

```typescript
// Development environment
window.location.hostname  // "localhost"
// RP ID: "localhost"

// Credentials created during development:
// ✅ Work on: http://localhost:3000
// ✅ Work on: http://localhost:8080
// ✅ Work on: https://localhost:5173
// ❌ Don't work on: 127.0.0.1 (different hostname!)
```

**Development tip:** Always use `localhost`, not `127.0.0.1`, for consistent RP ID.

### Migration from v0.6.0 to v0.7.0

In v0.6.0, the RP ID could be manually configured:

```typescript
// v0.6.0 (old)
const w3pk = createWeb3Passkey({
  rpId: 'example.com',  // Manual configuration
})
```

In v0.7.0+, this was removed for security:

```typescript
// v0.7.0+ (current)
const w3pk = createWeb3Passkey({
  // rpId is auto-detected from window.location.hostname
  // Cannot be overridden
})
```

**Why this change?**
- Prevents misconfiguration
- Enforces best practices
- Eliminates cross-origin credential risks
- Simplifies API

### Credential Storage and Scoping

**What's stored and where:**

```typescript
// localStorage (origin-scoped by browser)
// Key: w3pk_credential_<base64url SHA-256 of "w3pk-cred-id:" + credentialId>
{
  "id": "credential-abc123",
  "publicKey": "MFkw...",      // Public key only
  "username": "alice",
  "ethereumAddress": "0x1234...",
  "createdAt": 1234567890
}

// localStorage (origin-scoped by browser)
// Key: w3pk_wallet_<credentialId>
{
  "ethereumAddress": "0x1234...",
  "encryptedMnemonic": "v1kT...",  // AES-GCM encrypted
  "credentialId": "credential-abc123",
  "createdAt": 1234567890
}

// Authenticator (hardware/platform)
// WebAuthn private key (bound to RP ID)
// - Cannot be exported
// - Cannot be used for different RP ID
// - Hardware-protected
```

**Security properties:**

1. **localStorage**: Origin-scoped by browser (cannot access from different origin); the wallet is also encrypted under a key derived from the credential metadata
2. **Authenticator**: RP ID-bound + hardware-protected

### Common Questions

**Q: Can I use the same wallet on multiple domains?**

A: No, each domain requires separate registration. However, you can import the same mnemonic on different domains to access the same wallet addresses:

```typescript
// On domain1.com
const { mnemonic } = await w3pk.register({ username: 'alice' })
// Save mnemonic: "word1 word2 ... word12"

// On domain2.com (later)
await w3pk.register({
  username: 'alice',
  mnemonic: 'word1 word2 ... word12'  // Import same mnemonic
})
// ✅ Same wallet addresses, different WebAuthn credential
```

**Q: What if I want to share credentials across subdomains?**

A: Currently not supported. Each subdomain requires separate registration. This is the most secure approach.

**Q: Can I migrate credentials between domains?**

A: WebAuthn credentials cannot be migrated, but wallets can:

1. Export mnemonic from old domain
2. Register on new domain with same mnemonic
3. Same wallet addresses, new credential

**Q: What happens if I switch from `app.example.com` to `example.com`?**

A: These are different RP IDs. You'll need to re-register. Export your mnemonic first to preserve your wallet.

### Security Best Practices

1. **Educate users**: Make it clear that credentials are per-domain
2. **Prompt for backup**: Always prompt users to save their mnemonic after registration
3. **Test on production domain**: Don't expect development credentials to work in production
4. **Use consistent domains**: Avoid switching between `www.example.com` and `example.com`
5. **Display current domain**: Show users which domain they're authenticating for

### Implementation Example

```typescript
// Show user which domain they're registering on
const currentDomain = window.location.hostname

console.log(`🔐 Creating credential for: ${currentDomain}`)
console.log(`⚠️  This credential will only work on ${currentDomain}`)

await w3pk.register({ username: 'alice' })

console.log(`✅ Credential created for ${currentDomain}`)
console.log(`💾 Save your recovery phrase - you'll need it to access`)
console.log(`   this wallet on other domains or devices`)
```

## WebAuthn Security Features

### User Verification
w3pk enforces `userVerification: "required"`, which means:

- **Platform authenticators** (TouchID, FaceID, Windows Hello):
  - Biometric verification required
  - Local-only (biometric never leaves device)
  - Hardware-protected

- **Security keys** (YubiKey, etc.):
  - PIN required
  - FIDO2 certified hardware
  - Tamper-resistant

### Credential Protection
- **Resident credentials** (discoverable):
  - Stored in authenticator hardware
  - Protected by Secure Enclave/TPM
  - Cannot be extracted

- **Private key** never exposed:
  - Signature operations happen in hardware
  - Key never enters browser/OS memory
  - Cannot be dumped or stolen

## Authenticator's Built-In Credential Storage

### What Is It?

Modern authenticators (TouchID, Windows Hello, YubiKey) have **built-in secure storage** for credentials. This is separate from browser storage and provides additional security.

### How It Works

```
┌─────────────────────────────────────────┐
│ Your Computer                            │
│                                          │
│  Browser Storage (localStorage)         │
│  ┌─────────────────────────────────┐    │
│  │ • Username                       │    │
│  │ • Public key (safe)              │    │
│  │ • Ethereum address              │    │
│  │ • Encrypted wallet              │    │
│  │ • Credential ID                 │    │
│  └─────────────────────────────────┘    │
│                                          │
│  ┌───────────────────────────────────┐  │
│  │ Secure Enclave / TPM              │  │
│  │ (Hardware Protected)              │  │
│  │                                   │  │
│  │ ✓ WebAuthn Private Key           │  │
│  │ ✓ Credential Metadata            │  │
│  │ ✓ Touch/Face biometric data      │  │
│  │                                   │  │
│  │ ❌ Cannot be exported             │  │
│  │ ❌ Cannot be copied               │  │
│  │ ❌ Survives OS reinstall (iOS)    │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### Security Benefits

1. **Hardware Protection**
   - Private keys stored in Secure Enclave (iOS) or TPM (Windows)
   - Cannot be extracted even with root/admin access
   - Survives malware/OS compromise

2. **Biometric Storage**
   - Fingerprints/face data NEVER leave device
   - Stored in encrypted hardware
   - Matched locally in secure element

3. **Credential Backup** (Platform-dependent)
   - **iCloud Keychain** (iOS/macOS):
     - Credentials sync across user's Apple devices
     - End-to-end encrypted
     - Requires device unlock

   - **Windows Hello**:
     - Tied to specific device/TPM
     - Does NOT sync by default
     - Requires device PIN

   - **Android**:
     - Can backup to Google account
     - End-to-end encrypted
     - Requires screen unlock

### Considerations for w3pk

**The authenticator stores:**
- ✅ WebAuthn private key (secure)
- ✅ Credential metadata (credential ID, RP ID)
- ❌ **NOT** the wallet mnemonic

**The wallet mnemonic is stored:**
- In browser localStorage (encrypted)
- Can only be decrypted with WebAuthn signature
- Requires fresh biometric authentication

**This means:**
- Losing your authenticator = Lose access to decrypt wallet
- **CRITICAL:** Users must save their mnemonic phrase
- Mnemonic is the ultimate recovery mechanism
- WebAuthn is for convenience + security, not recovery

## Backup & Recovery Security

w3pk implements a **three-layer backup and recovery system** that balances security, usability, and resilience. Each layer uses different cryptographic primitives and trust models.

### Layer 1: Passkey Auto-Sync (Platform-Based)

**How it works:**
- WebAuthn credentials automatically sync via platform services (iCloud Keychain, Google Password Manager, Microsoft Account)
- Encrypted end-to-end by platform provider
- Requires device unlock + cloud account authentication

**Security properties:**
- ✅ **Encrypted in transit** - Platform handles E2E encryption
- ✅ **Hardware-backed *passkey*** - The WebAuthn credential's private key is protected by the Secure Enclave/TPM. The wallet's at-rest key derives from the passkey's PRF output, so the seed at rest is bound to the passkey too (see [At-Rest Encryption](#at-rest-encryption-what-it-protects-and-what-it-doesnt)).
- ✅ **Automatic** - No user action required
- ⚠️ **Platform trust** - Relies on Apple/Google/Microsoft security
- ⚠️ **Ecosystem lock-in** - Cannot cross platforms (Apple → Android)

**Threat model:**
| Threat | Protected? | Notes |
|--------|-----------|-------|
| Device loss (same ecosystem) | ✅ Yes | Credentials restore on new device |
| Device loss (cross-platform) | ❌ No | Need Layer 2 (mnemonic) |
| Platform account compromise | ⚠️ Depends | Platform MFA protects |
| State-level attack on cloud | ⚠️ Possible | Platform E2E encryption helps |

### Layer 2: Encrypted Backups (User-Controlled)

**How it works:**
- Mnemonic encrypted with user-chosen password
- Backup format: encrypted backup files
- Encryption: **AES-256-GCM** with **Argon2id** (64 MiB, 3 passes) for backup files

**Security properties:**
- ✅ **Military-grade encryption** - AES-256-GCM
- ✅ **Password-based** - User controls secret
- ✅ **Offline storage** - Can be stored on paper/USB/safe
- ✅ **Platform-independent** - Works across any device
- ⚠️ **Password strength critical** - Weak password = vulnerable

**Cryptographic details:**
```typescript
// Key derivation (BackupFile v4)
Argon2id
├─ Memory: 64 MiB, passes: 3, lanes: 4
├─ Salt: 16 bytes (random per backup)
└─ Output: 256-bit key

// Encryption
AES-256-GCM
├─ Key: From Argon2id
├─ IV: 12 bytes (random per encryption)
├─ Auth tag: 16 bytes (automatic)
└─ Additional data: none (the file holds no address)
```

**Password validation:**
w3pk follows [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) §3.1.1.2 and the [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html):
- 15 to 256 characters, counted in Unicode code points after NFC normalization
- Any characters: spaces, accents and emoji are fine, and no mix of character types is required
- Not one of the 1,000 most common passwords of that length (whole-password match, any case, ignoring spaces, dots, dashes and underscores), and not a single repeated character

**Using `isStrongPassword` utility:**
```typescript
import { isStrongPassword } from 'w3pk'

// Validate before creating backups
const password = userInput
if (!isStrongPassword(password)) {
  throw new Error('Password must be at least 15 characters and not a common password')
}

// Now safe to create backup
const { blob, filename } = await w3pk.createBackupFile(password)
```

**Examples:**
```typescript
// Test fixtures - not real passwords!
isStrongPassword('violet lantern under seven bridges')  // ✅ true
isStrongPassword('mot de passe très long')        // ✅ true
isStrongPassword('Test1234!@#$')                  // ❌ false - too short
isStrongPassword('passwordpassword')              // ❌ false - common password
```

**Threat model:**
| Threat | Protected? | Notes |
|--------|-----------|-------|
| Backup file stolen | ✅ Yes | Requires password to decrypt |
| Weak password | ⚠️ Partly | New backups refuse a password that fails `isStrongPassword()`, but one that passes can still be guessable |
| Password forgotten | ❌ Unrecoverable | Need Layer 3 (social recovery) |
| Brute force (strong password) | ✅ Yes | Argon2id makes each guess slow and memory-hungry |
| Brute force (weak password) | ❌ Vulnerable | Minutes to hours with GPU |

**Brute force analysis:**

| Password Type | Entropy | Verdict |
|--------------|---------|---------------|
| `password123` (common) | ~20 bits | In every wordlist: falls quickly |
| `MyPassword123!` (weak) | ~35 bits | Within reach of a GPU rig |
| `Correct-Horse-Battery-Staple-7` (strong) | ~44 bits from a 7,776-word list, more with 5+ words | Costly with Argon2id |
| Truly random 16 chars | ~100 bits | Out of reach |

**Recommendation:** Use password manager to generate strong passwords or use multi-word passphrases (4+ random words).

### Layer 3: Social Recovery (Distributed Trust)

**How it works:**
- Mnemonic split into **N shares** using **Shamir Secret Sharing**
- Requires **M-of-N** shares to recover (e.g., 3-of-5)
- Each guardian receives encrypted share via QR code
- Guardians never see the actual mnemonic

**Cryptographic details:**
```typescript
// Shamir Secret Sharing over GF(256)
├─ Threshold: M (minimum shares needed)
├─ Total shares: N (total guardians)
├─ Secret: Mnemonic (67 bytes UTF-8)
├─ Polynomial degree: M-1
├─ Field: Galois Field GF(256)
│   ├─ Primitive polynomial: x^8 + x^4 + x^3 + x + 1 (0x11b)
│   ├─ Generator: 3
│   └─ Lagrange interpolation for reconstruction
└─ Share format:
    ├─ Byte 0: X coordinate (1-255)
    └─ Bytes 1-67: Y values (polynomial evaluation)

// Guardian share encryption
AES-256-GCM (same as Layer 2)
├─ Optional: Guardian can password-protect their share
└─ QR code includes guardian metadata + instructions
```

**Security properties:**
- ✅ **Information-theoretic security** - Cannot learn secret from M-1 shares
- ✅ **Distributed trust** - No single point of failure
- ✅ **Privacy-preserving** - Guardians never see mnemonic
- ✅ **Flexible threshold** - Customize M-of-N based on risk tolerance
- ⚠️ **Coordination required** - Must contact M guardians
- ⚠️ **Guardian trust** - Guardians could collude (if ≥M)

**Threat model:**
| Threat | Protected? | Notes |
|--------|-----------|-------|
| M-1 guardians compromised | ✅ Yes | Cannot recover without Mth share |
| M guardians collude | ❌ Vulnerable | Can reconstruct mnemonic |
| All guardians lost | ❌ Unrecoverable | Need Layer 2 backup |
| Guardian share stolen | ✅ Depends | If password-protected, still safe |
| User forgets who guardians are | ⚠️ Problem | Keep guardian list separately |

**Information-theoretic security proof:**

Shamir Secret Sharing over GF(256) provides perfect secrecy:
- Given M-1 shares, **every possible secret is equally likely**
- Attacker learns **zero bits** of information about secret
- No amount of computation can break this (unlike encryption)

Mathematical proof:
```
For threshold M and secret S:
- Polynomial P(x) = a₀ + a₁x + ... + aₘ₋₁x^(M-1)
- Secret: S = P(0) = a₀
- Share i: Sᵢ = P(i)

Given M-1 shares {S₁, S₂, ..., Sₘ₋₁}:
- Infinite polynomials pass through these points
- Each yields different P(0) = a₀
- All secrets equally probable
- H(S | S₁,...,Sₘ₋₁) = H(S)  [Shannon entropy unchanged]
```

**Example configuration:**

| Scenario | Threshold | Guardians | Rationale |
|----------|-----------|-----------|-----------|
| High paranoia | 5-of-7 | 7 close friends | Can lose 2 guardians |
| Balanced | 3-of-5 | 5 trusted contacts | Standard recommendation |
| Convenience | 2-of-3 | 3 family members | Easy to coordinate |
| Multi-sig like | 2-of-2 | 2 co-owners | Both must agree |

### Layered Security Strategy

**Defense in depth:**
```
┌─────────────────────────────────────────────┐
│ Recovery Scenario                            │
├─────────────────────────────────────────────┤
│                                              │
│ Lost Device (Same Platform)                 │
│ └─> Layer 1: Passkey Sync ✅ RECOVERED      │
│                                              │
│ Lost Device (Cross-Platform)                │
│ └─> Layer 1: Failed ❌                       │
│ └─> Layer 2: Encrypted Backup ✅ RECOVERED   │
│                                              │
│ Lost Device + Forgot Password               │
│ └─> Layer 1: Failed ❌                       │
│ └─> Layer 2: Failed ❌                       │
│ └─> Layer 3: Social Recovery ✅ RECOVERED    │
│                                              │
│ Lost Everything + All Guardians Lost        │
│ └─> ❌ UNRECOVERABLE                         │
│                                              │
└─────────────────────────────────────────────┘
```

**Security scoring:**

w3pk calculates a security score (0-70) based on active backup methods:

| Configuration | Score | Level |
|--------------|-------|-------|
| No backup that restores without a passkey (none, or `prf` only) | ≤ 20 | 🔴 Vulnerable |
| Passkey + password backup | 40 | 🟡 Protected |
| Passkey + password backup, verified or synced to 2+ devices | 41-60 | 🟢 Secured |
| All layers, verified | 61-70 | 🟦 Fort Knox |

**Score calculation:**
```typescript
score = 0
+ (passkeySync.enabled ? 20 : 0)
+ (passkeySync.deviceCount > 1 ? 10 : 0)
+ (backupVerified ? 10 + min(verifications - 1, 10) : 0)
+ (encryptedBackups > 0 ? 20 : 0)          // file, QR or prf

// Capped at 20 while no backup restores without a passkey: a lost device
// with no synced passkey can only be recovered from a password file, a QR
// code, the phrase or social recovery. A password-only backup isn't penalized.
```

`getBackupStatus().recommendedMode` is `password` until such a backup exists, then `prf` for convenient sync.

### Backup Best Practices

**1. Use multiple layers:**
```typescript
// ✅ GOOD: Enable all three layers
await w3pk.setupSocialRecovery([...guardians], 3, backupPassword)
await w3pk.createBackupFile(backupPassword)
// Passkey sync enabled by default on platform

// ❌ BAD: Rely on single layer
// (only passkey sync - what if switch platforms?)
```

**2. Test recovery before trusting:**
```typescript
// Simulate recovery scenarios
import { RecoverySimulator } from 'w3pk'

const simulator = new RecoverySimulator()
const status = await w3pk.getBackupStatus()

const test1 = await simulator.simulateScenario(
  { type: 'lost-device', description: 'Phone lost' },
  status
)
console.log('Can recover?', test1.success)

const test2 = await simulator.simulateScenario(
  { type: 'lost-phrase', description: 'Recovery phrase lost' },
  status
)
console.log('Can recover?', test2.success)
```

**3. Store backups securely:**
```typescript
// ✅ GOOD: Offline, encrypted, geographically distributed
- Physical safe (home)
- Safety deposit box (bank)
- Encrypted USB drive (office)
- Password manager (different password)

// ❌ BAD: Digital-only, centralized
- Cloud storage unencrypted
- Email to self
- Single location
- Shared with others
```

**4. Choose guardians wisely:**
```typescript
// ✅ GOOD guardian criteria:
- Trustworthy (won't collude)
- Available (can reach when needed)
- Technical (understands basic security)
- Diverse (different locations/relationships)
- Long-term (stable relationship)

// ❌ BAD guardian choices:
- All family members (could collude)
- All same location (disaster risk)
- Strangers/acquaintances
- People who might lose share
```

**5. Use strong passwords:**
```typescript
// ✅ GOOD passwords:
'Correct-Horse-Battery-Staple-7'  // Multi-word passphrase
'MyS3cur3!Backup@December2024'  // Long with variety
(password manager generated)     // Truly random

// ❌ BAD passwords:
'password123'      // Common
'MyPassword'       // Dictionary word
'12345678'         // Sequential
'qwerty123'        // Keyboard pattern
```

### API Security Considerations

**All backup operations require authentication:**
```typescript
// These operations trigger biometric prompt
await w3pk.createBackupFile(password)       // ✅ Auth required
await w3pk.setupSocialRecovery(...)         // ✅ Auth required
await w3pk.exportForSync(password)          // ✅ Auth required

// Read-only operations don't require auth
await w3pk.getBackupStatus()                // ✅ No auth needed
```

**Password validation is client-side:**
⚠️ **Important:** Password strength is checked in the browser. A determined attacker with code execution could bypass validation and create backups with weak passwords.

**Mitigation:**
- Short session durations
- XSS/injection protection (CSP, input sanitization)
- Educate users on password strength

**Recovery operations don't require a login:**
```typescript
// Recovery from existing backups works logged out
await w3pk.restoreFromBackupFile(backupFile, password)
await w3pk.recoverFromGuardians([shares...], password)

// Rationale: If user has backup data + password/shares,
// they own the wallet regardless of authentication
```

### Comparison with Other Recovery Systems

| Recovery Method | w3pk Layer 1 | w3pk Layer 2 | w3pk Layer 3 | Traditional Seed | Hardware Wallet |
|----------------|--------------|--------------|--------------|------------------|-----------------|
| **Automatic** | ✅ Yes | ❌ Manual | ❌ Manual | ❌ Manual | ❌ Manual |
| **Cross-platform** | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **Offline storage** | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes | N/A |
| **No single point** | ❌ No | ❌ No | ✅ Yes | ❌ No | ❌ No |
| **Cryptographic** | ✅ E2E | ✅ AES-256 | ✅ Shamir | N/A | N/A |
| **User effort** | None | Medium | High | Low | None |
| **Trust model** | Platform | Self | Distributed | Self | Self |

## Best Practices for Users

### 1. **Always Save Your Mnemonic**
```typescript
const { mnemonic } = await w3pk.register({ username: 'alice' })

// ⚠️ CRITICAL: Save this offline
console.log('Write this down:', mnemonic)
```

**Why?**
- If you lose/reset your device, mnemonic is only recovery
- WebAuthn credentials are device-specific
- Hardware failure = need mnemonic

### 2. **Understand Your Authenticator**

| Authenticator | Backup? | Sync? | Recovery |
|--------------|---------|-------|----------|
| TouchID/FaceID (iCloud enabled) | ✅ Yes | ✅ Yes | Other Apple devices |
| TouchID/FaceID (iCloud disabled) | ❌ No | ❌ No | Mnemonic only |
| Windows Hello | ❌ No | ❌ No | Mnemonic only |
| Android (Google backup) | ✅ Yes | ✅ Yes | Other Android devices |
| YubiKey | ❌ No | ❌ No | Mnemonic only |

### 3. **Device Loss Scenarios**

**Scenario 1: Lost iPhone (iCloud Keychain enabled)**
- ✅ Get new iPhone
- ✅ Sign into iCloud
- ✅ WebAuthn credentials restore automatically
- ✅ Can decrypt wallet (no mnemonic needed)

**Scenario 2: Lost iPhone (iCloud Keychain disabled)**
- ❌ WebAuthn credentials lost
- ✅ Import mnemonic on new device
- ✅ Re-register with new WebAuthn credential
- ✅ Wallet recovered

**Scenario 3: Wiped Computer**
- ❌ All browser data lost
- ❌ WebAuthn credentials lost (except external security keys)
- ✅ Import mnemonic
- ✅ Re-register
- ✅ Wallet recovered

## Threat Model Summary

| Threat | Protected? | How |
|--------|-----------|-----|
| Malware steals browser files | ✅ Yes | Files are encrypted, key requires biometric |
| Keylogger captures password | ✅ Yes | No password - uses biometric |
| Phishing site | ⚠️ Partial | WebAuthn checks domain, but user must verify |
| Physical device theft | ✅ Yes | Biometric/PIN required |
| Database dump | ✅ Yes | Wallet encrypted with signature-derived key |
| Active session hijacking | ❌ No | If wallet in memory, can be accessed |
| Device loss without backup | ⚠️ Depends | Need mnemonic if authenticator not backed up |
| Coercion (forced authentication) | ❌ No | Cannot prevent forced biometric |

## Security Recommendations

### For Developers

1. **Never store secrets** in localStorage/sessionStorage
2. **Always require re-authentication** for sensitive operations
3. **Use `userVerification: "required"`** to enforce biometric/PIN
4. **Prompt users to save mnemonic** prominently during registration
5. **Clear wallet from memory** after operations complete

### For Users

1. **Write down your mnemonic** on paper (offline)
2. **Enable authenticator backup** if available (iCloud Keychain, etc.)
3. **Test recovery** before storing significant funds
4. **Use strong device security** (PIN/password)
5. **Verify domain** before authenticating
6. **Keep devices updated** for security patches

## Comparison: w3pk vs Traditional Wallets

| Feature | w3pk | MetaMask | Hardware Wallet |
|---------|------|----------|-----------------|
| Password required | ❌ No | ✅ Yes | ❌ No (PIN on device) |
| Biometric auth | ✅ Yes | ❌ No | ❌ No |
| Seed phrase backup | ✅ Required | ✅ Required | ✅ Required |
| File access = theft? | ❌ **No*** | ⚠️ **Partial*** | ❌ No |
| Keylogger risk | ❌ **No** | ✅ **Yes** | ❌ No |
| XSS risk (active session) | ⚠️ **Yes** | ⚠️ **Yes** | ⚠️ Limited (per-tx) |
| Remote attack protection | ✅ Strong | ⚠️ Password-dependent | ✅ Strong |
| Offline brute force | ❌ Not possible† | ⚠️ Possible† | ❌ Not possible |
| Hardware required | ❌ No | ❌ No | ✅ Yes |
| Cost | Free | Free | $50-200 |
| Best for | Convenience + Security | General use | High-value holdings |

**\*File access = theft?**
- **w3pk:** The stored wallet's key needs the passkey's PRF output; localStorage alone doesn't decrypt it. A silent "Remember Me" session is the exception while it lasts.
- **MetaMask:** Can decrypt vault with password. Weak passwords are vulnerable to brute force.
- **Hardware Wallet:** Private keys never leave device. File access doesn't help attacker.

**†Offline brute force:**
- **w3pk:** The key is HKDF of a 256-bit PRF output held by the authenticator. There is no password or stored secret to brute-force.
- **MetaMask:** Attacker needs password. Weak passwords can be brute-forced. Strong passwords with vault encryption are resistant.
- **Hardware Wallet:** Private keys in secure element. Cannot be extracted even with physical access (except advanced hardware attacks).

## Post-Quantum Cryptography

w3pk is preparing for the future quantum computing threat. While quantum computers capable of breaking current cryptography (ECDSA, secp256k1) are estimated to be **10-15 years away**, we have a comprehensive migration roadmap in place.

**Current Status:**
- ✅ **Quantum-resistant encryption** - AES-256-GCM provides 128-bit quantum security
- ✅ **Migration-ready architecture** - Account abstraction ([EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) / [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337)) enables smooth transition
- ⚠️ **Signature vulnerability** - secp256k1 and P-256 are vulnerable to quantum attacks (Shor's algorithm)

**Migration Strategy:**
1. **Phase 2 (interim):** [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) account abstraction with [Kohaku](https://github.com/ethereum/kohaku) post-quantum signatures
2. **Phase 4 (long-term):** [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) native account abstraction with validation frames and protocol-layer STARK aggregation

**Timeline:** 18-36 months for full quantum-safe deployment (aligned with [Ethereum's quantum resistance roadmap](https://x.com/VitalikButerin/status/2027075026378543132))

**📄 For detailed information, see [Post-Quantum Cryptography](./POST_QUANTUM.md)**

---

## Conclusion

w3pk's security model combines **WebAuthn authentication** with **deterministic encryption** to provide strong protection against remote attacks and convenient biometric access. Understanding both the strengths and limitations is critical for secure deployment.

**Key Security Properties:**

1. **Strong Protection Against Remote Attacks**
   - WebAuthn authentication required for SDK operations
   - Domain-scoped credentials prevent phishing
   - No keylogger risk (biometric, not password)
   - Better than password-based wallets for online threats

2. **Encryption At Rest**
   - Wallet encrypted with AES-256-GCM
   - Key derived from the passkey's PRF output (deterministic per passkey)
   - An attacker with file system access can't decrypt it without the passkey
   - Exception: a silent "Remember Me" session stores its own key

3. **Defense in Depth Required**
   - Use device encryption (FileVault, BitLocker, etc.)
   - Use strong device passwords
   - Keep sessions short or disabled for sensitive apps
   - Implement XSS prevention (CSP, input sanitization)
   - Don't rely solely on w3pk encryption for protection

**What You Need to Know:**

An attacker would need different things depending on their goal:

**To decrypt the wallet offline (outside w3pk):**
- Access to browser storage files (localStorage)
- Can then import mnemonic into any wallet

**To use the wallet via w3pk SDK:**
- Physical access to your device, AND
- Your fingerprint/face/PIN to authenticate, OR
- Code execution during active session (XSS)

**Best Practices:**
- ✅ Save your mnemonic securely (ultimate recovery)
- ✅ Use device encryption + strong device password
- ✅ Short sessions for sensitive applications (`sessionDuration: 0.1` or `0`)
- ✅ Implement XSS prevention (this is critical)
- ✅ Understand that w3pk provides convenience + authentication gating, not cryptographic impossibility
- ✅ Use hardware wallets for very high-value holdings (>$10k)

w3pk provides a strong balance between **security and usability** for most web3 applications. It's significantly more secure than password-based wallets against online threats, while providing biometric convenience. However, it should be deployed with proper device security and XSS prevention for maximum protection.
