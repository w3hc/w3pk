# w3pk Architecture

**Complete technical overview of how WebAuthn and Crypto Wallets work together**

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Components](#system-components)
3. [Data Flow Diagrams](#data-flow-diagrams)
4. [Storage Architecture](#storage-architecture)
5. [Cryptographic Details](#cryptographic-details)
6. [Security Model](#security-model)
7. [Recovery Scenarios](#recovery-scenarios)
8. [Common Misconceptions](#common-misconceptions)

---

## Executive Summary

### The Core Concept

w3pk combines **two completely separate cryptographic systems**:

```
┌──────────────────────┐         ┌──────────────────────┐
│   WebAuthn System    │         │  Crypto Wallet       │
│                      │         │                      │
│  P-256 Key Pair      │         │  secp256k1 Key Pair  │
│  Hardware-backed     │         │  Software-based      │
│  OS-managed          │         │  App-managed         │
│  Cloud sync          │         │  Mnemonic backup     │
│                      │         │                      │
│  Signs:              │         │  Signs:              │
│  - Auth challenges ✅│         │  - ETH transactions ✅│
│  - ETH transactions ❌│         │  - Auth challenges ❌│
└──────────────────────┘         └──────────────────────┘
         │                                    │
         └────────────┬───────────────────────┘
                      │
                      ▼
              ┌───────────────┐
              │  The Bridge   │
              │               │
              │  Derives AES  │
              │  encryption   │
              │  key from     │
              │  WebAuthn     │
              │  metadata     │
              └───────────────┘
```

### Key Insight

- **WebAuthn** = The LOCK (authentication system)
- **Crypto Wallet** = The SAFE (asset storage)
- **Encryption Bridge** = The COMBINATION (derived from lock metadata)

They remain **separate systems** with different keys, algorithms, and purposes.

---

## System Components

### 1. WebAuthn (Passkey)

**Purpose**: User authentication

**Technology**:
- Standard: W3C WebAuthn, FIDO2, CTAP2
- Curve: P-256 (NIST secp256r1)
- Algorithm: ECDSA with ES256 or RS256
- Storage: Hardware Secure Enclave / TPM
- Managed by: Operating System

**Capabilities**:
- ✅ Authenticate user identity
- ✅ Sign authentication challenges
- ✅ Trigger biometric/PIN prompts
- ✅ Sync across devices (iCloud/Google)
- ❌ Cannot sign Ethereum transactions (wrong curve)
- ❌ Cannot generate BIP39 mnemonics
- ❌ Cannot derive Ethereum addresses

**Data Structure**:
```typescript
interface WebAuthnCredential {
  id: string;              // Credential identifier
  publicKey: string;       // P-256 public key (SPKI format)
  username: string;
  ethereumAddress: string; // Link to wallet
  createdAt: string;
  lastUsed: string;
}
```

---

### 2. Crypto Wallet (HD Wallet)

**Purpose**: Blockchain transaction signing

**Technology**:
- Standards: BIP32, BIP39, BIP44, EIP-155
- Curve: secp256k1 (Bitcoin/Ethereum standard)
- Algorithm: ECDSA + Keccak-256
- Storage: IndexedDB (AES-256-GCM encrypted)
- Managed by: Application (w3pk)

**Capabilities**:
- ✅ Sign Ethereum transactions
- ✅ Derive unlimited addresses
- ✅ Recover from 12-word mnemonic
- ✅ Export private keys (app-controlled)
- ❌ Cannot authenticate users
- ❌ Cannot trigger biometric prompts
- ❌ Cannot sync via OS cloud
- ❌ Cannot sign WebAuthn challenges (wrong curve)

**Data Structure**:
```typescript
interface EncryptedWallet {
  ethereumAddress: string;  // Primary address (m/44'/60'/0'/0/0)
  encryptedMnemonic: string; // AES-256-GCM encrypted BIP39 phrase
  credentialId: string;      // Link to WebAuthn credential
  createdAt: string;
}
```

**Key Derivation Path** (BIP44):
```
Mnemonic (12 words)
    ↓
Seed (512 bits) via BIP39
    ↓
Master Private Key via HMAC-SHA512
    ↓
m/44'/60'/0'/0/0  ← Default Ethereum address
m/44'/60'/0'/0/1  ← Second address
m/44'/60'/0'/0/2  ← Third address
...
```

---

### 3. The Bridge (Encryption Layer)

**Purpose**: Link WebAuthn authentication to wallet encryption

**Implementation**: [src/wallet/crypto.ts:21-66](src/wallet/crypto.ts#L21-L66)

**Process**:
```typescript
function deriveEncryptionKeyFromWebAuthn(
  credentialId: string,
  publicKey: string
): CryptoKey {
  // Step 1: Combine inputs
  const keyMaterial = `w3pk-v4:${credentialId}:${publicKey}`;

  // Step 2: Hash with SHA-256
  const hash = SHA256(keyMaterial);

  // Step 3: PBKDF2 key derivation (210,000 iterations)
  const encryptionKey = PBKDF2(hash, salt, 210000);

  // Result: AES-256-GCM key (NEVER STORED)
  return encryptionKey;
}
```

**Properties**:
- **Deterministic**: Same inputs → Same output
- **Secure**: 210,000 PBKDF2 iterations (OWASP 2023)
- **Stateless**: No key storage required
- **Authentication-gated**: Requires biometric/PIN to access inputs

---

## Data Flow Diagrams

### Registration Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                      REGISTRATION PROCESS                       │
└─────────────────────────────────────────────────────────────────┘

STEP 1: Generate Crypto Wallet (INDEPENDENT)
┌──────────────────────────────────────┐
│  ethers.Wallet.createRandom()        │
│                                      │
│  Output:                             │
│  - Mnemonic (BIP39): "abandon..."    │
│  - Private Key (secp256k1)           │
│  - Address: 0x742d...                │
└──────────────────────────────────────┘
                 ↓

STEP 2: Create WebAuthn Credential (INDEPENDENT)
┌──────────────────────────────────────┐
│  navigator.credentials.create()      │
│                                      │
│  User Action: Face ID / Touch ID 👆  │
│                                      │
│  OS Creates:                         │
│  - P-256 key pair                    │
│  - Private key → Secure Enclave 🔒   │
│  - Public key → App                  │
│                                      │
│  Output:                             │
│  - credentialId: "abc123..."         │
│  - publicKey: "04A1B2C3D4..."        │
└──────────────────────────────────────┘
                 ↓

STEP 3: Derive Encryption Key
┌──────────────────────────────────────┐
│  deriveEncryptionKeyFromWebAuthn()   │
│                                      │
│  Input: credentialId + publicKey     │
│       ↓                              │
│  SHA-256 hash                        │
│       ↓                              │
│  PBKDF2 (210,000 iterations)         │
│       ↓                              │
│  AES-256-GCM Key (NOT STORED!)       │
└──────────────────────────────────────┘
                 ↓

STEP 4: Encrypt & Store
┌────────────────────────────┬────────────────────────────┐
│  localStorage              │  IndexedDB                 │
│  ─────────────             │  ─────────────             │
│                            │                            │
│  w3pk_credential_*:        │  Web3PasskeyWallet:        │
│  {                         │  {                         │
│    id: "hash(abc123)",     │    ethereumAddress,        │
│    publicKey (plaintext),  │    encryptedMnemonic,      │
│    encryptedUsername,      │    credentialId: "abc123"  │
│    encryptedAddress        │  }                         │
│  }                         │                            │
│                            │                            │
│  (WebAuthn metadata)       │  (Encrypted wallet)        │
└────────────────────────────┴────────────────────────────┘
```

### Login & Usage Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         LOGIN PROCESS                           │
└─────────────────────────────────────────────────────────────────┘

STEP 1: WebAuthn Authentication
┌──────────────────────────────────────┐
│  navigator.credentials.get()         │
│                                      │
│  User Action: Face ID / Touch ID 👆  │
│                                      │
│  OS signs challenge with P-256 key   │
│  in Secure Enclave                   │
│                                      │
│  Output: credentialId "abc123"       │
└──────────────────────────────────────┘
                 ↓

STEP 2: Fetch Stored Data
┌────────────────────────────┬────────────────────────────┐
│  localStorage              │  IndexedDB                 │
│                            │                            │
│  Get by credentialId:      │  Get by credentialId:      │
│  → publicKey               │  → encryptedMnemonic       │
└─────────────┬──────────────┴──────────────┬─────────────┘
              │                             │
              └──────────┬──────────────────┘
                         ↓

STEP 3: Re-derive Encryption Key (DETERMINISTIC!)
┌──────────────────────────────────────┐
│  Same inputs as registration:        │
│  - credentialId: "abc123"            │
│  - publicKey: "04A1B2C3D4..."        │
│       ↓                              │
│  Same SHA-256 hash                   │
│       ↓                              │
│  Same PBKDF2 (210,000 iterations)    │
│       ↓                              │
│  SAME AES-256-GCM Key!               │
└──────────────────────────────────────┘
                 ↓

STEP 4: Decrypt Mnemonic
┌──────────────────────────────────────┐
│  AES-GCM Decrypt                     │
│                                      │
│  decrypt(encryptedMnemonic, key)     │
│       ↓                              │
│  Mnemonic: "abandon ability..."      │
└──────────────────────────────────────┘
                 ↓

STEP 5: Recreate Wallet
┌──────────────────────────────────────┐
│  ethers.HDNodeWallet.fromPhrase()    │
│                                      │
│  Derives secp256k1 keys:             │
│  - Path: m/44'/60'/0'/0/0            │
│  - Private Key                       │
│  - Address: 0x742d...                │
│                                      │
│  ✅ Ready to sign transactions       │
└──────────────────────────────────────┘
```

### Transaction Signing Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                   ETHEREUM TRANSACTION SIGNING                  │
└─────────────────────────────────────────────────────────────────┘

User wants to send 1 ETH
         ↓

┌─────────────────────────────────────┐
│  Optional: Re-authenticate          │
│                                     │
│  If requireAuth: true               │
│    → Prompt Face ID again           │
│    → Re-decrypt mnemonic            │
│  Else:                              │
│    → Use cached session mnemonic    │
└─────────────────────────────────────┘
         ↓

┌─────────────────────────────────────┐
│  Build Transaction                  │
│  {                                  │
│    to: "0xRecipient...",            │
│    value: "1000000000000000000",    │
│    nonce: 42,                       │
│    gasLimit: 21000                  │
│  }                                  │
└─────────────────────────────────────┘
         ↓

┌─────────────────────────────────────┐
│  Sign with Crypto Wallet            │
│  (NOT WebAuthn!)                    │
│                                     │
│  Algorithm: secp256k1 ECDSA         │
│  Hash: Keccak-256                   │
│                                     │
│  wallet.signTransaction(tx)         │
│       ↓                             │
│  Signature: { r, s, v }             │
└─────────────────────────────────────┘
         ↓

┌─────────────────────────────────────┐
│  Broadcast to Ethereum              │
│                                     │
│  provider.sendTransaction(signedTx) │
│       ↓                             │
│  Transaction Hash: 0xabc123...      │
└─────────────────────────────────────┘
```

---

## Storage Architecture

### localStorage Structure

**Location**: `window.localStorage`
**Keys**: `w3pk_credential_*`
**Purpose**: WebAuthn credential metadata

```typescript
// Example: localStorage.getItem('w3pk_credential_abc123')
{
  id: "sha256_hash_of_credential_id",
  encryptedUsername: "AES-GCM...",      // Protected from XSS
  encryptedAddress: "AES-GCM...",       // Protected from XSS
  publicKey: "04A1B2C3D4E5F6...",       // PLAINTEXT (needed for encryption)
  publicKeyFingerprint: "sha256_hash",
  createdAt: "2024-11-25T12:00:00Z",
  lastUsed: "2024-11-25T15:30:00Z"
}
```

**Why publicKey is plaintext**: It's needed to derive the encryption key. It's the **public** part of the WebAuthn key pair—not sensitive.

### IndexedDB Structure

**Database**: `Web3PasskeyWallet`
**Store**: `wallets`
**Key Path**: `ethereumAddress`
**Purpose**: Encrypted wallet storage

```typescript
// Example record in IndexedDB
{
  ethereumAddress: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7",
  encryptedMnemonic: "U2FsdGVkX1+vupppZksvRf...",  // AES-256-GCM blob
  credentialId: "abc123...",                       // Link to WebAuthn
  createdAt: "2024-11-25T12:00:00Z"
}
```

**Security**: The mnemonic is encrypted with AES-256-GCM using the derived encryption key. Without WebAuthn authentication, it cannot be decrypted.

---

## Cryptographic Details

### Two Separate Signature Systems

#### WebAuthn Signature (Authentication)

```
┌─────────────────────────────────────────────┐
│  Purpose: Prove user identity              │
│  Curve: P-256 (NIST secp256r1)             │
│  Algorithm: ECDSA (ES256)                  │
│  Input: Random challenge                   │
│  Key Location: Hardware Secure Enclave     │
│  Output: Authentication signature          │
│                                            │
│  Used for: Unlocking access                │
│  NOT for: Blockchain transactions ❌        │
└─────────────────────────────────────────────┘
```

**Example**:
```javascript
// WebAuthn authentication (P-256)
const credential = await navigator.credentials.get({
  publicKey: { challenge: randomBytes(32) }
});
// Returns P-256 signature over the challenge
```

#### Crypto Wallet Signature (Transactions)

```
┌─────────────────────────────────────────────┐
│  Purpose: Authorize blockchain transaction │
│  Curve: secp256k1                          │
│  Algorithm: ECDSA + Keccak-256             │
│  Input: Transaction data                   │
│  Key Location: Derived from mnemonic       │
│  Output: Transaction signature (r, s, v)   │
│                                            │
│  Used for: Sending crypto                  │
│  NOT for: Authentication ❌                 │
└─────────────────────────────────────────────┘
```

**Example**:
```javascript
// Ethereum transaction (secp256k1)
const wallet = ethers.HDNodeWallet.fromPhrase(mnemonic);
const tx = { to: "0x...", value: ethers.parseEther("1.0") };
const signedTx = await wallet.signTransaction(tx);
// Returns secp256k1 signature over the transaction
```

### Why Different Curves?

| Aspect | P-256 | secp256k1 |
|--------|-------|-----------|
| **Standard** | NIST | Bitcoin/Ethereum |
| **Chosen By** | NSA (2000) | Satoshi Nakamoto (2009) |
| **Hardware Support** | ✅ Excellent | ❌ Limited |
| **WebAuthn** | ✅ Required | ❌ Not supported |
| **Ethereum** | ❌ Not supported | ✅ Required |
| **Compatibility** | **Incompatible** | **Incompatible** |

**Critical**: You **cannot** use a P-256 key to sign Ethereum transactions, and you **cannot** use a secp256k1 key for WebAuthn authentication. They are mathematically incompatible.

### Encryption Key Derivation (PBKDF2)

**Implementation**: [src/wallet/crypto.ts:21-66](src/wallet/crypto.ts#L21-L66)

```javascript
async function deriveEncryptionKeyFromWebAuthn(
  credentialId: string,
  publicKey: string
): Promise<CryptoKey> {
  // 1. Combine inputs into key material
  const keyMaterial = `w3pk-v4:${credentialId}:${publicKey}`;

  // 2. SHA-256 hash
  const keyMaterialHash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(keyMaterial)
  );

  // 3. Import as PBKDF2 base key
  const importedKey = await crypto.subtle.importKey(
    "raw",
    keyMaterialHash,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  // 4. Generate deterministic salt
  const salt = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode("w3pk-salt-v4")
  );

  // 5. Derive AES-256-GCM key
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array(salt),
      iterations: 210000,  // OWASP 2023 recommendation
      hash: "SHA-256",
    },
    importedKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
```

**Properties**:
- **Deterministic**: Same inputs always produce same output
- **Secure**: 210,000 iterations make brute-force impractical
- **Stateless**: No need to store the encryption key
- **Fast enough**: ~100-200ms on modern devices

---

## Security Model

### Four-Layer Defense

```
Layer 1: WebAuthn Authentication
┌─────────────────────────────────────┐
│  ✅ Biometric / PIN required        │
│  ✅ Hardware-backed (Secure Enclave)│
│  ✅ OS-level security               │
│  ✅ Phishing-resistant              │
└─────────────────────────────────────┘
         ↓ UNLOCKS ACCESS TO

Layer 2: Encryption Key Derivation
┌─────────────────────────────────────┐
│  ✅ PBKDF2 (210,000 iterations)     │
│  ✅ Deterministic (no storage)      │
│  ✅ Requires WebAuthn success       │
└─────────────────────────────────────┘
         ↓ DECRYPTS

Layer 3: Encrypted Mnemonic Storage
┌─────────────────────────────────────┐
│  ✅ AES-256-GCM encryption          │
│  ✅ IndexedDB storage               │
│  ✅ Cannot decrypt without Layers 1&2│
└─────────────────────────────────────┘
         ↓ REVEALS

Layer 4: Crypto Wallet
┌─────────────────────────────────────┐
│  ✅ BIP39 mnemonic                  │
│  ✅ HD key derivation (BIP32/44)    │
│  ✅ Signs blockchain transactions   │
└─────────────────────────────────────┘
```

### Threat Model

#### ✅ Protected Against

| Threat | Protection |
|--------|-----------|
| **XSS attacks** | Username/address encrypted in localStorage |
| **Phishing** | WebAuthn verifies origin (FIDO2) |
| **Keyloggers** | No passwords—biometric only |
| **Credential stuffing** | No shared credentials across sites |
| **Device theft (locked)** | Requires biometric/PIN |
| **Cloud backup theft** | Passkey synced, but needs device to use |

#### ⚠️ Requires User Vigilance

| Threat | User Action Required |
|--------|---------------------|
| **Device theft (unlocked)** | Lock device, create mnemonic backup |
| **Malicious apps** | Only use trusted apps |
| **Compromised browser** | Use up-to-date browser |
| **Lost mnemonic backup** | Store backup securely (not digitally) |

#### ❌ Cannot Protect Against

| Threat | Reason |
|--------|--------|
| **No backup created** | User never wrote down 12 words |
| **Both device + backup lost** | Irrecoverable without either |
| **Physical access to unlocked device** | Attacker can export mnemonic |

---

## Recovery Scenarios

### Scenario 1: Lost Device (✅ Have Backup)

```
Situation:
  Device: ❌ Lost
  Passkey: ❌ Lost (was on device)
  Mnemonic: ✅ Have 12-word backup

Recovery Steps:
  1. Get new device
  2. Install w3pk app
  3. Click "Restore from backup"
  4. Enter 12-word mnemonic ✅
  5. Create new WebAuthn credential ✅
  6. Wallet re-encrypted with new passkey ✅

Result: ✅ Full recovery
```

### Scenario 2: Lost Backup (✅ Have Device)

```
Situation:
  Device: ✅ Still have it
  Passkey: ✅ Works (iCloud/Google synced)
  Mnemonic: ❌ Never wrote it down / lost it

Recovery Steps:
  1. Login with existing passkey ✅
  2. Call w3pk.exportMnemonic() ✅
  3. Write down 12 words immediately ✅
  4. Store backup securely ✅

Result: ✅ Can create new backup
Warning: Do this ASAP before losing device!
```

### Scenario 3: Forgot Password (N/A)

```
Situation:
  User: "I forgot my password"

Response:
  ❌ There is no password!
  ✅ Use biometric (Face ID / Touch ID)
  ✅ Or enter 12-word mnemonic backup

Result: ✅ Passwordless = no password to forget
```

### Scenario 4: Lost Both (❌ Irrecoverable)

```
Situation:
  Device: ❌ Lost
  Passkey: ❌ Lost (no cloud backup)
  Mnemonic: ❌ Never created backup

Recovery Steps:
  None. Funds are permanently lost.

Reason:
  - WebAuthn credential cannot be recovered
  - Mnemonic never backed up
  - No way to decrypt encrypted wallet

Prevention:
  ✅ ALWAYS create mnemonic backup during registration!
```

---

## Common Misconceptions

### ❌ "The passkey IS the wallet"

**False.** They are separate systems:
- Passkey: P-256 authentication key (OS-managed)
- Wallet: secp256k1 Ethereum keys (app-managed)

The passkey **unlocks access** to the wallet.

### ❌ "Lose your passkey = lose your crypto"

**False.** You can restore from the 12-word mnemonic:
1. Enter mnemonic on new device
2. Create new passkey
3. Wallet re-encrypted with new passkey

The mnemonic is your **ultimate backup**.

### ❌ "The passkey signs Ethereum transactions"

**False.** Different curves:
- Passkey uses P-256 (WebAuthn standard)
- Ethereum uses secp256k1 (blockchain standard)
- **Incompatible**—cannot use passkey for Ethereum

### ❌ "The mnemonic is derived from the passkey"

**False.** The mnemonic is randomly generated:
1. Generate random BIP39 mnemonic (12 words)
2. Create passkey separately
3. Use passkey metadata to encrypt mnemonic

They are **independent** until encryption.

### ❌ "I only need the 12 words"

**Partially true, but misses the point:**
- ✅ 12 words can recover your crypto
- ❌ But you lose biometric convenience
- ✅ Better: Have both passkey (convenience) + backup (safety)

### ❌ "WebAuthn is a crypto wallet standard"

**False.** WebAuthn is an **authentication** standard:
- Created by: W3C + FIDO Alliance
- Purpose: Replace passwords
- Not designed for: Cryptocurrency

w3pk **bridges** WebAuthn and crypto wallets.

### ✅ "The passkey unlocks access to the wallet"

**True!** Correct mental model:
```
Passkey (Face ID) → Decrypt mnemonic → Use wallet
```

---

## Component Comparison Table

| Feature | WebAuthn | Crypto Wallet | The Bridge |
|---------|----------|---------------|------------|
| **Curve** | P-256 | secp256k1 | N/A (uses AES) |
| **Purpose** | Authentication | Transactions | Encryption |
| **Storage** | Secure Enclave | IndexedDB | None (derived) |
| **Backup** | iCloud/Google | 12-word phrase | N/A |
| **Standards** | FIDO2, W3C | BIP32/39/44 | PBKDF2, AES-GCM |
| **Managed By** | OS | App | App |
| **Can Sign ETH TX** | ❌ No | ✅ Yes | ❌ No |
| **Can Authenticate** | ✅ Yes | ❌ No | ❌ No |
| **Requires Biometric** | ✅ Yes | ❌ No | ✅ Yes (indirectly) |
| **Cloud Sync** | ✅ Yes | ❌ No | ❌ No |
| **Recoverable** | Via cloud/device | Via 12 words | Re-derived |

---

## Why This Architecture?

### Problem: Single Point of Failure

Traditional crypto wallets:
```
Lose 12-word mnemonic → Lose everything ❌
```

### Solution: Defense in Depth

w3pk architecture:
```
Layer 1: WebAuthn     → Biometric convenience + cloud sync
Layer 2: Session      → Prevents repeated prompts (1 hour)
Layer 3: Mnemonic     → Ultimate backup and recovery

Scenarios:
  Lose device?     → ✅ Restore from mnemonic
  Lose mnemonic?   → ✅ Still accessible via passkey (if device works)
  Lose both?       → ❌ Should have created backup!
```

### Benefits

1. **Best UX**: Biometric authentication (no passwords)
2. **Best Security**: Hardware-backed + encrypted storage
3. **Best Recovery**: Multiple options (cloud sync + mnemonic)
4. **Web3 Native**: Full Ethereum compatibility
5. **Standards-Based**: W3C + BIP standards

---

## Quick Reference

### What's in localStorage?

```json
{
  "id": "hashed_credential_id",
  "publicKey": "04A1B2C3D4... (plaintext)",
  "encryptedUsername": "AES-GCM...",
  "encryptedAddress": "AES-GCM...",
  "createdAt": "2024-11-25T..."
}
```

### What's in IndexedDB?

```json
{
  "ethereumAddress": "0x742d...",
  "encryptedMnemonic": "U2FsdGVkX1+... (AES-GCM)",
  "credentialId": "abc123",
  "createdAt": "2024-11-25T..."
}
```

### Key Derivation Formula

```
encryptionKey = PBKDF2(
  SHA256("w3pk-v4:" + credentialId + ":" + publicKey),
  SHA256("w3pk-salt-v4"),
  210000 iterations
)
```

---

## Further Reading

- [SECURITY.md](./docs/SECURITY.md) - Complete security documentation
- [RECOVERY.md](./docs/RECOVERY.md) - Backup and recovery guide
- [API_REFERENCE.md](./docs/API_REFERENCE.md) - Full API documentation
- [WebAuthn Spec](https://www.w3.org/TR/webauthn-2/) - W3C standard
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) - Mnemonic specification
- [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) - HD wallet paths

---

## Summary

**w3pk combines WebAuthn (P-256 authentication) and Crypto Wallets (secp256k1 transactions) through a PBKDF2-derived encryption bridge. They are completely separate cryptographic systems that work together to provide biometric-protected Web3 access with multiple recovery options.**
