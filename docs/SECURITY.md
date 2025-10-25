# Security Architecture

This document explains the security model of w3pk and how wallet protection works.

## Overview

w3pk uses **WebAuthn signatures** to derive encryption keys, ensuring that wallets can **only be decrypted with biometric/PIN authentication**. Even if an attacker gains full access to your computer, they **cannot steal your wallet** without your fingerprint/face/PIN.

## Security Guarantees

### ✅ Protected Against

1. **File System Access** - Attacker with access to browser storage cannot decrypt wallet
2. **Malware/Keyloggers** - Encryption key never exists in recoverable form
3. **Memory Dumps** - Keys are ephemeral and derived on-demand
4. **Database Theft** - Encrypted wallet is useless without biometric authentication
5. **JavaScript Injection** - Cannot replay signatures (fresh challenge each time)

### ⚠️ NOT Protected Against

1. **Physical coercion** - Forcing user to authenticate
2. **Compromised authenticator** - If hardware is backdoored
3. **Active browser session** - If wallet is in memory and user is authenticated

## How It Works

### 1. Encryption Key Derivation

**The encryption key is derived from a WebAuthn signature:**

```typescript
// SECURE: Signature requires biometric/PIN authentication
const signature = await navigator.credentials.get({
  publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: window.location.hostname,
    userVerification: "required" // Force biometric/PIN
  }
})

// Derive encryption key from signature
const key = await deriveEncryptionKeyFromSignature(
  signature.response.signature,
  credentialId
)

// Encrypt wallet
const encryptedWallet = await encryptData(mnemonic, key)
```

**Why this is secure:**

- The `signature` can **only** be obtained by:
  1. User providing biometric (fingerprint/face) OR
  2. User entering device PIN/password
- The signature is **different every time** (fresh challenge)
- Cannot be replayed or stolen from storage
- Signature never leaves the browser

### 2. What's Stored (All Safe to Expose)

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

#### IndexedDB (Encrypted Wallet)
```json
{
  "ethereumAddress": "0x1234...5678",
  "encryptedMnemonic": "v1kT...x3Zp",  // AES-GCM encrypted
  "credentialId": "credential-abc123",
  "createdAt": 1234567890
}
```

**NO secrets stored:**
- No private keys
- No challenge values
- No decryption keys
- Only public identifiers + encrypted data

### 3. Attack Scenario Analysis

#### ❌ Attack: Copy files and decrypt offline

```javascript
// Attacker steals browser storage
const stolen = {
  encryptedMnemonic: "v1kT...x3Zp",
  credentialId: "credential-abc123"
}

// Try to decrypt
const key = deriveEncryptionKeyFromSignature(???, credentialId)
//                                           ^^^
//                                           BLOCKED: Cannot get signature
//                                           Requires user's biometric/PIN
```

**Result:** ❌ **Attack fails** - Cannot obtain signature without authentication

#### ❌ Attack: JavaScript injection to read wallet

```javascript
// Malicious script tries to decrypt wallet
const signature = await navigator.credentials.get({...})
//                      ^^^^^^^^^^^^^^^^^^^
//                      BLOCKED: Browser shows authentication prompt
//                      User sees malicious domain
//                      User denies (or doesn't recognize the request)
```

**Result:** ❌ **Attack fails** - User must explicitly authenticate

#### ❌ Attack: Replay old signature

```javascript
// Attacker records a signature from network traffic
const oldSignature = capturedFromNetwork()

// Try to use it
const key = await deriveEncryptionKeyFromSignature(oldSignature, credentialId)
const decrypted = await decryptData(encryptedWallet, key)
//                      ^^^^^^^^^^^
//                      BLOCKED: Signatures are tied to fresh random challenges
//                      Old signature won't decrypt (different challenge = different signature)
```

**Result:** ❌ **Attack fails** - Signatures cannot be replayed

## Encryption Strength

### Key Derivation
- **Algorithm:** PBKDF2
- **Iterations:** 210,000 (OWASP 2023 recommendation)
- **Hash:** SHA-256
- **Salt:** Unique per credential (credentialId)

### Encryption
- **Algorithm:** AES-GCM
- **Key Size:** 256 bits
- **IV:** Random 12 bytes per encryption
- **Authentication:** Built-in (GCM mode)

### Signature Entropy
- WebAuthn signatures are typically **ECDSA P-256**
- **256 bits** of entropy from signature
- **256 bits** additional entropy from challenge
- Combined: **512 bits** of key material

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
│  └─────────────────────────────────┘    │
│                                          │
│  IndexedDB                               │
│  ┌─────────────────────────────────┐    │
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
- In browser IndexedDB (encrypted)
- Can only be decrypted with WebAuthn signature
- Requires fresh biometric authentication

**This means:**
- Losing your authenticator = Lose access to decrypt wallet
- **CRITICAL:** Users must save their mnemonic phrase
- Mnemonic is the ultimate recovery mechanism
- WebAuthn is for convenience + security, not recovery

## Best Practices for Users

### 1. **Always Save Your Mnemonic**
```typescript
const { mnemonic } = await w3pk.register({ username: 'alice' })

// ⚠️ CRITICAL: Save this offline
console.log('Write this down:', mnemonic)

await w3pk.saveWallet()
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
6. **Use `saveWallet()` immediately** after registration

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
| Password required | ❌ No | ✅ Yes | ❌ No |
| Biometric auth | ✅ Yes | ❌ No | ❌ No |
| Seed phrase backup | ✅ Required | ✅ Required | ✅ Required |
| File access = theft? | ❌ **No** | ✅ **Yes** | ❌ No |
| Keylogger risk | ❌ **No** | ✅ **Yes** | ❌ No |
| Hardware required | ❌ No | ❌ No | ✅ Yes |
| Cost | Free | Free | $50-200 |

## Conclusion

w3pk's security model ensures that **even with full file system access, an attacker cannot decrypt your wallet** without your biometric or device PIN. The encryption key is derived from WebAuthn signatures, which can only be obtained through hardware-protected authentication.

**Key Takeaway:** Your wallet is protected by the same hardware security that protects your phone/computer unlock. An attacker would need:
1. Physical access to your device, AND
2. Your fingerprint/face/PIN, AND
3. Active browser session

This makes w3pk significantly more secure than traditional password-protected wallets while maintaining the same recovery mechanism (mnemonic phrase).
