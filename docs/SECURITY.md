# Security Architecture

This document explains the security model of w3pk and how wallet protection works.

## Overview

w3pk uses **WebAuthn signatures** to derive encryption keys, ensuring that wallets can **only be decrypted with biometric/PIN authentication**. Even if an attacker gains full access to your computer, they **cannot steal your wallet** without your fingerprint/face/PIN.

For better user experience, w3pk implements **secure sessions** that cache the decrypted mnemonic in memory for a configurable duration (default 1 hour), allowing operations without repeated authentication prompts while maintaining security.

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

## Session Management

### How Sessions Work

w3pk implements **secure in-memory sessions** for better UX. After initial authentication, the decrypted mnemonic is cached in memory for a configurable duration.

```typescript
// Configure session duration (default: 1 hour)
const w3pk = new Web3Passkey({
  sessionDuration: 1 // hours
})

// After login, operations work without repeated authentication
await w3pk.login()              // ✅ Requires biometric
await w3pk.deriveWallet(0)      // ✅ Uses session (no prompt)
await w3pk.exportMnemonic()     // ✅ Uses session (no prompt)
await w3pk.stealth.getKeys()    // ✅ Uses session (no prompt)

// Session expires after 1 hour - next operation will prompt
await w3pk.deriveWallet(1)      // ✅ Prompts for biometric (session expired)
```

### Session Security

**What's cached:**
- ✅ Decrypted mnemonic (in memory only)
- ✅ Session expiration timestamp
- ✅ Credential ID

**What's NOT cached:**
- ❌ Private keys (derived on-demand)
- ❌ WebAuthn signatures (fresh each time)
- ❌ Encryption keys (derived from signatures)

**Security properties:**
- Sessions exist **only in RAM** - never persisted to disk
- Automatically cleared after expiration
- Cleared on logout
- Cleared when browser tab closes
- Can be manually cleared with `clearSession()`

### Session Management API

```typescript
// Check if session is active
const hasSession = w3pk.hasActiveSession()

// Get remaining time (in seconds)
const remaining = w3pk.getSessionRemainingTime()

// Extend session by configured duration
w3pk.extendSession()

// Manually clear session (force re-authentication)
w3pk.clearSession()

// Update session duration
w3pk.setSessionDuration(2) // 2 hours

// Disable sessions entirely (most secure)
const w3pk = new Web3Passkey({ sessionDuration: 0 })
```

### Force Authentication Option

Developers can require fresh authentication for specific operations, even when a session is active:

```typescript
// Force authentication for sensitive operations
await w3pk.exportMnemonic({ requireAuth: true })
await w3pk.signMessage('Transfer $1000', { requireAuth: true })
await w3pk.deriveWallet(5, { requireAuth: true })
await w3pk.stealth.getKeys({ requireAuth: true })

// Example: Context-based security
async function transferFunds(amount: number, recipient: string) {
  // Require fresh auth for high-value transactions
  const requireAuth = amount > 100

  const signature = await w3pk.signMessage(
    `Transfer ${amount} to ${recipient}`,
    { requireAuth }
  )

  // ... submit transaction
}

// Example: Time-based security
async function exportBackup() {
  // Always require fresh auth for backup exports
  const mnemonic = await w3pk.exportMnemonic({ requireAuth: true })

  // ... show mnemonic to user
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
// Attacker can steal mnemonic during session window
setInterval(async () => {
  if (w3pk.hasActiveSession()) {
    const mnemonic = await w3pk.exportMnemonic({ requireAuth: false })
    sendToAttacker(mnemonic) // ❌ Stolen!
  }
}, 1000)

// Mitigation: Very short sessions
const w3pk = new Web3Passkey({ sessionDuration: 0.1 }) // 6 minutes

// Scenario: XSS attack + expired session
await w3pk.exportMnemonic({ requireAuth: false })
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

### 1. Prevent XSS Attacks

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

### 2. Defend Against Malicious Browser Extensions

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

### 3. Prevent Compromised Dependencies (Supply Chain)

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

### 4. Prevent Code Injection

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
      w3pk.exportMnemonic.toString(),
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
Object.freeze(w3pk.exportMnemonic)
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
monitor.trackOperation('exportMnemonic')
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
