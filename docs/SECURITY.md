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
- Copy your IndexedDB data
- Trick you into visiting their site
- Use an identical UI

The browser enforces that credentials for `example.com` can only be used on `example.com`.

#### ✅ Origin-Based Storage Isolation

```typescript
// Browser storage is automatically scoped by origin
localStorage  // Scoped to "https://example.com"
IndexedDB     // Scoped to "https://example.com"

// A different origin cannot access this storage
// - https://attacker.com → different origin
// - https://subdomain.example.com → different origin (unless RP ID configured for parent)
// - http://example.com → different origin (different protocol)
```

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
// Key: w3pk_credential_<credentialId>
{
  "id": "credential-abc123",
  "publicKey": "MFkw...",      // Public key only
  "username": "alice",
  "ethereumAddress": "0x1234...",
  "createdAt": 1234567890
}

// IndexedDB (origin-scoped by browser)
// Store: wallets
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

1. **localStorage**: Origin-scoped by browser (cannot access from different origin)
2. **IndexedDB**: Origin-scoped by browser + encrypted with WebAuthn signature
3. **Authenticator**: RP ID-bound + hardware-protected

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

## Backup & Recovery Security

w3pk implements a **three-layer backup and recovery system** that balances security, usability, and resilience. Each layer uses different cryptographic primitives and trust models.

### Layer 1: Passkey Auto-Sync (Platform-Based)

**How it works:**
- WebAuthn credentials automatically sync via platform services (iCloud Keychain, Google Password Manager, Microsoft Account)
- Encrypted end-to-end by platform provider
- Requires device unlock + cloud account authentication

**Security properties:**
- ✅ **Encrypted in transit** - Platform handles E2E encryption
- ✅ **Hardware-backed** - Credentials protected by Secure Enclave/TPM
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
- Multiple backup formats: password-protected ZIP, QR code
- Encryption: **AES-256-GCM** with **PBKDF2** (310,000 iterations, OWASP 2025 standard)

**Security properties:**
- ✅ **Military-grade encryption** - AES-256-GCM
- ✅ **Password-based** - User controls secret
- ✅ **Offline storage** - Can be stored on paper/USB/safe
- ✅ **Platform-independent** - Works across any device
- ⚠️ **Password strength critical** - Weak password = vulnerable

**Cryptographic details:**
```typescript
// Key derivation
PBKDF2-SHA256
├─ Iterations: 310,000 (OWASP 2025)
├─ Salt: 32 bytes (random per backup)
└─ Output: 256-bit key

// Encryption
AES-256-GCM
├─ Key: From PBKDF2
├─ IV: 12 bytes (random per encryption)
├─ Auth tag: 16 bytes (automatic)
└─ Additional data: Ethereum address (for integrity)
```

**Password validation:**
w3pk enforces strong passwords:
- Minimum 12 characters
- Uppercase + lowercase + numbers + special chars
- Not in common password list
- Strength score ≥50/100 required

**Threat model:**
| Threat | Protected? | Notes |
|--------|-----------|-------|
| Backup file stolen | ✅ Yes | Requires password to decrypt |
| Weak password | ⚠️ Vulnerable | User responsibility |
| Password forgotten | ❌ Unrecoverable | Need Layer 3 (social recovery) |
| Brute force (strong password) | ✅ Yes | 310k iterations slow down attacks |
| Brute force (weak password) | ❌ Vulnerable | Minutes to hours with GPU |

**Brute force analysis:**

Assuming attacker has:
- Modern GPU (RTX 4090)
- ~100,000 PBKDF2-SHA256 hashes/second at 310k iterations

| Password Type | Entropy | Time to Crack |
|--------------|---------|---------------|
| `password123` (common) | ~20 bits | Seconds |
| `MyPassword123!` (weak) | ~35 bits | Hours |
| `MyS3cur3!Pass@2024` (medium) | ~50 bits | Months |
| `correct horse battery staple` (strong) | ~80 bits | Centuries |
| Truly random 16 chars | ~100 bits | Universe lifetime |

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

w3pk calculates a security score (0-100) based on active backup methods:

| Configuration | Score | Level |
|--------------|-------|-------|
| No backups | 0-25 | 🔴 Vulnerable |
| Passkey sync only | 30-50 | 🟡 Protected |
| Passkey + encrypted backup | 60-80 | 🟢 Secured |
| All three layers | 85-100 | 🟦 Fort Knox |

**Score calculation:**
```typescript
score = 0
+ (passkeySync.enabled ? 30 : 0)
+ (backups.zip > 0 ? 25 : 0)
+ (backups.qr > 0 ? 15 : 0)
+ (socialRecovery.configured ? 30 : 0)
```

### Backup Best Practices

**1. Use multiple layers:**
```typescript
// ✅ GOOD: Enable all three layers
await w3pk.setupSocialRecovery([...guardians], 3)
await w3pk.createZipBackup('MyS3cur3!Password@2024')
// Passkey sync enabled by default on platform

// ❌ BAD: Rely on single layer
// (only passkey sync - what if switch platforms?)
```

**2. Test recovery before trusting:**
```typescript
// Simulate recovery scenarios
const test1 = await w3pk.simulateRecoveryScenario({
  type: 'lost-device',
  hasBackup: true,
  hasSocialRecovery: true
})
console.log('Can recover?', test1.canRecover)

const test2 = await w3pk.simulateRecoveryScenario({
  type: 'lost-phrase',
  hasPasskeySync: true
})
console.log('Can recover?', test2.canRecover)
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
'correct horse battery staple'  // Multi-word passphrase
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
await w3pk.createZipBackup(password)        // ✅ Auth required
await w3pk.createQRBackup(password)         // ✅ Auth required
await w3pk.setupSocialRecovery(...)         // ✅ Auth required
await w3pk.exportMnemonic()                 // ✅ Auth required

// Read-only operations don't require auth
await w3pk.getBackupStatus()                // ✅ No auth needed
await w3pk.getSyncStatus()                  // ✅ No auth needed
```

**Password validation is client-side:**
⚠️ **Important:** Password strength is checked in the browser. A determined attacker with code execution could bypass validation and create backups with weak passwords.

**Mitigation:**
- Use `requireAuth: true` for backup creation
- Short session durations
- XSS/injection protection (CSP, input sanitization)
- Educate users on password strength

**Recovery operations don't require authentication:**
```typescript
// Recovery from existing backups is public
await w3pk.restoreFromBackup(encryptedData, password)
await w3pk.recoverFromGuardians([shares...])

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
