# Integration Guidelines

This guide covers essential best practices for integrating w3pk into your application.

## Table of Contents

- [Wallet Derivation Strategy](#wallet-derivation-strategy)
- [Registration Flow](#registration-flow)
- [Backup & Recovery](#backup--recovery)
- [Security Considerations](#security-considerations)

---

## Wallet Derivation Strategy

### Default: Use STANDARD Mode

**Best Practice:** For most applications, use the default STANDARD mode wallet derivation.

```typescript
// ✅ Recommended for most use cases
const wallet = await w3pk.deriveWallet()
// Returns: { address, index, origin, mode: 'STANDARD', tag: 'MAIN' }
// No private key exposed
// Persistent sessions allowed
```

**Why STANDARD mode?**
- **Security:** Private keys are never exposed to your application
- **User Control:** Users retain full custody of their wallet
- **Signing:** You can still sign messages and transactions via `w3pk.signMessage()`
- **Trust:** Users don't need to trust your application with key material
- **Convenience:** Supports persistent sessions for "Remember Me" functionality

### STRICT Mode: Maximum Security

**Use STRICT mode for high-security applications that need extra protection.**

```typescript
// ✅ For banking, high-value DeFi, or sensitive operations
const strictWallet = await w3pk.deriveWallet('STRICT')
// Returns: { address, index, origin, mode: 'STRICT', tag: 'MAIN' }
// No private key exposed
// Requires biometric/PIN authentication every time (no persistent sessions)
```

**When to use STRICT mode:**
- Banking and financial applications
- High-value DeFi protocols
- Enterprise/corporate wallets
- Compliance-focused applications
- Applications handling sensitive assets

### YOLO Mode: When You Need Private Keys

**Use YOLO mode ONLY when your application requires direct access to private keys.**

```typescript
// ⚠️ Use only when necessary (non-financial apps, games, etc.)
const yoloWallet = await w3pk.deriveWallet('YOLO')
// Returns: { address, privateKey, index, origin, mode: 'YOLO', tag: 'MAIN' }
// Private key exposed
// Persistent sessions allowed

// With custom tag for specific features
const gamingWallet = await w3pk.deriveWallet('YOLO', 'GAMING')
```

**Valid Use Cases:**
- Gaming applications (low-value in-game assets)
- Social applications (non-financial operations)
- Throwaway wallets for testing/development
- Apps where users explicitly want your app to manage keys

**Important Security Implications:**

When you use YOLO mode, **you control the user's private key** for that specific derived wallet. This means:

1. **Custody Risk:** Your application has full access to the private key
2. **User Trust:** Users must trust your application not to misuse their keys
3. **Liability:** Your application is responsible for securing these keys
4. **Regulatory:** May have compliance implications depending on jurisdiction

```typescript
// Different modes create different addresses
const standard = await w3pk.deriveWallet()                    // STANDARD - no private key
const strict = await w3pk.deriveWallet('STRICT')              // STRICT - no private key, no sessions
const yolo = await w3pk.deriveWallet('YOLO')                  // YOLO - has private key
const gaming = await w3pk.deriveWallet('YOLO', 'GAMING')      // YOLO + custom tag

console.log(standard.address !== strict.address)    // true (different modes)
console.log(standard.address !== yolo.address)      // true (different modes)
console.log(yolo.address !== gaming.address)        // true (different tags)
```

**Decision Matrix:**

| Use Case | Recommended Mode |
|----------|------------------|
| Financial transactions | STANDARD mode |
| DeFi applications | STANDARD mode |
| NFT purchases | STANDARD mode |
| Banking/high-value | STRICT mode |
| Enterprise wallets | STRICT mode |
| Gaming (low value) | YOLO mode |
| Social features | YOLO mode |
| Testing/development | YOLO mode |

---

## Signing Methods

w3pk supports multiple signing methods for different use cases. Choose the appropriate method based on your application's requirements.

### EIP-191 (Default): Standard Message Signing

```typescript
// Standard Ethereum signed message
const result = await w3pk.signMessage('Hello World')
// Uses EIP-191 prefix: "\x19Ethereum Signed Message:\n<length>"
```

**Use for:**
- General message signing
- Wallet authentication
- Proof of ownership
- Simple signatures

### SIWE: Sign-In with Ethereum (EIP-4361)

```typescript
import { createSiweMessage, generateSiweNonce } from 'w3pk'

// Create properly formatted SIWE message
const message = createSiweMessage({
  domain: 'app.example.com',
  address: await w3pk.getAddress(),
  uri: 'https://app.example.com/login',
  version: '1',
  chainId: 1,
  nonce: generateSiweNonce(),
  issuedAt: new Date().toISOString(),
  statement: 'Sign in to Example App'
})

// Sign with SIWE method
const result = await w3pk.signMessage(message, {
  signingMethod: 'SIWE'
})
```

**Use for:**
- Web3 authentication flows
- dApp login
- Decentralized identity
- Session management

### EIP-712: Structured Typed Data

```typescript
// Define EIP-712 structure
const domain = {
  name: 'MyDApp',
  version: '1',
  chainId: 1,
  verifyingContract: '0x...'
}

const types = {
  Transfer: [
    { name: 'to', type: 'address' },
    { name: 'amount', type: 'uint256' }
  ]
}

const message = {
  to: '0x...',
  amount: '1000000000000000000'
}

// Sign typed data
const result = await w3pk.signMessage(JSON.stringify(message), {
  signingMethod: 'EIP712',
  eip712Domain: domain,
  eip712Types: types,
  eip712PrimaryType: 'Transfer'
})
```

**Use for:**
- Token permits (gasless approvals)
- DAO voting
- NFT minting signatures
- Meta-transactions
- Any structured data requiring user approval

### rawHash: Pre-computed Hashes

```typescript
import { TypedDataEncoder } from 'ethers'

// Compute hash manually (if needed for custom schemes)
const hash = TypedDataEncoder.hash(domain, types, message)

// Sign the raw hash
const result = await w3pk.signMessage(hash, {
  signingMethod: 'rawHash'
})
```

**Use for:**
- Safe multisig transactions
- Custom signature schemes
- Pre-computed EIP-712 hashes
- Advanced use cases

### Choosing the Right Method

| Use Case | Method | Reason |
|----------|--------|---------|
| User authentication | SIWE | Standardized Web3 login |
| General signatures | EIP-191 | Simple and universal |
| Token permits | EIP-712 | Gasless approvals |
| DAO voting | EIP-712 | Structured proposals |
| Safe multisig | rawHash | Pre-computed transaction hashes |
| NFT allowlist | EIP-712 | Structured whitelist data |
| Gasless meta-tx | EIP-712 | Relayer signatures |

---

## Registration Flow

### Check for Existing Wallet First

**Critical:** Before registering a new wallet, always check if one exists on the device.

#### Available Methods

w3pk provides three methods for checking existing credentials:

1. **`hasExistingCredential(): Promise<boolean>`**
   - Returns `true` if at least one wallet exists on the device
   - Use for simple yes/no checks

2. **`getExistingCredentialCount(): Promise<number>`**
   - Returns the number of existing wallets
   - Useful for showing counts in warning messages

3. **`listExistingCredentials(): Promise<Array<{username, ethereumAddress, createdAt, lastUsed}>>`**
   - Returns full list of wallets with metadata
   - Use for showing users which wallets they have

```typescript
// ✅ Correct registration flow
async function handleUserOnboarding() {
  try {
    // Check if user already has a wallet on this device
    const hasExisting = await w3pk.hasExistingCredential()

    if (hasExisting) {
      // User already has a wallet - use login instead
      console.log('Found existing wallet, logging in...')
      await w3pk.login()
      return
    }

    // No existing wallet - proceed with registration
    const { address, username } = await w3pk.register({
      username: 'user@example.com'
    })

    console.log('New wallet created:', address)

    // Prompt for backup immediately after registration
    promptUserForBackup()

  } catch (error) {
    console.error('Onboarding failed:', error)
  }
}
```

**Why This Matters:**

1. **Apple Platform Limitation:** iOS/macOS have a unique Relying Party ID (RP ID) per domain
   - Creating multiple passkeys on the same device can cause conflicts
   - Better UX to have one wallet per device, synced via iCloud/Google

2. **User Experience:**
   - Prevents confusion from multiple wallets
   - Leverages platform passkey sync (iCloud Keychain, Google Password Manager)
   - Simplifies backup and recovery

3. **Security:**
   - Reduces attack surface (fewer credentials to manage)
   - Clearer security model for users

**Example 1: Simple Flow (Auto-Login if Wallet Exists)**

```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey({
  sessionDuration: 2 // 2 hour sessions
})

async function onboardUser(email: string) {
  // 1. Check for existing credential
  const existing = await w3pk.hasExistingCredential()

  if (existing) {
    // Show "Welcome back" UI
    await w3pk.login()
    return { isNewUser: false }
  }

  // 2. Register new user
  const { address, username } = await w3pk.register({
    username: email
  })

  // 3. Show success message
  console.log(`✅ Wallet created: ${address}`)

  // 4. Immediately prompt for backup
  await promptBackupOptions()

  return { isNewUser: true, address }
}
```

**Example 2: Advanced Flow with Warning (Allows Multiple Wallets)**

For applications that want to support multiple wallets but warn users:

```typescript
async function onboardUserWithWarning(email: string) {
  // 1. Check for existing credentials
  const count = await w3pk.getExistingCredentialCount()

  if (count > 0) {
    // 2. List existing wallets
    const existingWallets = await w3pk.listExistingCredentials()

    // 3. Show warning dialog to user
    const userChoice = await showWarningDialog({
      title: 'Wallet Already Exists',
      message: `You have ${count} wallet(s) on this device:

${existingWallets.map((w, i) => `${i + 1}. ${w.username} (${w.ethereumAddress.slice(0, 10)}...)`).join('\n')}

⚠️ Creating a NEW wallet will generate a DIFFERENT address.
Funds sent to different addresses won't appear in the same wallet.

What would you like to do?`,
      options: [
        { label: 'Login to Existing Wallet', value: 'login' },
        { label: 'Create New Wallet', value: 'create', warning: true },
        { label: 'Cancel', value: 'cancel' }
      ]
    })

    if (userChoice === 'login') {
      // Let user select which wallet to login to
      await w3pk.login()
      return { isNewUser: false }
    } else if (userChoice === 'cancel') {
      throw new Error('User cancelled registration')
    }
    // else: userChoice === 'create', continue with registration
  }

  // 4. Proceed with registration (user explicitly confirmed or no existing wallet)
  const { address, username } = await w3pk.register({
    username: email
  })

  console.log(`✅ New wallet created: ${address}`)
  await promptBackupOptions()

  return { isNewUser: true, address }
}

async function promptBackupOptions() {
  // Show modal/screen with backup options
  const userChoice = await showBackupModal()

  if (userChoice === 'qr-code') {
    const { qrCodeDataURL } = await w3pk.createQRBackup()
    displayQRCode(qrCodeDataURL)
  } else if (userChoice === 'social-recovery') {
    await setupSocialRecoveryFlow()
  }
}
```

---

## Backup & Recovery

### Allow Users Multiple Backup Options

**Critical:** Users should set up at least one backup method immediately after registration.

```typescript
// ✅ Provide multiple backup options
async function setupBackups() {
  const status = await w3pk.getBackupStatus()

  console.log('Security Score:', status.securityScore.score)
  console.log('Has passkey sync:', status.securityScore.hasPasskeyBackup)
  console.log('Has encrypted backup:', status.securityScore.hasEncryptedBackup)
  console.log('Has social recovery:', status.securityScore.hasSocialRecovery)

  // Warn if security score is low
  if (status.securityScore.score < 60) {
    showBackupWarning()
  }
}
```

### Three-Layer Backup Strategy

Encourage users to enable multiple backup methods:

#### 1. Passkey Auto-Sync (Automatic)

```typescript
// Already enabled by default via platform
// - iCloud Keychain (Apple devices)
// - Google Password Manager (Android/Chrome)
// - Microsoft Account (Windows/Edge)

const status = await w3pk.getBackupStatus()
if (status.securityScore.hasPasskeyBackup) {
  console.log('✅ Passkey synced to cloud')
}
```

#### 2. Encrypted Backups (Manual)

```typescript
import { isStrongPassword } from 'w3pk'

async function createEncryptedBackup() {
  // Get password from user
  const password = await promptUserForPassword()

  // Validate strength
  if (!isStrongPassword(password)) {
    throw new Error('Password too weak. Need 12+ chars with mixed case, numbers, symbols')
  }

  // Create QR backup
  const { qrCodeDataURL } = await w3pk.createQRBackup(password)
  displayQRForPrinting(qrCodeDataURL)
}
```

#### 3. Social Recovery (Best UX)

```typescript
async function setupSocialRecovery() {
  // Setup 3-of-5 guardians
  await w3pk.setupSocialRecovery(
    [
      { name: 'Alice', email: 'alice@example.com' },
      { name: 'Bob', email: 'bob@example.com' },
      { name: 'Charlie', phone: '+1234567890' },
      { name: 'Diana', email: 'diana@example.com' },
      { name: 'Eve', email: 'eve@example.com' }
    ],
    3 // threshold - need 3 out of 5 to recover
  )

  // Generate and send guardian invites
  const guardians = await w3pk.getGuardians()
  for (const guardian of guardians) {
    const invite = await w3pk.generateGuardianInvite(guardian.id)
    await sendInviteToGuardian(guardian, invite)
  }
}
```

### Backup Reminder Strategy

```typescript
// Check backup status regularly
async function checkBackupReminder() {
  const status = await w3pk.getBackupStatus()
  const daysSinceRegistration = calculateDaysSince(status.createdAt)

  // Remind users who haven't set up backup
  if (!status.securityScore.hasEncryptedBackup &&
      !status.securityScore.hasSocialRecovery) {

    if (daysSinceRegistration === 1) {
      showBackupReminder('urgent')
    } else if (daysSinceRegistration === 7) {
      showBackupReminder('critical')
    } else if (daysSinceRegistration % 30 === 0) {
      showBackupReminder('periodic')
    }
  }
}
```

### Recovery Flow

```typescript
async function recoverWallet() {
  // Let user choose recovery method
  const method = await showRecoveryOptions()

  if (method === 'encrypted-backup') {
    const file = await getBackupFile()
    const password = await getPasswordFromUser()
    await w3pk.restoreFromBackup(file, password)

  } else if (method === 'social-recovery') {
    const shares = await collectGuardianShares()
    const { mnemonic } = await w3pk.recoverFromGuardians(shares)
    console.log('✅ Wallet recovered!')

  } else if (method === 'qr-backup') {
    const qrData = await scanQRCode()
    const password = await getPasswordFromUser()
    await w3pk.restoreFromBackup(qrData, password)
  }
}
```

---

## Security Considerations

### Session Management

w3pk supports both **in-memory** (default) and **persistent** sessions:

```typescript
// ✅ In-memory sessions (default, cleared on page refresh)
const w3pk = createWeb3Passkey({
  sessionDuration: 1 // 1 hour (cleared on refresh)
})

// ✅ Persistent sessions ("Remember Me" functionality)
const w3pkPersistent = createWeb3Passkey({
  sessionDuration: 1,        // In-memory session duration
  persistentSession: {
    enabled: true,           // Enable persistent sessions
    duration: 168,           // 7 days (survives page refresh)
    requireReauth: true      // Prompt on page refresh (more secure)
  }
})

// ✅ Auto-restore (convenience mode)
const w3pkAutoRestore = createWeb3Passkey({
  persistentSession: {
    enabled: true,
    duration: 30 * 24,       // 30 days
    requireReauth: false     // Silent restore (no prompt)
  }
})

// For high-security apps, require auth for sensitive operations
async function sendHighValueTransaction(amount: number) {
  const requireAuth = amount > 1000 // Force auth for >$1000

  const signature = await w3pk.signMessage(
    `Transfer ${amount} USDC`,
    { requireAuth }
  )

  // Submit transaction...
}

// Or use STRICT mode to disable persistent sessions entirely
const strictWallet = await w3pk.deriveWallet('STRICT')
// STRICT mode ALWAYS requires fresh authentication (no persistent sessions)
```

**Persistent Session Security:**
- STANDARD mode: Persistent sessions ✅ allowed
- YOLO mode: Persistent sessions ✅ allowed
- STRICT mode: Persistent sessions ❌ NEVER allowed
- Sessions encrypted with WebAuthn-derived keys
- Requires valid credential to decrypt
- Time-limited expiration
- Origin-isolated via IndexedDB

### Build Verification

```typescript
// ✅ Verify package integrity on app initialization
import { verifyBuildHash } from 'w3pk'

const TRUSTED_HASH = 'bafybeig2xoiu2hfcjexz6cwtjcjf4u4vwxzcm66zhnqivhh6jvi7nx2qa4'

async function initializeApp() {
  const isValid = await verifyBuildHash(TRUSTED_HASH)

  if (!isValid) {
    throw new Error('w3pk package integrity check failed!')
  }

  // Continue with app initialization
}
```

### Origin Isolation

w3pk automatically provides origin isolation:

- Different domains derive different wallets
- `app.example.com` gets different addresses than `gaming.example.com`
- Prevents cross-origin wallet access

```typescript
// On app.example.com
const wallet1 = await w3pk.deriveWallet()
// address: 0xaaa...

// On gaming.example.com
const wallet2 = await w3pk.deriveWallet()
// address: 0xbbb... (different!)
```

### Never Expose Master Mnemonic

```typescript
// ❌ This will throw an error - master mnemonic is never exposed
try {
  await w3pk.exportMnemonic()
} catch (error) {
  console.error('Cannot export master mnemonic') // Expected
}

// ✅ Use derived wallets instead
const wallet = await w3pk.deriveWallet('GAMING') // Safe, tagged wallet
```

---

## Complete Integration Example

```typescript
import { createWeb3Passkey, isStrongPassword } from 'w3pk'

class WalletManager {
  private w3pk = createWeb3Passkey({
    sessionDuration: 2,
    stealthAddresses: {} // Optional stealth support
  })

  async initialize() {
    // Verify package integrity
    const TRUSTED_HASH = 'bafybeig2xoiu2hfcjexz6cwtjcjf4u4vwxzcm66zhnqivhh6jvi7nx2qa4'
    const isValid = await verifyBuildHash(TRUSTED_HASH)
    if (!isValid) throw new Error('Package integrity check failed')
  }

  async onboard(username: string) {
    // Check for existing wallet
    const hasExisting = await this.w3pk.hasExistingCredential()

    if (hasExisting) {
      await this.w3pk.login()
      return { isNewUser: false }
    }

    // Register new wallet
    const { address } = await this.w3pk.register({ username })

    // Immediate backup prompt
    await this.promptBackup()

    return { isNewUser: true, address }
  }

  async promptBackup() {
    const status = await this.w3pk.getBackupStatus()

    if (status.securityScore.score < 60) {
      // Show backup modal to user
      const choice = await this.showBackupOptions()

      if (choice === 'encrypted') {
        const password = await this.getStrongPassword()
        const blob = await this.w3pk.createZipBackup(password)
        this.downloadBackup(blob)
      } else if (choice === 'social') {
        await this.setupSocialRecovery()
      }
    }
  }

  async getWallet() {
    // ✅ Use STANDARD mode by default (no private key exposure)
    return await this.w3pk.deriveWallet()
  }

  async signTransaction(message: string, amount?: number) {
    // Force auth for high-value transactions
    const requireAuth = amount && amount > 1000

    // Sign with STANDARD mode by default
    const result = await this.w3pk.signMessage(message, { requireAuth })
    return result.signature
  }

  private async getStrongPassword(): Promise<string> {
    let password = await this.promptUserForPassword()
    while (!isStrongPassword(password)) {
      password = await this.promptUserForPassword(
        'Password too weak. Need 12+ chars with mixed case, numbers, symbols'
      )
    }
    return password
  }
}

// Usage
const wallet = new WalletManager()
await wallet.initialize()
await wallet.onboard('user@example.com')
```

---

## Checklist

Use this checklist to ensure proper integration:

- [ ] Check for existing credentials before registration using `hasExistingCredential()`
- [ ] Consider showing warning with `listExistingCredentials()` if allowing multiple wallets
- [ ] Use STANDARD mode by default (no private key exposure)
- [ ] Only use YOLO mode when you need private keys (and understand the implications)
- [ ] Use STRICT mode for high-security or compliance-focused applications
- [ ] Prompt users to set up backup immediately after registration
- [ ] Verify package integrity on app initialization
- [ ] Configure appropriate session duration for your use case
- [ ] Require fresh authentication for high-value operations
- [ ] Show backup reminders to users without sufficient backup coverage
- [ ] Test recovery flows (encrypted backup, social recovery)
- [ ] Review [Security Architecture](./SECURITY.md) documentation

---

## Further Reading

- [Quick Start Guide](./QUICK_START.md)
- [API Reference](./API_REFERENCE.md)
- [Security Architecture](./SECURITY.md)
- [Recovery & Backup System](./RECOVERY.md)
- [Build Verification](./BUILD_VERIFICATION.md)
