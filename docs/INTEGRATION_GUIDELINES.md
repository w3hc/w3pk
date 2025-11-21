# Integration Guidelines

This guide covers essential best practices for integrating w3pk into your application.

## Table of Contents

- [Wallet Derivation Strategy](#wallet-derivation-strategy)
- [Registration Flow](#registration-flow)
- [Backup & Recovery](#backup--recovery)
- [Security Considerations](#security-considerations)

---

## Wallet Derivation Strategy

### Default: Use MAIN-tagged Wallets

**Best Practice:** For most applications, use the default MAIN-tagged wallet derivation.

```typescript
// ✅ Recommended for most use cases
const wallet = await w3pk.deriveWallet()
// Returns: { address, index, origin, tag: 'MAIN' }
// No private key exposed
```

**Why MAIN tag?**
- **Security:** Private keys are never exposed to your application
- **User Control:** Users retain full custody of their wallet
- **Signing:** You can still sign messages and transactions via `w3pk.signMessage()`
- **Trust:** Users don't need to trust your application with key material

### Custom Tags: When You Need Private Keys

**Use custom tags ONLY when your application requires direct access to private keys.**

```typescript
// ⚠️ Use only when necessary (non-financial apps, games, etc.)
const gamingWallet = await w3pk.deriveWallet('GAMING')
// Returns: { address, privateKey, index, origin, tag: 'GAMING' }
```

**Valid Use Cases:**
- Gaming applications (low-value in-game assets)
- Social applications (non-financial operations)
- Throwaway wallets for testing/development
- Apps where users explicitly want your app to manage keys

**Important Security Implications:**

When you use custom tags, **you control the user's private key** for that specific derived wallet. This means:

1. **Custody Risk:** Your application has full access to the private key
2. **User Trust:** Users must trust your application not to misuse their keys
3. **Liability:** Your application is responsible for securing these keys
4. **Regulatory:** May have compliance implications depending on jurisdiction

```typescript
// Custom tags create different addresses
const main = await w3pk.deriveWallet()          // MAIN - no private key
const gaming = await w3pk.deriveWallet('GAMING') // Has private key
const social = await w3pk.deriveWallet('SOCIAL') // Has private key

console.log(main.address !== gaming.address)    // true
console.log(gaming.address !== social.address)  // true
```

**Decision Matrix:**

| Use Case | Recommended Approach |
|----------|---------------------|
| Financial transactions | MAIN tag (no private key) |
| DeFi applications | MAIN tag (no private key) |
| NFT purchases | MAIN tag (no private key) |
| Gaming (low value) | Custom tag acceptable |
| Social features | Custom tag acceptable |
| Testing/development | Custom tag acceptable |

---

## Registration Flow

### Check for Existing Wallet First

**Critical:** Before registering a new wallet, always check if one exists on the device.

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

**Example: Complete Onboarding UI**

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

async function promptBackupOptions() {
  // Show modal/screen with backup options
  const userChoice = await showBackupModal()

  if (userChoice === 'encrypted-backup') {
    const password = await getPasswordFromUser()
    const blob = await w3pk.createZipBackup(password)
    downloadBlob(blob, 'wallet-backup.zip')
  } else if (userChoice === 'qr-code') {
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

  // Create ZIP backup
  const blob = await w3pk.createZipBackup(password)
  downloadFile(blob, 'wallet-backup.zip')

  // OR create QR backup
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

```typescript
// ✅ Configure appropriate session duration
const w3pk = createWeb3Passkey({
  sessionDuration: 1 // Default: 1 hour
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
```

### Build Verification

```typescript
// ✅ Verify package integrity on app initialization
import { verifyBuildHash } from 'w3pk'

const TRUSTED_HASH = 'bafybeifysgwvsyog2akxjk4cjky2grqqyzfehamuwyk6zy56srgkc5jopi'

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
    const TRUSTED_HASH = 'bafybeifysgwvsyog2akxjk4cjky2grqqyzfehamuwyk6zy56srgkc5jopi'
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
    // ✅ Use MAIN tag by default (no private key exposure)
    return await this.w3pk.deriveWallet()
  }

  async signTransaction(message: string, amount?: number) {
    // Force auth for high-value transactions
    const requireAuth = amount && amount > 1000
    return await this.w3pk.signMessage(message, { requireAuth })
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

- [ ] Check for existing credentials before registration
- [ ] Use MAIN-tagged wallet by default (no private key exposure)
- [ ] Only use custom tags when you need private keys (and understand the implications)
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
