# W3PK Backup & Recovery System

> **Simple. Universal. Secure.**
> A unified backup file system for w3pk wallets with multiple recovery paths.

> ✅ **Status: Fully Implemented & Production-Ready**
> This system is complete with all tests passing, covering backup encryption, device sync, and social recovery.

## Overview

The W3PK backup system provides a simplified portable approach to wallet backups. A single backup file can be used for multiple purposes: restoration, registration, cross-device sync, and social recovery.

W3PK uses a **universal backup file format** (BackupFile v2) as the foundation for all recovery workflows. Think of it as a portable encrypted file that can be used for multiple purposes.

---

## 🔑 Key Concepts: Passkey vs. Mnemonic

Before diving into the recovery system, it's crucial to understand the difference between your **passkey** and your **mnemonic**:

### **Passkey (WebAuthn Credential)**
- Your biometric authentication method (Face ID, fingerprint, Windows Hello, etc.)
- **Syncs automatically** via platform services (iCloud Keychain, Google Password Manager)
- Used to **unlock and decrypt** your locally stored encrypted mnemonic
- Platform-specific (Apple ↔ Apple, Google ↔ Google, etc.)
- **Cannot** be exported or transferred to different ecosystems
- Think of it as: **"Your key to the safe"**

### **Mnemonic (Recovery Phrase)**
- Your actual wallet seed phrase (12 words following BIP39 standard)
- **Does NOT sync automatically** - stored locally in encrypted form
- **Must be manually backed up** using the methods described below
- Universal - works with any BIP39-compatible wallet (MetaMask, Ledger, etc.)
- Platform-agnostic - can be imported anywhere
- Think of it as: **"Your safe's combination"**

### **How They Work Together**
```
┌─────────────────────────────────────────────────────────┐
│  1. You authenticate with Passkey (Face ID/Touch ID)   │
│  2. Passkey decrypts your locally stored mnemonic       │
│  3. Mnemonic generates your wallet private keys         │
│  4. You can now sign transactions                       │
└─────────────────────────────────────────────────────────┘
```

### **Critical Understanding**

| Scenario | What Syncs | What Doesn't Sync |
|----------|------------|-------------------|
| New iPhone (same iCloud) | ✅ Passkey syncs | ⚠️ Mnemonic stays on old device |
| New Android (same Google account) | ✅ Passkey syncs | ⚠️ Mnemonic stays on old device |
| Switch from iPhone to Android | ❌ Passkey doesn't sync | ❌ Mnemonic doesn't sync |

**Why this matters:**
- If you lose your device but have passkey sync enabled, you can authenticate on a new device, BUT you still need the encrypted mnemonic from your old device to recover your wallet
- This is why **manual mnemonic backup** is essential for true recovery

---

## 🎯 Backup File Format

All workflows use the same universal format:

```typescript
interface BackupFile {
  createdAt: string;              // ISO 8601 timestamp
  ethereumAddress: string;        // m/44'/60'/0'/0/0 (index #0)
  encryptedMnemonic: string;      // AES-256-GCM encrypted
  encryptionMethod: 'passkey' | 'password' | 'hybrid';
  addressChecksum: string;        // For verification

  // Optional fields based on encryption method
  credentialId?: string;
  publicKeyFingerprint?: string;
  passwordEncryption?: {
    salt: string;
    iv: string;
    iterations: number;
  };
}
```

### Example Backup File

```json
{
  "createdAt": "2025-11-25T17:02:43.393Z",
  "ethereumAddress": "0x84Aa4D5c00D93CE377EfDc9b20b68C29C67E2c76",
  "encryptedMnemonic": "+0ew4mo3jbsHGIJVb17eXsftc5Sqi710SW+h8EZ67I4...",
  "encryptionMethod": "password",
  "passwordEncryption": {
    "salt": "KUA/RBWL8N1Y648K6IkHIaaps8vyR1H3BxZqQd5agyM=",
    "iv": "4XBZgFB0Lek9PCtj",
    "iterations": 310000
  },
  "addressChecksum": "OFVy+n2ehtgYy1Rq"
}
```

---

## 🔐 Encryption Methods

### Password-based
- **Use case**: Disaster recovery, social recovery, new device setup
- **Security**: PBKDF2 (310,000 iterations) + AES-256-GCM
- **Pros**: Platform-agnostic, works everywhere
- **Cons**: Must remember password

### Passkey-based
- **Use case**: Cross-device sync (when passkey is synced)
- **Security**: WebAuthn credential → PBKDF2 (210,000 iterations) → AES-256-GCM
- **Pros**: No password needed, uses synced passkey
- **Cons**: Requires passkey on target device

### Hybrid
- **Use case**: Maximum security scenarios
- **Security**: Double encryption (passkey → password)
- **Pros**: Two-factor protection
- **Cons**: Requires both passkey AND password

---

## 📚 Core Workflows

### **1. Backup/Restore (Disaster Recovery)**

**Purpose**: Create portable encrypted backup for disaster recovery

**Create Backup:**
```typescript
const sdk = createWeb3Passkey();
await sdk.login();

// Password-protected backup (recommended)
const { blob, filename } = await sdk.createBackupFile('password', 'MySecurePassword123!');
// Downloads: w3pk-backup-0x1234abcd-2025-11-25.json
```

**Restore on New Device (Two Options):**

**Option 1: Register new passkey (recommended)**
```typescript
const sdk = createWeb3Passkey();

// Register new passkey with wallet from backup
await sdk.registerWithBackupFile(backupFile, 'MySecurePassword123!', 'myusername');
// Now logged in with new passkey, credentials stored locally ✅
```

**Option 2: Restore to existing passkey**
```typescript
const sdk = createWeb3Passkey();
await sdk.login(); // Login with existing passkey first

// Restore and decrypt the backup
const { mnemonic } = await sdk.restoreFromBackupFile(backupFile, 'MySecurePassword123!');

// Import to current logged-in user
await sdk.importMnemonic(mnemonic);
// Credentials now stored locally under existing passkey ✅
```

**Encryption**: Password → PBKDF2 (310k iterations) → AES-256-GCM

**Use Cases:**
1. **First backup after wallet creation** - Essential safety net
2. **Switching devices/platforms** - Works everywhere
3. **Long-term storage** - Store in password manager or encrypted cloud
4. **Emergency recovery** - When all else fails

**Pros:**
- ✅ Works on any device/platform
- ✅ No platform dependencies
- ✅ Can store safely in cloud (already encrypted)
- ✅ BIP39 compatible - works with other wallets

**Cons:**
- ⚠️ Must remember password (can't be reset)
- ⚠️ Manual creation required
- ⚠️ File can be lost if not stored properly

**Recovery scenarios:**
| Scenario | Can Recover? | How |
|----------|--------------|-----|
| Lost all devices | ✅ Yes | Import backup file + password |
| Forgot password | ❌ No | Cannot decrypt - need other method |
| Backup file lost | ❌ No | Need passkey sync or social recovery |
| Switch to different wallet app | ✅ Yes | BIP39 mnemonic works everywhere |

---

### **2. Cross-Device Sync**

**Purpose**: Sync wallet to devices where passkey is already synced

There are two approaches depending on whether you have an existing wallet session:

#### Option A: Sync with passkey + backup file (recommended for new devices)

Use this when you're on a new device that already has your passkey synced (e.g., via iCloud/Google Password Manager) but doesn't have the wallet data yet.

```typescript
const sdk = createWeb3Passkey();

// Provide your backup file (any encryption method: password, passkey, or hybrid)
const backupData = '...'; // JSON string or Blob from your backup file
const { mnemonic, ethereumAddress } = await sdk.syncWalletWithPasskey(backupData);
// 1. SDK prompts you to select your synced passkey
// 2. Decrypts backup using the selected passkey
// 3. Stores wallet data locally and starts a session ✅
```

For password or hybrid backups, pass the password as a second argument:

```typescript
const { mnemonic, ethereumAddress } = await sdk.syncWalletWithPasskey(backupData, 'MyPassword123!');
```

**Requirement**: Passkey must be synced to this device (iCloud/Google Password Manager)

**Supports**: All backup encryption methods (`password`, `passkey`, `hybrid`)

#### Option B: Export/import sync file (between two active devices)

Use this when you have the wallet active on Device A and want to transfer to Device B.

**Export from Device A:**
```typescript
const sdk = createWeb3Passkey();
await sdk.login(); // On device with wallet

const { blob, filename, qrCode } = await sdk.exportForSync();
// Transfer via QR code, AirDrop, email, etc.
```

**Import on Device B:**
```typescript
const sdk = createWeb3Passkey();
await sdk.login(); // Passkey must be synced to this device

await sdk.importFromSync(syncData);
// Wallet now available on Device B, credentials stored locally ✅
```

**Encryption**: WebAuthn-derived key → AES-256-GCM

**Use Case**: Wallet on desktop, want it on mobile (same passkey ecosystem)

**Requirement**: Passkey must be synced via iCloud/Google Password Manager

**Pros:**
- ✅ No password needed (passkey-encrypted backups)
- ✅ Leverages existing passkey sync
- ✅ Fast and convenient
- ✅ `syncWalletWithPasskey()` works without an existing session

**Cons:**
- ⚠️ Requires passkey on target device
- ⚠️ Platform-specific (iCloud or Google)

---

### **3. Social Recovery**

**Purpose**: Distribute encrypted wallet data among trusted guardians using Shamir Secret Sharing (M-of-N)

**Setup (3-of-5 example):**
```typescript
const sdk = createWeb3Passkey();
await sdk.login();

// Create encrypted backup and split among guardians
const { guardianShares } = await sdk.setupSocialRecovery(
  [
    { name: 'Alice', email: 'alice@example.com' },
    { name: 'Bob', email: 'bob@example.com' },
    { name: 'Charlie', email: 'charlie@example.com' },
    { name: 'David', email: 'david@example.com' },
    { name: 'Eve', email: 'eve@example.com' },
  ],
  3, // threshold: need 3 shares to recover
  'OptionalPassword' // encrypts backup before splitting
);

// Generate invitation for each guardian
for (const share of guardianShares) {
  const invitation = await sdk.generateGuardianInvite(share);
  // Send invitation.downloadBlob or invitation.qrCodeDataURL to guardian
}
```

**Recover Wallet (Two Options):**

**Option 1: Recover and register new passkey (recommended for lost devices)**
```typescript
const sdk = createWeb3Passkey();

// Step 1: Collect shares from 3+ guardians
const shares = [aliceShare, bobShare, charlieShare];

// Step 2: Combine shares and decrypt to get mnemonic and address
const { mnemonic, ethereumAddress } = await sdk.recoverFromGuardians(
  shares,
  'OptionalPassword' // password used during setupSocialRecovery (if any)
);

// Step 3: Create a new password-protected backup from recovered mnemonic
const { BackupFileManager } = await import('w3pk/backup/backup-file');
const manager = new BackupFileManager();
const { backupFile } = await manager.createPasswordBackup(
  mnemonic,
  ethereumAddress,
  'NewPassword123!' // Choose a new password
);

// Step 4: Register new passkey using the backup
const backupData = JSON.stringify(backupFile);
await sdk.registerWithBackupFile(backupData, 'NewPassword123!', 'username');
// Now logged in with new passkey, credentials stored locally ✅
```

**Option 2: Recover and import to existing passkey**
```typescript
const sdk = createWeb3Passkey();

// Step 1: Login with existing WebAuthn credential
await sdk.login();

// Step 2: Collect shares and recover mnemonic
const shares = [aliceShare, bobShare, charlieShare];
const { mnemonic } = await sdk.recoverFromGuardians(
  shares,
  'OptionalPassword'
);

// Step 3: Import mnemonic to current logged-in user
await sdk.importMnemonic(mnemonic);
// Credentials stored locally under current passkey ✅
```

**Encryption**:
1. Create BackupFile (password/passkey encrypted)
2. Serialize to JSON
3. Split using Shamir Secret Sharing (M-of-N)
4. Each guardian gets one share

**Use Case**: Forgot password, lost all devices, ultimate safety net

**Security**: No single guardian can recover wallet alone

**Pros:**
- ✅ No single point of failure
- ✅ Survives your own forgetfulness
- ✅ Survives any 2 guardians disappearing
- ✅ Highest security and redundancy

**Cons:**
- ⚠️ Requires trusted friends/family
- ⚠️ Setup complexity
- ⚠️ Recovery takes time (24-48 hours)
- ⚠️ Coordination required

**Recovery scenarios:**
| Scenario | Can Recover? | How |
|----------|--------------|-----|
| Forgot password + lost devices | ✅ Yes | Contact 3 guardians → combine shares |
| Lost backup + lost passkey | ✅ Yes | Contact 3 guardians |
| 2 guardians unavailable | ✅ Yes | Still have 3 others |
| All guardians lost shares | ❌ No | Need another recovery layer |

---

## 📊 Workflow Comparison

| Workflow | Encryption | Use Case | Requirements |
|----------|------------|----------|--------------|
| **Backup/Restore** | Password | Lost all devices, platform switch | Password only |
| **Sync (passkey + backup)** | Any | New device with synced passkey, no active session | Passkey synced + backup file |
| **Sync (export/import)** | Passkey | Transfer from active device to another | Active session + passkey synced to target |
| **Social Recovery** | Password* | Forgot everything, ultimate backup | 3+ guardians available |

*Social recovery can use passkey encryption, but password is recommended for guardian scenarios.

---

## 🔒 Security Features

1. **Never Exposes Mnemonic**: Mnemonic is always encrypted in backup files
2. **Address Checksum**: Verification to detect corruption or wrong password
3. **Version Control**: Future-proof format versioning
4. **Shamir Secret Sharing**: No single guardian can recover wallet alone
5. **Multiple Encryption Options**: Choose security/convenience tradeoff

### **Social Recovery Cryptography**

```typescript
Shamir Secret Sharing Algorithm:

Example: 3-of-5 scheme
- Split secret S into 5 shares: s1, s2, s3, s4, s5
- Any 3 shares can reconstruct S
- Any 2 shares reveal ZERO information about S
- Each guardian only has an encrypted piece

Mathematical basis:
- Polynomial interpolation over finite field
- Degree = threshold - 1 (e.g., degree-2 polynomial for 3-of-5)
- Points on polynomial = shares
- Reconstruct polynomial with 3 points → get secret

Share encryption:
Each share is encrypted with guardian's public key:
- Guardian generates key pair (on their device)
- Share encrypted with guardian's public key
- Only guardian can decrypt their share
- Prevents share theft from coordinator
```

**Trust model:**
```
Coordinator (You):
- Cannot recover from less than threshold shares
- Can revoke/replace guardians
- Can update threshold

Guardians:
- Cannot recover alone
- Cannot collude unless threshold met
- Can verify share validity
- Can export/backup their share

Attacker:
- Cannot recover with < threshold shares
- Cannot brute-force (mathematically secure)
- Must compromise guardians directly
```

---

## 🛠️ API Reference

### Create Backup

```typescript
// Password-protected backup
const { blob, filename } = await w3pk.createBackupFile('password', password);

// Passkey-encrypted backup
const { blob, filename } = await w3pk.createBackupFile('passkey');

// Hybrid backup (both password and passkey)
const { blob, filename } = await w3pk.createBackupFile('hybrid', password);
```

### Restore from Backup

```typescript
// Option 1: Register new passkey (creates and stores credentials)
await w3pk.registerWithBackupFile(backupData, password, username);

// Option 2: Import to existing passkey (stores credentials under current user)
await w3pk.login();
const { mnemonic } = await w3pk.restoreFromBackupFile(backupData, password);
await w3pk.importMnemonic(mnemonic);
```

### Cross-Device Sync

```typescript
// Sync to new device using existing passkey + backup file (no prior session needed)
const { mnemonic, ethereumAddress } = await w3pk.syncWalletWithPasskey(backupData);
// or with password for password/hybrid backups:
const result = await w3pk.syncWalletWithPasskey(backupData, 'MyPassword123!');

// Export for sync (Device A - requires active session)
const { blob, qrCode } = await w3pk.exportForSync();

// Import on another device (Device B - stores credentials locally)
await w3pk.login(); // Must have passkey synced
await w3pk.importFromSync(backupData);
```

### Social Recovery

```typescript
// Setup
const { guardianShares } = await w3pk.setupSocialRecovery(guardians, threshold, password);

// Generate invitations
const invitation = await w3pk.generateGuardianInvite(guardianShare);

// Recover (returns mnemonic - then register or import)
const { mnemonic, ethereumAddress } = await w3pk.recoverFromGuardians(shares, password);

// Option 1: Register new passkey (stores credentials)
const { BackupFileManager } = await import('w3pk/backup/backup-file');
const manager = new BackupFileManager();
const { backupFile } = await manager.createPasswordBackup(mnemonic, ethereumAddress, 'newpass');
await w3pk.registerWithBackupFile(JSON.stringify(backupFile), 'newpass', 'username');

// Option 2: Import to existing passkey (stores credentials)
await w3pk.login();
await w3pk.importMnemonic(mnemonic);
```

---

## 📝 Best Practices

### Backup Creation
1. **Always create a password backup** immediately after wallet creation
2. **Use strong passwords** (12+ characters, mixed case, numbers, symbols)
3. **Test recovery** on another device before relying on it
4. **Store backups securely**:
   - Password manager (1Password, Bitwarden) ✅ Recommended
   - Encrypted cloud storage (Google Drive, Dropbox) ✅
   - Physical safe ✅
   - USB drive in safe ✅
5. **Never expose mnemonic** - always use encrypted backups

### Social Recovery Setup
1. **Choose appropriate guardians**:
   - Trustworthy people ✅
   - Tech-savvy (can handle QR codes) ✅
   - Geographically distributed ✅
   - Long-term relationships ✅
   - Available when needed ✅
2. **Set appropriate threshold**:
   - 2-of-3 minimum
   - 3-of-5 recommended
   - Higher for more security
3. **Guardian verification**: Ensure guardians confirm receipt of shares

### Password Requirements

For encrypted backups, enforce strong passwords:

```typescript
import { isStrongPassword } from 'w3pk'

// Validate password before creating backup
const password = userInput
if (!isStrongPassword(password)) {
  throw new Error('Password does not meet security requirements')
}

const blob = await w3pk.createZipBackup(password)
```

**Password requirements:**
- Minimum 12 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 number
- At least 1 special character
- Not a common password (dictionary check)

**Strength indicator:**
- 0-25%   : ❌ Weak (rejected)
- 26-50%  : ⚠️  Fair (warning shown)
- 51-75%  : 🟡 Good (accepted)
- 76-100% : ✅ Strong (recommended)

---

## 📖 Technical Implementation

### Files Created
- [src/backup/backup-file.ts](src/backup/backup-file.ts) - Core backup file manager
- [src/sync/backup-sync.ts](src/sync/backup-sync.ts) - Cross-device sync
- [src/recovery/backup-based-recovery.ts](src/recovery/backup-based-recovery.ts) - Social recovery
- [test/backup-file.test.ts](test/backup-file.test.ts) - Test suite

### Key Classes
- `BackupFileManager` - Create and restore backup files
- `DeviceSyncManager` - Handle cross-device sync
- `SocialRecovery` - Split/combine guardian shares

### Core Architecture

```
src/backup/
├── backup-file.ts              # Main backup orchestration
├── types.ts                    # TypeScript interfaces
├── encryption.ts               # PBKDF2 + AES-256-GCM utilities
└── storage.ts                  # IndexedDB for metadata

src/sync/
├── backup-sync.ts              # DeviceSyncManager class
└── types.ts                    # Sync-related interfaces

src/recovery/
├── backup-based-recovery.ts    # SocialRecovery class
├── shamir.ts                   # Shamir Secret Sharing
└── types.ts                    # Recovery-related interfaces

src/core/
└── sdk.ts                      # Main SDK with all workflow methods
```

---

## 🧪 Testing

Run the test suite:
```bash
# Backup file tests
pnpm tsx test/backup-file.test.ts

# All backup tests
pnpm test:backup
```

All tests pass:
- ✅ Password backup creation and restoration
- ✅ Social recovery with guardian shares (3-of-5)
- ✅ Guardian invitation generation with QR codes
- ✅ Downloadable backup file creation
- ✅ Address checksum verification

---

## 📚 User Documentation

### Quick Start: Backup Your Wallet

```markdown
1. Create Password-Protected Backup (Recommended)
   - Click "Backup Wallet" in settings
   - Choose "Password Backup"
   - Enter strong password (you MUST remember this!)
   - Download w3pk-backup-[address]-[date].json
   - Store in password manager or encrypted cloud

2. Optional: Set Up Social Recovery
   - Click "Social Recovery" in settings
   - Add 5 trusted friends/family
   - Choose threshold (3-of-5 recommended)
   - Send guardian invitations
   - Wait for confirmations

3. Verify Your Backup
   - Try restoring in a different browser
   - Check that address matches
   - Delete test import (keep original)
```

---

## 🚨 Recovery Guide

### How to Recover Your Wallet

#### **Method 1: Using Password-Protected Backup**

```markdown
1. Download your backup file (w3pk-backup-[address]-[date].json)
2. Go to w3pk recovery page
3. Click "Register with Backup"
4. Select your backup file
5. Enter your password
6. System decrypts and verifies
7. Wallet restored ✅

Verification:
- Address shown: 0x1234...5678
- Match with your known address? → Success!
```

#### **Method 2: Using Passkey Sync**

**Option A: Passkey + backup file (new device, no prior session)**

```markdown
1. Get new device (same ecosystem)
2. Sign into cloud account (iCloud/Google) - passkey syncs automatically
3. Go to w3pk website
4. Provide your backup file (any encryption method)
5. Call syncWalletWithPasskey(backupData) or use the app's "Sync Wallet" flow
6. Authenticate with biometric when prompted
7. Wallet decrypted and stored locally ✅

Platform-specific:
- iOS → iCloud Keychain must be enabled
- Android → Google Password Manager
- Windows → Limited sync support
```

**Option B: Export/import sync file (transfer from active device)**

```markdown
1. On Device A: export sync file via exportForSync()
2. Transfer file to Device B (AirDrop, QR code, etc.)
3. On Device B: sign in with synced passkey, then importFromSync(syncData)
4. Wallet decrypted ✅
```

#### **Method 3: Using Social Recovery**

```markdown
1. Go to w3pk recovery page
2. Click "Social Recovery"
3. Contact your guardians (need 3 of 5)
4. Each guardian provides their share:
   - Scan QR code, OR
   - Enter share code manually
5. After 3 shares collected:
   - System reconstructs backup file
   - Enter password if used during setup
   - System extracts mnemonic
6. Choose recovery path:
   - "Register New Passkey" → Creates new WebAuthn credential, stores locally ✅
   - "Login & Import" → Login with existing passkey, import mnemonic ✅

Timeline: ~24-48 hours (depends on guardian availability)
Note: Either path stores credentials locally after recovery
```

#### **Method 4: Manual Mnemonic Import**

```markdown
1. Find your 12-word recovery phrase
   - Check password manager
   - Check physical backup
   - Check encrypted file
2. Go to w3pk recovery page
3. Click "Import Mnemonic"
4. Enter 12 words in order
5. System validates and imports
6. Wallet restored ✅

Compatible with:
- MetaMask
- Ledger
- Trezor
- Any BIP39 wallet
```

---

## ❓ FAQ

**Q: Does my passkey sync mean my wallet is backed up?**
A: **No!** This is a critical distinction. Your passkey (Face ID/Touch ID credential) syncs via iCloud/Google, but your encrypted wallet data does NOT automatically sync. You MUST create a manual backup to ensure full wallet recovery. Passkey sync only helps with authentication, not wallet recovery.

**Q: If I get a new iPhone and sign into iCloud, will my wallet be there?**
A: Only if you also transferred your wallet data or created a backup. The passkey will sync automatically, allowing you to authenticate, but the encrypted wallet data needs to be restored separately from a backup. Use `syncWalletWithPasskey(backupData)` to combine your synced passkey with a backup file in a single step.

**Q: What's the difference between `syncWalletWithPasskey()` and `importFromSync()`?**
A: `syncWalletWithPasskey()` is for new devices with no active session — it prompts for your synced passkey and accepts any backup file (password, passkey, or hybrid encrypted). `importFromSync()` requires you to already be logged in and uses a passkey-encrypted sync export from another device.

**Q: Can I use multiple backup methods?**
A: Yes! We recommend using at least 2 methods for redundancy.

**Q: Is my encrypted backup safe to store in Google Drive?**
A: Yes, the backup is encrypted with AES-256-GCM and cannot be decrypted without your password.

**Q: What if I forget my backup password?**
A: You'll need to use another recovery method (passkey sync or social recovery). Password cannot be reset.

**Q: How secure is social recovery?**
A: Mathematically secure with Shamir's Secret Sharing. Any 2 guardians cannot recover (need 3 of 5).

**Q: Can guardians steal my wallet?**
A: No, each guardian only has an encrypted piece. They need 3 pieces minimum, and even then, the backup may be password-protected.

**Q: What happens if a guardian loses their share?**
A: No problem! You only need 3 out of 5. As long as 3 guardians have their shares, you can recover.

**Q: Can I change guardians later?**
A: Yes, you can add/remove/replace guardians anytime. You'll need to redistribute new shares.

**Q: Does passkey sync work across Apple and Android?**
A: No, passkey sync is ecosystem-specific. Use password backup or social recovery for cross-platform.

**Q: How often should I update my backup?**
A: Your mnemonic never changes! One backup is enough. Only update if you change your mnemonic.

**Q: Is this better than writing down 12 words on paper?**
A: Paper backup is good! Our system adds encryption and multiple options for convenience and security.

---

## 🛡️ Security Score Tracking

W3PK automatically tracks your wallet's security score based on the backup and recovery methods you've enabled. The score is calculated and updated automatically whenever you:

- Create a backup file
- Restore from a backup
- Set up social recovery
- Verify guardians
- Sync across devices

### Score Components (Max 100 points)

| Component | Points | Description |
|-----------|--------|-------------|
| **Passkey Active** | 20 pts | You have a passkey set up |
| **Passkey Multi-Device** | 10 pts | Your passkey is synced to 2+ devices |
| **Encrypted Backup** | 20 pts | You have at least one encrypted backup |
| **Phrase Verified** | 10-20 pts | You've successfully verified your backup (10 pts base + up to 10 pts for multiple verifications) |
| **Social Recovery** | 20-30 pts | You've set up social recovery (20 pts base + 10 pts bonus if enough guardians are verified) |

### Security Levels

- **0-20 pts: Vulnerable** - Minimal protection
- **21-50 pts: Protected** - Basic security in place
- **51-80 pts: Secured** - Strong multi-layered protection
- **81+ pts: Fort Knox** - Maximum security achieved

### How Verification Works

Your backup is automatically marked as "verified" when you successfully:
- Restore from a backup file using `restoreFromBackupFile()`
- Register a new passkey from backup using `registerWithBackupFile()`
- Recover from guardian shares using `recoverFromGuardians()`
- Import from device sync using `importFromSync()`

Verification proves that your backup actually works, increasing your security score.

### Checking Your Score

```typescript
const sdk = new W3PK();
const status = await sdk.getBackupStatus();

console.log(status.securityScore);
// {
//   total: 70,
//   level: "secured",
//   breakdown: {
//     passkeyActive: 20,
//     passkeyMultiDevice: 10,
//     phraseVerified: 10,
//     encryptedBackup: 20,
//     socialRecovery: 20
//   },
//   nextMilestone: "Enable all methods to reach 'fort-knox' (100 pts)"
// }
```

### Score Updates

The security score updates automatically in the following scenarios:

1. **After Backup Creation**: Creating a backup file adds 20 points for encrypted backup
2. **After Restore**: Successfully restoring marks your backup as verified (+10-20 pts)
3. **After Social Recovery Setup**: Setting up guardians adds 20 points
4. **After Guardian Verification**: Verifying enough guardians adds +10 bonus points
5. **After Device Sync**: Importing from sync marks backup as verified

The score is recalculated on-demand when you call `getBackupStatus()`, ensuring it always reflects your current security posture.

---

## 📦 Dependencies

```json
{
  "dependencies": {
    "secrets.js-grempe": "^2.0.0",    // Shamir Secret Sharing
    "qrcode": "^1.5.3"                 // QR code generation
  }
}
```

---

## 📖 References

- [BIP39 Mnemonic Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-4/)

---

## 📝 Migration from Old Format

The old backup format (version 1) is no longer supported. To migrate:

1. Restore using old system
2. Create new backup using `createBackupFile()`
3. Update all stored backups and guardian shares

---

## 📝 License

This recovery system architecture is part of w3pk and follows the same license.
