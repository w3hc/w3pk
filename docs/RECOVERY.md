# W3PK Backup & Recovery System

> **Simple. Universal. Secure.**
> A unified backup file system for w3pk wallets with multiple recovery paths.

> ✅ **Status: Fully Implemented & Production-Ready**
> This system is complete with all tests passing, covering backup encryption, device sync, and social recovery.

## Overview

The W3PK backup system provides a simplified portable approach to wallet backups. A single backup file can be used for multiple purposes: restoration, registration, cross-device sync, and social recovery.

W3PK uses a **universal backup file format** (BackupFile v3) as the foundation for all recovery workflows. Think of it as a portable encrypted file that can be used for multiple purposes.

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

## 🚦 Backup Status

Browser storage can be wiped (eviction, Safari's 7-day cap, clearing site data). Without a backup, the wallet is then lost for good, so ask for one right after registration and warn while none exists.

```typescript
const { hasBackup } = await sdk.register({ username: 'alice' });

if (!hasBackup) {
  // "Back up now": download a backup file...
  const { blob, filename } = await sdk.createBackupFile(password);
  // ...or show the recovery phrase, then record the user's confirmation
  await sdk.confirmRecoveryPhraseBackup();
}

const status = await sdk.getBackupStatus();
status.hasBackup;       // true once a backup that restores without a passkey exists
status.recommendedMode; // 'password', then 'prf', then undefined
status.lastBackupAt;    // ISO 8601 time of the latest backup
status.methods;         // e.g. ['file', 'phrase', 'prf']
```

A lost device without a synced passkey can only be recovered from a backup that doesn't need the passkey: a password file, a QR code, the recovery phrase, or social recovery (which splits a password file). `hasBackup` counts only those. A `prf` file from `exportForSync()` is recorded (method `prf`) but doesn't count, since it needs the passkey.

`recommendedMode` is the next backup to make:
- `password` while no backup restores without a passkey: it's the backup that must exist
- `prf` once one does, for convenient sync to devices where the passkey synced
- `undefined` once both exist

While `hasBackup` is `false`, the security score is capped at 20 and its level is `vulnerable`. A password-only backup isn't penalized. Backups are recorded per wallet, in localStorage on this device.

---

## 🎯 Backup File Format (v3)

All workflows use the same universal format:

```typescript
interface BackupFile {
  version: 3;
  createdAt: string;              // ISO 8601 timestamp
  encryptedMnemonic: string;      // base64(iv || AES-256-GCM ciphertext)
  encryptionMethod: 'password' | 'prf';

  // Optional fields based on encryption method
  passwordEncryption?: {          // password
    kdf: 'argon2id';
    salt: string;                 // base64, 16 random bytes
    memoryKiB: number;            // 65536 (19456 before v0.11.1)
    passes: number;               // 3 (2 before v0.11.1)
    parallelism: number;          // 4 (1 before v0.11.1)
  };
  credential?: { id: string; publicKey: string }; // passkey that owns the wallet
  prfSalt?: string;               // prf
  username?: string;              // prf
}
```

The file holds no address, in clear or hashed: it doesn't say whose wallet it is. Restores derive the address from the decrypted mnemonic, and AES-GCM rejects a wrong key or an altered ciphertext.

### Example Backup File

```json
{
  "version": 3,
  "createdAt": "2026-11-01T17:02:43.393Z",
  "encryptedMnemonic": "4XBZgFB0Lek9PCtj+0ew4mo3jbsHGIJVb17eXsftc5Sqi710SW+h8EZ67I4...",
  "encryptionMethod": "password",
  "passwordEncryption": {
    "kdf": "argon2id",
    "salt": "KUA/RBWL8N1Y648K6IkHIQ==",
    "memoryKiB": 65536,
    "passes": 3,
    "parallelism": 4
  },
  "credential": { "id": "…", "publicKey": "…" }
}
```

### v2 files

w3pk restores v3 files only, with no compatibility layer. A v2 file (no `version` field) throws `UnsupportedBackupVersionError` (`code: 'BACKUP_VERSION_UNSUPPORTED'`). To recover a v2 password backup, open the [v0.10.6 offline tool](https://github.com/w3hc/w3pk/blob/v0.10.6/standalone/extract-mnemonic.html), extract the mnemonic, import it, then create a new backup. A v2 `prf` file can't be converted: export a new one with `exportForSync()` on a device where the wallet is. Guardian shares made before v3 rebuild a v2 file: the error then carries it as `backupFileJson`, for the v0.10.6 tool.

---

## 🔐 Encryption Methods

### Password-based (the backup that must exist)
- **Use case**: Disaster recovery, social recovery, new device setup
- **Security**: Argon2id (RFC 9106; 64 MiB, 3 passes, 4 lanes; random 16-byte salt) + AES-256-GCM. The password is NFC-normalized.
- **Password**: 15 to 256 characters, counted in Unicode code points after NFC normalization, with no composition rules (spaces and any Unicode accepted), not one of the 1,000 most common passwords of that length, and not a single repeated character (the rules of `isStrongPassword()`, after [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) §3.1.1.2). A refused one throws `WeakPasswordError`, whose `feedback` gives each reason; social recovery and the `exportForSync(password)` fallback apply the same rules.
- **Pros**: Platform-agnostic, restores without a passkey, memory-hard against GPU guessing
- **Cons**: Must remember password

The Argon2id parameters are RFC 9106's second recommendation. They take about 1 to 2 s in pure JavaScript (`@noble/hashes`), so the offline tool runs them too. Restores read the parameters from the file, up to 64 MiB, 3 passes and 4 lanes, so a crafted file can't freeze the page, and backups made before v0.11.1 (19 MiB, 2 passes, 1 lane) still restore.

### PRF-based (convenient sync)
- **Use case**: Cross-device sync (when passkey is synced), from `exportForSync()`
- **Security**: WebAuthn PRF output → HKDF-SHA256 → AES-256-GCM; decrypting takes a fresh assertion with the passkey
- **Pros**: No password needed, uses synced passkey
- **Cons**: Requires the passkey and an authenticator with PRF support; doesn't help when the passkey is lost

### Removed: passkey and hybrid
`passkey` and `hybrid` backups (before 0.11.0) derived their key from the credential ID and public key, with no WebAuthn ceremony: a `passkey` file decrypted from public data, and a `hybrid` file was only as strong as its password. Restoring one throws `RemovedBackupMethodError` (`code: 'BACKUP_METHOD_REMOVED'`). Log in where the wallet is and create a new `password` or `prf` backup.

---

## 📚 Core Workflows

### **1. Backup/Restore (Disaster Recovery)**

**Purpose**: Create portable encrypted backup for disaster recovery

**Create Backup:**
```typescript
const sdk = createWeb3Passkey();
await sdk.login();

// Password-protected backup (recommended)
const { blob, filename } = await sdk.createBackupFile('MyS3cure!Backup@2042');
// Downloads: w3pk-backup-2026-11-01.json
```

**Restore on New Device (Two Options):**

**Option 1: Register new passkey (recommended)**
```typescript
const sdk = createWeb3Passkey();

// Register new passkey with wallet from backup
await sdk.registerWithBackupFile(backupFile, 'MyS3cure!Backup@2042', 'myusername');
// Now logged in with new passkey, credentials stored locally ✅
```

**Option 2: Restore to existing passkey**
```typescript
const sdk = createWeb3Passkey();
await sdk.login(); // Login with existing passkey first

// Restore and decrypt the backup. A backup of another wallet than the
// logged-in one throws AddressChangeError unless the user confirmed the
// replacement and the app passes { allowAddressChange: true }
await sdk.restoreFromBackupFile(backupFile, 'MyS3cure!Backup@2042');
// The wallet is now stored under the logged-in passkey ✅
```

**Encryption**: Password → Argon2id (64 MiB, 3 passes) → AES-256-GCM

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

There are two approaches: a PRF sync file needs no password, a password backup works everywhere.

#### Option A: PRF sync file (no password)

Use this when the wallet is active on Device A and the passkey synced to Device B (iCloud Keychain, Google Password Manager). Device B can be a fresh device with no data for the passkey.

**Export from Device A:**
```typescript
const sdk = createWeb3Passkey();
await sdk.login(); // On device with wallet

const { blob, filename, qrCode } = await sdk.exportForSync();
// One passkey prompt. Transfer via QR code, AirDrop, email, etc.
```

**Import on Device B:**
```typescript
const sdk = createWeb3Passkey();

await sdk.importFromSync(syncData); // or sdk.syncWalletWithPasskey(syncData)
// 1. One passkey prompt, restricted to the file's passkey
// 2. Decrypts the file (the address comes from the decrypted mnemonic)
// 3. Saves the passkey's metadata on this device if it's missing
// 4. Stores wallet data locally, starts a session and fires onAuthStateChanged(true, user) ✅
```

No `login()` first: on a device without the wallet, `login()` throws `SyncRequiredError` or `WalletMissingError`.

If this device already stores another wallet for the passkey, the file would replace it: `importFromSync()` and `syncWalletWithPasskey()` throw `AddressChangeError` after the prompt, with nothing stored changed, unless the user confirmed the replacement and the app passes `{ allowAddressChange: true }`.

**How it works**: the file (`encryptionMethod: 'prf'`) is encrypted with a key derived from the passkey's [WebAuthn PRF](https://w3c.github.io/webauthn/#prf-extension) output: HKDF-SHA256 over the PRF output at `SHA-256("w3pk-prf-sync-v1" || prfSalt)`, with a random `prfSalt` per file, then AES-256-GCM. The PRF secret syncs with the passkey but never leaves the authenticator, and the authenticator releases the output only on a user-verified assertion. So the file or its QR code alone decrypts nothing: it also takes the synced passkey and a biometric. An altered ciphertext or `prfSalt` is rejected. `restoreFromBackupFile(syncData)` restores a PRF file the same way.

The file also names its passkey (`credential: { id, publicKey }`) and carries the username. The public key is not a secret and doesn't decrypt the file. A fresh device needs it for `login()` and for the wallet key, and checks it against the assertion's signature first (`SyncBootstrapError` with `reason: 'PUBLIC_KEY_MISMATCH'` if it doesn't match).

**Fallback**: PRF works in Chrome 108+ and Safari 17+ / iOS 17+, not in Firefox. Where the authenticator has no PRF support, `exportForSync()` throws `PrfUnsupportedError`; `exportForSync(password)` emits a password backup instead, to restore with Option B. Passkeys sync within one ecosystem only (Apple or Google), so moving between ecosystems also takes Option B.

#### Option B: Sync with passkey + password backup

Use this when PRF is unavailable, or when you only have a password backup. This is also a path to take when `login()` throws `SyncRequiredError` or `WalletMissingError`.

```typescript
const sdk = createWeb3Passkey();

const backupData = '...'; // JSON string or Blob from your password backup file
const { ethereumAddress } = await sdk.syncWalletWithPasskey(backupData, 'MyS3cure!Backup@2042');
// 1. SDK prompts you to select your synced passkey
// 2. Decrypts the backup
// 3. Saves the passkey's metadata on this device if it's missing
// 4. Stores wallet data locally, starts a session and fires onAuthStateChanged(true, user) ✅
```

A password backup made while logged in names its passkey (`credential: { id, publicKey }`) and carries the username, restored with the passkey on a fresh device (older backups without one fall back to the wallet's address). The credential is what lets a fresh device set the passkey up: an assertion doesn't carry the public key, and `login()` and the wallet key both need it. The public key is not a secret, and the fresh device checks it against the assertion's signature.

**Requirement**: Passkey must be synced to this device (iCloud/Google Password Manager)

**Supports**:
- On a device with no data for the passkey: PRF files and password backups made by the passkey's user
- On a device that already has the passkey's metadata (the wallet record was lost): `prf` and `password` backups

On a fresh device, `syncWalletWithPasskey()` and `importFromSync()` throw `SyncBootstrapError` when they can't set the passkey up:
- `reason: 'NO_CREDENTIAL'`: password backup that doesn't name its passkey (made before 0.10.4); make a new one on a logged-in device
- `reason: 'CREDENTIAL_MISMATCH'`: the backup names another passkey than the one selected (or than the logged-in one, for `importFromSync()`)
- `reason: 'PUBLIC_KEY_MISMATCH'`: the backup's public key doesn't match the passkey's signature

**Use Case**: Wallet on desktop, want it on mobile (same passkey ecosystem)

**Pros:**
- ✅ No password needed with PRF sync files
- ✅ Leverages existing passkey sync
- ✅ Fast and convenient
- ✅ `syncWalletWithPasskey()` and `importFromSync()` work without an existing session

**Cons:**
- ⚠️ Requires passkey on target device
- ⚠️ Platform-specific (iCloud or Google)
- ⚠️ PRF sync files need Chrome 108+ or Safari 17+ / iOS 17+; elsewhere, use a password backup

---

### **3. Social Recovery**

**Purpose**: Distribute encrypted backup file fragments among trusted guardians using Shamir Secret Sharing (M-of-N)

**Setup (3-of-5 example):**
```typescript
const sdk = createWeb3Passkey();
await sdk.login();

// Step 1: Encrypt the wallet with a password and split it among guardians
const password = 'MyS3cure!Backup@2042'; // User must remember this
const guardians = [
  { name: 'Alice', email: 'alice@example.com' },
  { name: 'Bob', email: 'bob@example.com' },
  { name: 'Charlie', email: 'charlie@example.com' },
  { name: 'David', email: 'david@example.com' },
  { name: 'Eve', email: 'eve@example.com' },
];
const { guardianShares } = await sdk.setupSocialRecovery(
  guardians,
  3, // threshold: need 3 shares to recover
  password
);

// Step 2: Generate invitation for each guardian
for (const share of guardianShares) {
  const { downloadBlob, filename, shareDocument, qrCodeDataURL } =
    await sdk.generateGuardianInvite(share);
  // Send the share file (or document / QR code) to the guardian
  // Guardian stores their share safely (password manager, etc.)
}
```

w3pk stores no share on the device: only the guardians hold them.

**Recover Wallet:**
```typescript
const sdk = createWeb3Passkey();

// Step 1: Collect share files from 3+ guardians
const shares = [aliceShareFile, bobShareFile, charlieShareFile];

// Step 2: Rebuild the backup file from the shares and decrypt it with the password
const password = prompt('Enter your backup password');
const { ethereumAddress } = await sdk.recoverFromGuardians(shares, password);

// Step 3: Register a new passkey for the recovered wallet (kept in memory, never returned)
await sdk.register({ username: 'username' });
```

**Encryption**:
1. User creates password-encrypted BackupFile v3 (Argon2id + AES-256-GCM)
2. Serialize BackupFile to JSON
3. Split JSON using Shamir Secret Sharing (M-of-N threshold)
4. Each guardian gets one encrypted fragment
5. Recovery requires: threshold shares + original password

**Use Case**: Forgot password, lost all devices, ultimate safety net

**Security**: No single guardian can recover wallet alone. Guardians hold fragments of an already-encrypted backup file.

**Pros:**
- ✅ No single point of failure
- ✅ Double encryption: backup is encrypted, then fragments are distributed
- ✅ Guardians never see plaintext wallet data
- ✅ Password protection even after collecting shares
- ✅ Survives your own forgetfulness
- ✅ Survives any 2 guardians disappearing
- ✅ Highest security and redundancy

**Cons:**
- ⚠️ Requires trusted friends/family
- ⚠️ Must remember password (guardians don't have it)
- ⚠️ Setup complexity
- ⚠️ Recovery takes time (24-48 hours)
- ⚠️ Coordination required

**Recovery scenarios:**
| Scenario | Can Recover? | How |
|----------|--------------|-----|
| Lost all devices | ✅ Yes | Contact 3 guardians → combine shares → enter password |
| Lost backup + lost passkey | ✅ Yes | Contact 3 guardians → reconstruct backup file → enter password |
| 2 guardians unavailable | ✅ Yes | Still have 3 others |
| Forgot password + have shares | ❌ No | Backup file is encrypted with password |
| All guardians lost shares | ❌ No | Need another recovery layer |

---

## 📊 Workflow Comparison

| Workflow | Encryption | Use Case | Requirements |
|----------|------------|----------|--------------|
| **Backup/Restore** | Password | Lost all devices, platform switch | Password only |
| **Sync (passkey + backup)** | Any | New device with synced passkey, no active session | Passkey synced + backup file |
| **Sync (export/import)** | PRF | Transfer from active device to another | Active session + passkey synced to target |
| **Social Recovery** | Password | Forgot everything, ultimate backup | 3+ guardians available |

---

## 🔒 Security Features

1. **Never Exposes Mnemonic**: Mnemonic is always encrypted in backup files
2. **No Address in the File**: A stolen file doesn't say whose wallet it is; AES-GCM detects corruption or a wrong password
3. **Versioned Format**: `version: 3`; other versions fail with `UnsupportedBackupVersionError`
4. **Memory-Hard Password KDF**: Argon2id makes offline guessing costly on GPUs
5. **Shamir Secret Sharing**: No single guardian can recover wallet alone
6. **Multiple Encryption Options**: Choose security/convenience tradeoff

### **Social Recovery Cryptography**

```typescript
Backup File-Based Shamir Secret Sharing:

Example: 3-of-5 scheme

Step 1: Create Encrypted Backup File
- User creates password-encrypted backup file
- Backup contains: { version: 3, encryptedMnemonic, passwordEncryption, ... }
- Encryption: Argon2id(password) → AES-256-GCM
- Result: BackupFile JSON (already encrypted)

Step 2: Split Backup File
- Serialize BackupFile to JSON string
- Convert JSON to bytes
- Split bytes using Shamir Secret Sharing (3-of-5)
- Result: 5 shares of encrypted data

Step 3: Distribute Shares
- Each guardian gets one share (hex-encoded fragment)
- Shares are fragments of the encrypted backup file
- Guardians never see the plaintext mnemonic
- Guardians don't have the password

Recovery Process:
- Collect 3+ shares from guardians
- Combine shares → reconstruct BackupFile JSON
- Decrypt with password → extract mnemonic
- Register new passkey or import to existing

Mathematical basis:
- Polynomial interpolation over finite field GF(256)
- Degree = threshold - 1 (e.g., degree-2 polynomial for 3-of-5)
- Points on polynomial = shares
- Any 3 points → reconstruct polynomial → recover secret
- Any 2 points → mathematically impossible to recover
```

**Security Model:**
```
Double Encryption:
Layer 1: Backup file encrypted with password (AES-256-GCM)
Layer 2: Encrypted backup split into shares (Shamir)

Result:
- Guardians hold fragments of encrypted data
- Even with threshold shares, password still required
- No single guardian has access to wallet
- No collusion of guardians can bypass password

Attack Scenarios:
✅ Attacker steals 2 shares → Cannot reconstruct
✅ Attacker steals 3+ shares → Still needs password
✅ Attacker has password → Still needs threshold shares
❌ Attacker has password + threshold shares → Can recover
```

**Trust model:**
```
Coordinator (You):
- Must remember password (guardians don't have it)
- Cannot recover from less than threshold shares
- Can revoke/replace guardians (requires new setup)
- Can verify guardian shares are distributed

Guardians:
- Hold encrypted fragments only
- Cannot decrypt without password
- Cannot recover alone (need threshold + password)
- Can verify share validity
- Can store share safely (it's already encrypted)

Attacker:
- Cannot recover with < threshold shares
- Cannot decrypt backup without password
- Must compromise both guardians AND password
- Mathematically secure (Shamir + AES-256-GCM)
```

---

## 🛠️ API Reference

### Create Backup

```typescript
// Password-protected backup
const { blob, filename } = await w3pk.createBackupFile(password);

// PRF backup, decrypted by the passkey on any device where it synced
const { blob, filename } = await w3pk.exportForSync();
```

### Backup Status

```typescript
// Record that the user wrote down the recovery phrase
await w3pk.confirmRecoveryPhraseBackup();

// { hasBackup, lastBackupAt, methods, ..., securityScore }
const status = await w3pk.getBackupStatus();
```

### Restore from Backup

```typescript
// Option 1: Register new passkey (creates and stores credentials)
await w3pk.registerWithBackupFile(backupData, password, username);

// Option 2: Restore under the existing passkey (stores the wallet for the logged-in user)
// A backup of another wallet throws AddressChangeError: pass
// { allowAddressChange: true } once the user confirms the replacement
await w3pk.login();
await w3pk.restoreFromBackupFile(backupData, password);
```

### Cross-Device Sync

```typescript
// Export for sync (Device A - requires active session): PRF-encrypted, no password
const { blob, qrCode } = await w3pk.exportForSync();
// Or with a password fallback where PRF is unavailable
const fallback = await w3pk.exportForSync('MyS3cure!Backup@2042');

// Import on Device B where the passkey synced (no login needed, no password)
// If the passkey has another wallet on Device B, this throws AddressChangeError:
// pass { allowAddressChange: true } once the user confirms the replacement
await w3pk.importFromSync(syncData);

// Sync with a password backup (no prior session needed)
const { ethereumAddress } = await w3pk.syncWalletWithPasskey(backupData, 'MyS3cure!Backup@2042');
```

### Social Recovery

```typescript
// Setup - Encrypt the wallet with a password and split it among guardians
const { guardianShares } = await w3pk.setupSocialRecovery(
  [
    { name: 'Alice', email: 'alice@example.com' },
    { name: 'Bob', email: 'bob@example.com' },
    { name: 'Charlie', email: 'charlie@example.com' }
  ],
  2, // threshold
  'MyS3cure!Backup@2042'
);

// Generate invitations for guardians
for (const share of guardianShares) {
  const { downloadBlob, filename } = await w3pk.generateGuardianInvite(share);
  // Send the share file to the guardian
}

// Recover - Collect share files, rebuild the backup and decrypt it
const shares = [aliceShareFile, bobShareFile]; // JSON strings from guardians
const { ethereumAddress } = await w3pk.recoverFromGuardians(shares, 'MyS3cure!Backup@2042');
```

---

## 📝 Best Practices

### Backup Creation
1. **Always create a password backup** immediately after wallet creation
2. **Use strong passwords** (15+ characters, such as a passphrase of 4+ random words)
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

const { blob, filename } = await w3pk.createBackupFile(password)
```

**Password requirements** ([NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) §3.1.1.2, [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)):
- 15 to 256 characters, counted in Unicode code points after NFC normalization
- Any characters: spaces, accents and emoji are fine, and no mix of character types is required
- Not one of the 1,000 most common passwords of that length (whole-password match, any case, ignoring spaces, dots, dashes and underscores), and not a single repeated character

---

## 📖 Technical Implementation

### Files Created
- [src/backup/backup-file.ts](../src/backup/backup-file.ts) - Core backup file manager
- [src/sync/backup-sync.ts](../src/sync/backup-sync.ts) - Cross-device sync
- [src/recovery/backup-based-recovery.ts](../src/recovery/backup-based-recovery.ts) - Social recovery
- [test/backup-file.test.ts](../test/backup-file.test.ts) - Test suite

### Key Classes
- `BackupFileManager` - Create and restore backup files
- `DeviceSyncManager` - Handle cross-device sync
- `SocialRecovery` - Split/combine guardian shares

### Core Architecture

```
src/backup/
├── backup-file.ts              # Main backup orchestration
├── types.ts                    # TypeScript interfaces
├── encryption.ts               # Argon2id key derivation
└── storage.ts                  # localStorage for metadata

src/sync/
├── backup-sync.ts              # DeviceSyncManager class
└── types.ts                    # Sync-related interfaces

src/recovery/
├── backup-based-recovery.ts    # SocialRecovery class
├── shamir.ts                   # Shamir Secret Sharing
└── types.ts                    # Recovery-related interfaces

src/core/
├── sdk.ts                      # Web3Passkey: public workflow methods
├── backup-sync.ts              # Backup, restore and sync workflows
└── social-recovery.ts          # Social recovery workflows
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
- ✅ No address in the file; Argon2id parameters and bounds
- ✅ Offline extractor decrypts v3 password files (`test/standalone-extract.test.ts`)

---

## 📚 User Documentation

### Quick Start: Backup Your Wallet

```markdown
1. Create Password-Protected Backup (Recommended)
   - Click "Backup Wallet" in settings
   - Choose "Password Backup"
   - Enter strong password (you MUST remember this!)
   - Download w3pk-backup-[date].json
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
4. Provide your password backup file
5. Call syncWalletWithPasskey(backupData, password) or use the app's "Sync Wallet" flow
6. Authenticate with biometric when prompted
7. Wallet decrypted and stored locally ✅

Platform-specific:
- iOS → iCloud Keychain must be enabled
- Android → Google Password Manager
- Windows → Limited sync support
```

**Option B: Export/import sync file (transfer from active device)**

```markdown
1. On Device A: export sync file via exportForSync() (one passkey prompt)
2. Transfer file to Device B (AirDrop, QR code, etc.)
3. On Device B: importFromSync(syncData), and confirm the synced passkey when prompted
4. Wallet decrypted ✅ (no password; needs PRF: Chrome 108+, Safari 17+ / iOS 17+, not Firefox)
```

#### **Method 3: Using Social Recovery**

```markdown
1. Go to w3pk recovery page
2. Click "Social Recovery"
3. Contact your guardians (need 3 of 5)
4. Each guardian provides their share:
   - Scan QR code, OR
   - Paste share code manually (JSON format)
5. After collecting threshold shares (e.g., 3):
   - System reconstructs encrypted backup file ✅
   - Backup file is still encrypted
6. Enter your password:
   - This is the password you set during social recovery setup
   - Guardians DO NOT have this password
   - System decrypts backup file → extracts mnemonic
7. Choose username and register:
   - System creates new passkey on your device
   - Wallet credentials stored locally ✅

Timeline: ~24-48 hours (depends on guardian availability)
Security: Requires both guardian shares AND your password
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
A: `syncWalletWithPasskey()` takes any backup file and prompts for your synced passkey; on a device with no data for the passkey, that backup must be a PRF sync file or a password backup. `importFromSync()` takes only PRF sync files from `exportForSync()`, with no password. Both restore a PRF sync file the same way, and neither needs a prior `login()`.

**Q: Can I use multiple backup methods?**
A: Yes! We recommend using at least 2 methods for redundancy.

**Q: Is my encrypted backup safe to store in Google Drive?**
A: Yes, the backup is encrypted with AES-256-GCM and cannot be decrypted without your password.

**Q: What if I forget my backup password?**
A: You'll need to use another recovery method (passkey sync or social recovery). Password cannot be reset.

**Q: How secure is social recovery?**
A: Mathematically secure with Shamir's Secret Sharing. Any 2 guardians cannot recover (need 3 of 5).

**Q: Can guardians steal my wallet?**
A: No. Guardians hold encrypted fragments of an already-encrypted backup file. Even if they collude and combine all shares, they still need your password to decrypt the backup file. The password is never shared with guardians.

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
- Sync across devices

### Score Components (Max 70 points)

| Component | Points | Description |
|-----------|--------|-------------|
| **Passkey Active** | 20 pts | You have a passkey set up |
| **Passkey Multi-Device** | 10 pts | Your passkey is synced to 2+ devices |
| **Encrypted Backup** | 20 pts | You have at least one encrypted backup |
| **Phrase Verified** | 10-20 pts | You've successfully verified your backup (10 pts base + up to 10 pts for multiple verifications) |

### Security Levels

- **0-20 pts: Vulnerable** - Minimal protection
- **21-40 pts: Protected** - Basic security in place
- **41-60 pts: Secured** - Strong multi-layered protection
- **61-70 pts: Fort Knox** - Maximum security achieved

### How Verification Works

Your backup is automatically marked as "verified" when you successfully:
- Restore from a backup file using `restoreFromBackupFile()`
- Register a new passkey from backup using `registerWithBackupFile()`
- Recover from guardian shares using `recoverFromGuardians()`
- Import from device sync using `importFromSync()` or `syncWalletWithPasskey()`

Verification proves that your backup actually works, increasing your security score.

### Checking Your Score

```typescript
const sdk = createWeb3Passkey();
const status = await sdk.getBackupStatus();

console.log(status.securityScore);
// {
//   total: 60,
//   level: "secured",
//   breakdown: {
//     passkeyActive: 20,
//     passkeyMultiDevice: 10,
//     phraseVerified: 10,
//     encryptedBackup: 20
//   },
//   nextMilestone: 'Reach "fort-knox" (61+ pts): verify your backup again'
// }
```

### Score Updates

The security score updates automatically in the following scenarios:

1. **After Backup Creation**: Creating a backup file adds 20 points for encrypted backup
2. **After Restore**: Successfully restoring marks your backup as verified (+10-20 pts)
3. **After Device Sync**: Importing from sync marks backup as verified

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

## 📝 Migration from v2

BackupFile v2 (before 0.11.0) is no longer restored. To migrate a v2 password backup:

1. Open the [v0.10.6 offline tool](https://github.com/w3hc/w3pk/blob/v0.10.6/standalone/extract-mnemonic.html) (`standalone/extract-mnemonic.html` at tag `v0.10.6`) and extract the mnemonic
2. Import it (`importMnemonic()` while logged in), then create a new backup with `createBackupFile(password)`
3. Replace all stored backups and set up guardian shares again

## 🧰 Offline Extractor

`standalone/extract-mnemonic.html` decrypts v3 password backups in the browser, with no server and no network: Argon2id is inlined (a bundle of `@noble/hashes`), and AES-GCM comes from WebCrypto. Only its optional "Derive Wallets" section loads ethers from a CDN. Regenerate the inlined Argon2id after upgrading `@noble/hashes` with `pnpm build:standalone`. For v2 files, use the v0.10.6 tool linked above.

---

## 📝 License

This recovery system architecture is part of w3pk and follows the same license.
