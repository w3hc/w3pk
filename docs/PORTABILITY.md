# W3PK Portability Guide

This guide explains how to move, backup, and link your W3PK wallet across different contexts - whether you're an end-user wanting to secure your assets or a developer integrating these features.

---

## Table of Contents

- [For End-Users](#for-end-users)
  - [Creating and Restoring Backups](#creating-and-restoring-backups)
  - [Moving Your Wallet to a New Device](#moving-your-wallet-to-a-new-device)
  - [Extracting Your Mnemonic](#extracting-your-mnemonic)
- [For Developers](#for-developers)
  - [Implementing Backup/Restore Features](#implementing-backuprestore-features)
  - [Implementing Device Sync](#implementing-device-sync)
  - [Building Mnemonic Export Tools](#building-mnemonic-export-tools)

---

## For End-Users

### Creating and Restoring Backups

W3PK provides encrypted backup files that allow you to restore your wallet on any device or in any app that supports W3PK.

#### Creating a Backup

1. **In the app**, look for "Backup Wallet" or "Export Wallet" option
2. **Set a strong password**: This encrypts your backup file
   - Use a unique, strong password (12+ characters)
   - Mix uppercase, lowercase, numbers, and symbols
   - Store this password securely - it cannot be recovered!
3. **Download the backup file**: Save it to a secure location
   - The file will be named something like `w3pk_backup_YYYY-MM-DD.json`
   - Store it in multiple secure locations (encrypted USB drive, password manager, etc.)

#### What's in a Backup File?

Your backup contains:
- Your wallet's mnemonic (encrypted)
- Credential information for your WebAuthn passkeys
- Wallet metadata and configuration

**Important**: The backup file is encrypted with your password. Without the password, the backup cannot be restored.

#### Restoring from a Backup

1. **In the app**, look for "Restore from Backup" or "Import Wallet"
2. **Upload your backup file**: Select the `w3pk_backup_*.json` file
3. **Enter your backup password**: The password you used when creating the backup
4. **Re-register your passkey**: You'll need to create a new WebAuthn credential
   - Use the same device authenticator (fingerprint, Face ID, etc.) if possible
   - If on a new device, you'll create a new passkey for that device
5. **Wallet restored**: Your wallet is now accessible with the same address and assets

#### Backup Security Best Practices

- **Never share your backup file** or password with anyone
- **Store backups offline** when possible (USB drives, hardware wallets)
- **Use multiple backup locations**: Don't rely on a single copy
- **Test your backup**: After creating it, try restoring it to verify it works
- **Update backups regularly**: If you make significant changes to your wallet

---

### Moving Your Wallet to a New Device

If your passkey syncs to the new device (iCloud Keychain on Apple devices, Google Password Manager on Android and Chrome), you can move your wallet without a password:

1. **On the device that has your wallet**, choose "Sync to another device" (or similar) and confirm with your passkey
2. **Transfer the sync file**: scan the QR code, or send the file by AirDrop, email, etc.
3. **On the new device**, open the app, load the sync file and confirm with the same passkey
4. **Done**: your wallet is on the new device, with the same address

The sync file can't be opened with the file alone: it also takes your passkey and your fingerprint or face. Still, keep it private and delete it once the sync is done.

**When it doesn't work**: this needs a browser that supports the passkey PRF extension (Chrome 108+, Safari 17+ / iOS 17+; not Firefox), and passkeys only sync within one ecosystem (Apple or Google). In other cases, use a password-encrypted backup: the app asks for a password when it creates the sync file, and the new device asks for the same password.

---

### Extracting Your Mnemonic

If you need to import your W3PK wallet into another wallet application (like MetaMask, Trust Wallet, etc.), you can extract your mnemonic phrase.

#### When to Extract Your Mnemonic

- Importing into standard wallet apps (MetaMask, Trust Wallet, etc.)
- Creating a hardware wallet backup
- Migrating away from W3PK
- Advanced wallet recovery scenarios

#### How to Extract Your Mnemonic

W3PK provides a standalone tool for secure mnemonic extraction:

1. **Open the extraction tool**:
   - If using w3pk directly: Open `standalone/extract-mnemonic.html` in your browser
   - If through an app: Look for "Export Mnemonic" or "Show Recovery Phrase"

2. **Upload your backup file**: Select your `w3pk_backup_*.json` file

3. **Enter your backup password**: The password you used when creating the backup

4. **View your mnemonic**: Your 12 or 24-word recovery phrase will be displayed

5. **Write it down securely**:
   - Write on paper, never store digitally unencrypted
   - Store in a secure location (safe, safety deposit box)
   - Consider using a metal backup for fire/water resistance
   - Never take photos or screenshots

6. **Verify the mnemonic**: Some tools let you verify by re-entering the words

7. **Clear the display**: Close the tool and clear your browser's cache

#### Using Your Mnemonic in Other Wallets

Once you have your mnemonic:
1. Open your destination wallet app (e.g., MetaMask)
2. Select "Import wallet" or "Restore from seed phrase"
3. Enter your mnemonic words in order
4. Set a new password for that wallet app
5. Your wallet is imported with the same addresses

#### Critical Security Warnings

⚠️ **Your mnemonic is the master key to your wallet**
- Anyone with your mnemonic can access ALL your funds
- W3PK staff will NEVER ask for your mnemonic
- Phishing sites may try to trick you - always verify URLs
- Once exposed, consider your mnemonic compromised - move funds to a new wallet

⚠️ **The extraction tool runs entirely offline**
- `standalone/extract-mnemonic.html` runs in your browser only
- No data is sent to any server
- You can disconnect from the internet before using it
- Verify you're using the official tool from the W3PK repository

---

## For Developers

### Implementing Backup/Restore Features

W3PK provides encrypted backup functionality to allow users to export and import their wallets.

#### Creating Backups

```typescript
import { W3PK } from 'w3pk-sdk';

const sdk = new W3PK({
  credentialName: 'MyApp',
  rpcUrl: 'https://your-rpc-url'
});

// Create encrypted backup
const password = 'User-Provided-Backup-1!';
const backupData = await sdk.createBackupFile(password);

// Save to file
const blob = new Blob([JSON.stringify(backupData, null, 2)], {
  type: 'application/json'
});
const url = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = `w3pk_backup_${new Date().toISOString().split('T')[0]}.json`;
a.click();
URL.revokeObjectURL(url);
```

#### Restoring from Backup

```typescript
// Read backup file
const fileInput = document.getElementById('backup-file-input');
const file = fileInput.files[0];
const backupData = JSON.parse(await file.text());

// Restore wallet
const password = 'User-Provided-Backup-1!';
await sdk.restoreFromBackupFile(backupData, password);

// Wallet is now restored and ready to use
const address = await sdk.getAddress();
console.log('Restored wallet address:', address);
```

#### Backup File Structure

```json
{
  "version": "1.0",
  "timestamp": "2025-12-26T10:30:00Z",
  "encryptedData": {
    "mnemonic": "encrypted-mnemonic-data",
    "credentialInfo": "encrypted-credential-data",
    "metadata": "encrypted-metadata"
  },
  "salt": "random-salt-for-encryption",
  "iv": "initialization-vector"
}
```

#### UI/UX Best Practices

1. **Password Requirements**: Enforce strong passwords
   ```typescript
   function validateBackupPassword(password: string): boolean {
     return password.length >= 12 &&
            /[A-Z]/.test(password) &&
            /[a-z]/.test(password) &&
            /[0-9]/.test(password) &&
            /[^A-Za-z0-9]/.test(password);
   }
   ```

2. **Password Confirmation**: Require users to enter password twice

3. **Backup Verification**: Offer to test restore immediately after backup

4. **Download Confirmation**: Show success message with file location

5. **Restore Flow**:
   - File upload interface
   - Password input
   - WebAuthn re-registration prompt
   - Success confirmation with wallet address

#### Security Best Practices

- **Never log passwords**: Even in development mode
- **Clear sensitive data**: Wipe password strings from memory after use
- **Use HTTPS**: Always serve backup/restore interfaces over HTTPS
- **No server transmission**: Keep backups client-side only
- **Validate backup format**: Check version and structure before restoration
- **Rate limiting**: Prevent brute-force password attempts on restore

#### Error Handling

```typescript
try {
  await sdk.restoreFromBackupFile(backupData, password);
} catch (error) {
  if (error.message.includes('password')) {
    // Incorrect password
    showError('Incorrect password. Please try again.');
  } else if (error.message.includes('invalid backup')) {
    // Corrupted or invalid backup file
    showError('Invalid backup file. Please check the file and try again.');
  } else if (error.message.includes('credential')) {
    // WebAuthn credential registration failed
    showError('Failed to register credential. Please try again with a valid authenticator.');
  } else {
    // Generic error
    showError('Restore failed: ' + error.message);
  }
}
```

See [src/core/backup-sync.ts](../src/core/backup-sync.ts) for implementation details of `createBackupFile()` and `restoreFromBackupFile()`.

---

### Implementing Device Sync

`exportForSync()` makes a sync file encrypted with a key derived from the passkey's [WebAuthn PRF](https://w3c.github.io/webauthn/#prf-extension) output (`encryptionMethod: 'prf'`). Any device where the passkey synced restores it with one prompt and no password, even a fresh device with no data for the passkey.

```typescript
// Device A, logged in: one passkey prompt
const { blob, filename, qrCode } = await sdk.exportForSync()

// Device B, logged out: one passkey prompt, restricted to the file's passkey
const { ethereumAddress } = await sdk.importFromSync(syncData)
```

`syncWalletWithPasskey(syncData)` restores the same files and also takes password backups. If the passkey already has another wallet on the device, both throw `AddressChangeError` unless the app passes `{ allowAddressChange: true }` once the user confirms the replacement.

**Password fallback**: PRF works in Chrome 108+ and Safari 17+ / iOS 17+, not in Firefox. Without it, `exportForSync()` throws `PrfUnsupportedError`. Pass a password to fall back to a password backup, which the new device restores with `syncWalletWithPasskey(syncData, password)`:

```typescript
import { PrfUnsupportedError } from 'w3pk'

let sync
try {
  sync = await sdk.exportForSync()
} catch (error) {
  if (!(error instanceof PrfUnsupportedError)) throw error
  sync = await sdk.exportForSync(await askUserForPassword())
}
```

Or pass the password up front: `exportForSync(password)` uses it only when PRF is unavailable. Passkeys sync within one ecosystem only (Apple or Google), so moving between ecosystems also takes a password backup.

**PRF sync file structure:**

```json
{
  "version": 3,
  "createdAt": "2026-10-25T10:30:00.000Z",
  "encryptedMnemonic": "base64(iv || AES-256-GCM ciphertext)",
  "encryptionMethod": "prf",
  "credential": { "id": "passkey credential id", "publicKey": "base64url SPKI" },
  "prfSalt": "base64url, 32 random bytes",
  "username": "alice"
}
```

The key is HKDF-SHA256 over the PRF output evaluated at `SHA-256("w3pk-prf-sync-v1" || prfSalt)`. The public key doesn't decrypt anything; the new device needs it for later logins and checks it against the assertion's signature. The file fits in a QR code (`generateSyncQR()`).

---

### Building Mnemonic Export Tools

For advanced users who need to export their mnemonic to use in other wallets, W3PK provides a standalone extraction tool.

#### Reference Implementation

See [standalone/extract-mnemonic.html](../standalone/extract-mnemonic.html) for a complete standalone implementation.

To try it, [examples/w3pk_backup_example_2026-11-02.json](../examples/w3pk_backup_example_2026-11-02.json) is a password backup of the public test mnemonic `test test test test test test test test test test test junk`, with the password `test-password`.

#### Key Features to Implement

1. **Offline-First Design**
   - All processing happens in the browser
   - No network requests after page load
   - Can work completely disconnected from internet

2. **File Upload**
   ```html
   <input type="file" id="backup-file" accept=".json">
   ```

3. **Password Input**
   ```html
   <input type="password" id="backup-password" autocomplete="off">
   ```

4. **Decryption Logic (BackupFile v3, `password`)**
   ```typescript
   import { argon2idAsync } from '@noble/hashes/argon2.js';

   async function extractMnemonic(backupFile: File, password: string): Promise<string> {
     const backup = JSON.parse(await backupFile.text());
     if (backup.version !== 3) throw new Error('Not a BackupFile v3');
     const { salt, memoryKiB, passes, parallelism } = backup.passwordEncryption;
     const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

     const keyBytes = await argon2idAsync(
       new TextEncoder().encode(password.normalize('NFC')),
       b64(salt),
       { m: memoryKiB, t: passes, p: parallelism, dkLen: 32 }
     );
     const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
     const data = b64(backup.encryptedMnemonic); // iv (12 bytes) || ciphertext
     const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, key, data.slice(12));
     return new TextDecoder().decode(plain);
   }
   ```
   The reference page inlines a bundle of `argon2idAsync` so it needs no CDN (`pnpm build:standalone` regenerates it). For v2 files, use the [v0.10.6 tool](https://github.com/w3hc/w3pk/blob/v0.10.6/standalone/extract-mnemonic.html).

5. **Display Mnemonic Securely**
   ```html
   <div id="mnemonic-display" style="user-select: none;">
     <!-- Words displayed here -->
     <!-- Warn about screenshots -->
   </div>
   <button onclick="copyToClipboard()">Copy (Use Carefully)</button>
   <button onclick="clearDisplay()">Clear and Close</button>
   ```

#### Security Features to Include

1. **Warning Messages**:
   - Explain the security implications of exposing mnemonic
   - Warn against screenshots and digital storage
   - Recommend offline use

2. **Anti-Screenshot Measures**:
   - CSS `user-select: none` on mnemonic display
   - Blur effect that requires mouse hover
   - Watermark overlay

3. **Clear Function**:
   ```typescript
   function clearMnemonic() {
     // Clear display
     document.getElementById('mnemonic-display').innerHTML = '';

     // Clear clipboard
     navigator.clipboard.writeText('');

     // Clear file input
     document.getElementById('backup-file').value = '';

     // Clear password input
     document.getElementById('backup-password').value = '';
   }
   ```

4. **Auto-Clear Timer** (optional):
   ```typescript
   let clearTimer: number;

   function displayMnemonic(words: string[]) {
     // Display words...

     // Auto-clear after 5 minutes
     clearTimer = setTimeout(() => {
       clearMnemonic();
       alert('Mnemonic cleared for security');
     }, 5 * 60 * 1000);
   }
   ```

#### UI/UX Guidelines

1. **Clear Instructions**: Step-by-step guide visible at all times

2. **Progressive Disclosure**:
   - Upload file → Enter password → View mnemonic
   - Each step only visible when previous is complete

3. **Visual Security Indicators**:
   - Lock icon when encrypted
   - Warning icon when mnemonic is visible
   - Success checkmarks for each step

4. **Accessibility**:
   - High contrast for word display
   - Large, readable font
   - Keyboard navigation support

#### Testing Your Implementation

```typescript
// Test with a sample backup
const testBackup = {
  version: '1.0',
  timestamp: new Date().toISOString(),
  encryptedData: { /* ... */ }
};

// Verify decryption
const mnemonic = await extractMnemonic(testBackup, 'test-password');
console.assert(mnemonic.split(' ').length === 12 || mnemonic.split(' ').length === 24);

// Verify BIP39 validity
import { validateMnemonic } from 'bip39';
console.assert(validateMnemonic(mnemonic));
```

#### Deployment Considerations

- **No server required**: Static HTML/JS only
- **Subresource Integrity**: Use SRI for any CDN dependencies
- **Content Security Policy**: Restrict external resources
- **Audit**: Have security experts review the code
- **Open Source**: Make the tool verifiable by users

---

## Additional Resources

- [API Reference](./API_REFERENCE.md) - Complete SDK method documentation
- [EIP-7702 Documentation](./EIP_7702.md) - Technical details on delegation
- [Security Guide](./SECURITY.md) - Security best practices and considerations
- [GitHub Repository](https://github.com/your-org/w3pk) - Source code and examples

---

## Support

For issues or questions:
- File an issue on GitHub
- Check existing documentation
- Review example implementations in `/examples`

**Remember**: Never share your mnemonic, backup passwords, or private keys with anyone, including support staff.
