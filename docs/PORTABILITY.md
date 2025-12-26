# W3PK Portability Guide

This guide explains how to move, backup, and link your W3PK wallet across different contexts - whether you're an end-user wanting to secure your assets or a developer integrating these features.

---

## Table of Contents

- [For End-Users](#for-end-users)
  - [Linking an External Wallet (MetaMask, etc.)](#linking-an-external-wallet-metamask-etc)
  - [Creating and Restoring Backups](#creating-and-restoring-backups)
  - [Extracting Your Mnemonic](#extracting-your-mnemonic)
- [For Developers](#for-developers)
  - [Implementing External Wallet Linking](#implementing-external-wallet-linking)
  - [Implementing Backup/Restore Features](#implementing-backuprestore-features)
  - [Building Mnemonic Export Tools](#building-mnemonic-export-tools)

---

## For End-Users

### Linking an External Wallet (MetaMask, etc.)

W3PK allows you to link external wallets (like MetaMask) to your W3PK wallet using EIP-7702 delegation. This lets you use assets (NFTs, tokens) from your external wallet without transferring them.

#### Why Link an External Wallet?

- **Use NFTs**: Access NFTs in your MetaMask wallet from apps using W3PK
- **No transfers needed**: Assets stay in your external wallet - you just grant temporary access
- **Reversible**: You can revoke the link at any time
- **Keep custody**: You maintain full control of your assets

#### How to Link Your External Wallet

1. **In the app**, look for a "Link External Wallet" or "Connect MetaMask" option
2. **Enter your external wallet address** (e.g., your MetaMask address that holds the NFT)
3. **Sign the authorization in MetaMask**: You'll be prompted to sign an EIP-7702 authorization
   - This is NOT a transaction
   - You're authorizing your W3PK wallet to act on behalf of this address
   - Review the details carefully before signing
4. **Confirm the delegation**: The app will submit the signed authorization to the blockchain
5. **Start using your assets**: Your W3PK wallet can now use assets from the linked account

#### How to Unlink Your External Wallet

1. **In the app**, find the "Revoke Delegation" or "Unlink Wallet" option
2. **Confirm**: The app will remove the delegation, returning your external account to normal

#### Important Notes

- Your external wallet must support EIP-7702 signatures
- Delegation is chain-specific (linking on Ethereum mainnet doesn't affect other chains)
- Always verify the delegation details before signing
- You can check if an address is delegated using the app's verification tools

---

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

### Implementing External Wallet Linking

External wallet linking uses EIP-7702 to delegate an external EOA (like MetaMask) to your user's W3PK smart contract wallet.

#### Basic Integration

```typescript
import { W3PK } from 'w3pk-sdk';

// Initialize SDK
const sdk = new W3PK({
  credentialName: 'MyApp',
  rpcUrl: 'https://your-rpc-url',
  walletType: 'STANDARD+MAIN'
});

// 1. Setup delegation for external wallet
const externalWalletAddress = '0x1234...'; // User's MetaMask address
const authorization = await sdk.setupExternalWalletDelegation(externalWalletAddress);

// 2. Have user sign the authorization in their external wallet
// (This part depends on how you're connecting to the external wallet)
const signedAuth = await externalWallet.signTypedData(authorization);

// 3. Execute the delegation on-chain
const txHash = await sdk.executeExternalWalletDelegation(signedAuth);
console.log('Delegation active:', txHash);

// 4. Verify delegation status
const isDelegated = await sdk.verifyExternalWalletDelegation(externalWalletAddress);
console.log('Is delegated:', isDelegated);

// 5. Later: Revoke delegation when done
await sdk.revokeExternalWalletDelegation(externalWalletAddress);
```

#### Key Methods

See [src/eip7702/external-wallet.ts](../src/eip7702/external-wallet.ts) for implementation details.

**`setupExternalWalletDelegation(externalAddress)`**
- Prepares EIP-7702 authorization data
- Returns authorization object to be signed by external wallet
- Does not require gas or on-chain interaction

**`executeExternalWalletDelegation(signedAuthorization)`**
- Submits signed authorization to blockchain
- Transforms external EOA into delegated smart contract
- Requires gas (paid by W3PK wallet)

**`verifyExternalWalletDelegation(externalAddress)`**
- Checks if an address is currently delegated
- Returns boolean
- No gas required (view function)

**`revokeExternalWalletDelegation(externalAddress)`**
- Removes delegation from external address
- Returns address to normal EOA state
- Requires gas

#### UI/UX Considerations

1. **Clear Communication**: Explain to users what delegation means
   - "Allow your W3PK wallet to use assets from your MetaMask account"
   - Show which permissions are being granted
   - Emphasize that assets stay in their original wallet

2. **Signature Flow**: Guide users through the signing process
   - Explain they'll see a signature request in MetaMask
   - Show what data they're signing
   - Provide a way to cancel if they're unsure

3. **Status Indicators**: Show delegation status clearly
   - Visual indicator when delegation is active
   - List of currently delegated addresses
   - Easy access to revoke

4. **Error Handling**:
   - User rejects signature: Allow retry
   - Transaction fails: Show clear error message
   - Unsupported wallet: Explain EIP-7702 requirements

#### Security Considerations

- **Validate addresses**: Ensure external address is a valid Ethereum address
- **Check authorization data**: Verify signature before execution
- **Monitor delegations**: Provide users with list of active delegations
- **Implement timeouts**: Consider adding expiry to authorizations
- **Audit trail**: Log delegation events for user review

For more details, see [EIP_7702.md](./EIP_7702.md#external-wallet-integration).

---

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
const password = 'user-provided-strong-password';
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
const password = 'user-provided-password';
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

See [src/core/sdk.ts](../src/core/sdk.ts) for implementation details of `createBackupFile()` and `restoreFromBackupFile()`.

---

### Building Mnemonic Export Tools

For advanced users who need to export their mnemonic to use in other wallets, W3PK provides a standalone extraction tool.

#### Reference Implementation

See [standalone/extract-mnemonic.html](../standalone/extract-mnemonic.html) for a complete standalone implementation.

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

4. **Decryption Logic**
   ```typescript
   async function extractMnemonic(backupFile: File, password: string): Promise<string> {
     const backupData = JSON.parse(await backupFile.text());

     // Decrypt the backup
     const decrypted = await decryptBackup(backupData, password);

     // Extract mnemonic
     return decrypted.mnemonic;
   }
   ```

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
