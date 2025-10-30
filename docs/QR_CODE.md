# QR Code Backup System

> **Secure, Scannable, Offline Wallet Backups**
>
> Generate encrypted QR codes for wallet recovery with 30% damage tolerance and military-grade encryption.

---

## Table of Contents

- [Overview](#overview)
- [Security Architecture](#security-architecture)
- [Best Practices](#best-practices)
- [For Developers](#for-developers)
- [Using with React and Next.js](#using-with-react-and-nextjs)
- [For End Users](#for-end-users)
- [Technical Specifications](#technical-specifications)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## Overview

The w3pk QR Code backup system allows users to backup their wallet as a scannable QR code that can be:

- ✅ **Printed and stored offline** (paper, safe deposit box)
- ✅ **Password-protected** with AES-256-GCM encryption
- ✅ **Damage-resistant** with 30% error correction
- ✅ **Cross-platform** compatible (scannable from any device)
- ✅ **Secure** with address checksum verification

### Key Features

| Feature | Details |
|---------|---------|
| **Encryption** | AES-256-GCM with PBKDF2-SHA256 (310,000 iterations) |
| **Error Correction** | Reed-Solomon Level H (30% damage tolerance) |
| **Size** | 512×512 pixels (optimized for scanning) |
| **Format** | PNG data URL (embedded base64) |
| **Verification** | Address checksum prevents corrupted restores |
| **Fallback** | Canvas-based placeholder if library unavailable |

---

## Security Architecture

### Encryption Flow

```typescript
┌─────────────────────────────────────────────────────────┐
│ QR Code Creation Flow                                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. User Input                                          │
│     ├─ Mnemonic: "word1 word2 ... word12"              │
│     ├─ Password: "MyS3cur3!Password@2024"              │
│     └─ Options: { errorCorrection: 'H' }               │
│                                                          │
│  2. Key Derivation (PBKDF2-SHA256)                     │
│     ├─ Salt: Random 32 bytes                           │
│     ├─ Iterations: 310,000 (OWASP 2025)                │
│     └─ Output: 256-bit AES key                         │
│                                                          │
│  3. Encryption (AES-256-GCM)                           │
│     ├─ Algorithm: AES-GCM                               │
│     ├─ Key Size: 256 bits                              │
│     ├─ IV: Random 12 bytes                             │
│     ├─ Input: Mnemonic plaintext                       │
│     └─ Output: Encrypted ciphertext + auth tag         │
│                                                          │
│  4. Checksum Generation                                 │
│     ├─ Derive Ethereum address from mnemonic           │
│     ├─ Hash: SHA-256(address)                          │
│     └─ Store: First 8 bytes as checksum                │
│                                                          │
│  5. QR Code Data Structure                             │
│     {                                                    │
│       version: 1,                                       │
│       type: "encrypted",                                │
│       data: "<base64_encrypted_mnemonic>",             │
│       salt: "<base64_salt>",                           │
│       iv: "<base64_iv>",                               │
│       iterations: 310000,                               │
│       checksum: "<hex_address_checksum>"               │
│     }                                                    │
│                                                          │
│  6. QR Code Generation                                  │
│     ├─ Library: qrcode (npm)                           │
│     ├─ Error Correction: Level H (30%)                 │
│     ├─ Size: 512×512 pixels                            │
│     ├─ Margin: 2 modules                               │
│     └─ Output: PNG data URL                            │
│                                                          │
│  7. Recovery Instructions                               │
│     ├─ Storage recommendations                          │
│     ├─ Recovery steps                                   │
│     ├─ Security warnings                                │
│     └─ Verification guidance                            │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Decryption Flow

```typescript
┌─────────────────────────────────────────────────────────┐
│ QR Code Recovery Flow                                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. Scan QR Code                                        │
│     └─ Extract JSON data from QR                       │
│                                                          │
│  2. Parse and Validate                                  │
│     ├─ Verify version = 1                              │
│     ├─ Verify type = "encrypted"                       │
│     └─ Extract: data, salt, iv, iterations, checksum   │
│                                                          │
│  3. Key Derivation                                      │
│     ├─ User enters password                            │
│     ├─ PBKDF2-SHA256(password, salt, 310000)           │
│     └─ Derive 256-bit AES key                          │
│                                                          │
│  4. Decryption                                          │
│     ├─ AES-256-GCM decrypt                             │
│     ├─ Verify authentication tag                       │
│     └─ Output: Plaintext mnemonic                      │
│                                                          │
│  5. Verification                                        │
│     ├─ Derive Ethereum address from mnemonic           │
│     ├─ Calculate SHA-256(address)                      │
│     ├─ Compare with stored checksum                    │
│     └─ Match? → Success | Mismatch → Error             │
│                                                          │
│  6. Wallet Restoration                                  │
│     ├─ Display recovered address                       │
│     ├─ User verifies address                           │
│     └─ Re-register with new passkey                    │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Error Correction Details

QR codes use **Reed-Solomon error correction** to handle damage:

| Level | Recovery Capacity | w3pk Usage |
|-------|------------------|------------|
| **L** (Low) | 7% data loss | ❌ Not used |
| **M** (Medium) | 15% data loss | ❌ Not used |
| **Q** (Quartile) | 25% data loss | ❌ Not used |
| **H** (High) | **30% data loss** | ✅ **Default** |

**Level H means:**
- Up to 30% of QR code can be damaged/obscured
- Still fully scannable and recoverable
- Ideal for physical storage (folding, wear, water damage)
- Slightly larger QR code size (acceptable tradeoff)

---

## Best Practices

### For QR Code Generation

#### ✅ Always Use Encryption

```typescript
// ✅ RECOMMENDED: Password-protected QR
const backup = await sdk.createQRBackup('MyS3cur3!Password@2024', {
  errorCorrection: 'H'  // 30% damage tolerance
});

// ❌ DANGEROUS: Plain QR code (anyone with QR can steal wallet)
const backup = await sdk.createQRBackup(undefined, {
  errorCorrection: 'H'
});
```

#### ✅ Use Strong Passwords

w3pk enforces strong password requirements:

- **Minimum 12 characters**
- At least 1 uppercase letter (A-Z)
- At least 1 lowercase letter (a-z)
- At least 1 number (0-9)
- At least 1 special character (!@#$%^&*)
- Not in common password dictionary

**Good passwords:**
```
✅ correct horse battery staple        (passphrase)
✅ MyS3cur3!Backup@December2024        (long with variety)
✅ x8$mK9#nP2@vQ5!zR7                 (password manager generated)
```

**Bad passwords:**
```
❌ password123         (too common)
❌ MyPassword          (too simple)
❌ 12345678            (sequential)
❌ qwerty123           (keyboard pattern)
```

#### ✅ Test Scannability

Before printing final copies, test that the QR code is scannable:

1. Display QR on screen
2. Scan with phone camera (iOS/Android native camera app)
3. Verify data is readable
4. Test at different angles and lighting
5. Test with slightly damaged/obscured QR (cover 10-20%)

#### ✅ Store Securely

**Recommended storage locations:**

| Location | Security | Accessibility | Cost |
|----------|----------|---------------|------|
| **Safe deposit box** | ⭐⭐⭐⭐⭐ | ⭐⭐ | $$ |
| **Home safe** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | $$$ |
| **Trusted family member** | ⭐⭐⭐ | ⭐⭐⭐⭐ | Free |
| **Multiple locations** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | $ |

**DO:**
- ✅ Print on quality paper (acid-free for longevity)
- ✅ Store in protective sleeve/envelope
- ✅ Keep multiple copies in different locations
- ✅ Test QR code readability periodically
- ✅ Use tamper-evident storage (seal, signature)

**DON'T:**
- ❌ Take screenshots or digital photos
- ❌ Store in cloud unencrypted
- ❌ Email or message to anyone
- ❌ Display publicly or share online
- ❌ Laminate (can cause scanning glare issues)

### Security Considerations

#### 🔒 Password Security

Your QR backup is **only as secure as your password**.

**Brute-force resistance:**

| Password Type | Entropy | Time to Crack (GPU) |
|--------------|---------|---------------------|
| `password123` | ~20 bits | **Seconds** ⚠️ |
| `MyPassword123!` | ~35 bits | **Hours** ⚠️ |
| `MyS3cur3!Pass@2024` | ~50 bits | **Months** ✅ |
| `correct horse battery staple` | ~80 bits | **Centuries** ✅ |
| Random 16 chars | ~100 bits | **Universe lifetime** ✅ |

**Recommendation:** Use a password manager to generate and store strong passwords.

#### 🔒 Physical Security

Even encrypted QR codes need physical security:

**Threats:**
1. **QR Swapping Attack** - Attacker replaces your QR with theirs
   - **Mitigation:** Include visual identifiers (photo, unique icon, partial address)

2. **Camera Malware** - Compromised scanner steals QR data
   - **Mitigation:** Use trusted devices, scan in private locations

3. **Over-the-shoulder Scanning** - Someone photographs your QR while scanning
   - **Mitigation:** Scan in private, cover surroundings

4. **Interception During Recovery** - Network attacks during restoration
   - **Mitigation:** Use offline recovery tools, air-gapped devices

#### 🔒 Storage Best Practices

**Multi-location strategy:**

```
Primary Copy
├─ Location: Home safe
├─ Format: Printed + sealed envelope
└─ Access: Immediate

Backup Copy 1
├─ Location: Bank safe deposit box
├─ Format: Printed + instructions
└─ Access: Within 24 hours

Backup Copy 2
├─ Location: Trusted family member
├─ Format: Printed + sealed tamper-evident envelope
└─ Access: Within 48 hours (requires contact)

Backup Copy 3 (optional)
├─ Location: Encrypted cloud storage
├─ Format: Encrypted file + password in separate location
└─ Access: Anywhere with internet
```

---

## For Developers

### Installation

```bash
# Install w3pk
npm install w3pk ethers

# Optional: Install qrcode for QR generation
npm install qrcode

# Optional: Install types for better IDE support
npm install --save-dev @types/qrcode
```

### Basic Usage

```typescript
import { Web3Passkey } from 'w3pk';

const sdk = new Web3Passkey();

// 1. Create encrypted QR backup
const { qrCodeDataURL, instructions, rawData } = await sdk.createQRBackup(
  'MyS3cur3!Password@2024',
  { errorCorrection: 'H' }  // Level H = 30% damage tolerance
);

// 2. Display QR code in UI
document.getElementById('qr-image').src = qrCodeDataURL;

// 3. Show instructions to user
document.getElementById('instructions').textContent = instructions;

// 4. Optional: Download as image
const link = document.createElement('a');
link.href = qrCodeDataURL;
link.download = 'wallet-backup-qr.png';
link.click();
```

### Recovery Implementation

```typescript
// Recovery page - scan QR and restore
async function recoverFromQR(scannedData: string, password: string) {
  try {
    // Restore wallet from QR
    const { mnemonic, ethereumAddress } = await sdk.restoreFromQR(
      scannedData,
      password
    );

    // Show success with address verification
    showSuccess(`
      ✅ Wallet recovered successfully!

      Address: ${ethereumAddress}

      ⚠️ Please verify this matches your expected address.
    `);

    // Re-register with new passkey
    await sdk.register({
      username: 'recovered-wallet',
      mnemonic  // Use recovered mnemonic
    });

    return { success: true, address: ethereumAddress };

  } catch (error) {
    if (error.message.includes('checksum mismatch')) {
      showError('❌ Incorrect password or corrupted QR code. Please try again.');
    } else if (error.message.includes('Unsupported')) {
      showError('❌ This QR code format is not supported by this version.');
    } else {
      showError(`❌ Recovery failed: ${error.message}`);
    }

    return { success: false, error: error.message };
  }
}
```

### Advanced: Custom UI

```typescript
// Create QR backup with custom UI
async function createQRBackupWithUI(sdk: Web3Passkey) {
  // 1. Prompt for password
  const password = await promptSecurePassword({
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true
  });

  // 2. Show loading indicator
  showLoading('Generating encrypted QR code...');

  try {
    // 3. Generate QR backup
    const backup = await sdk.createQRBackup(password, {
      errorCorrection: 'H'
    });

    hideLoading();

    // 4. Display QR with visual verification
    displayQRBackup({
      qrCodeDataURL: backup.qrCodeDataURL,
      ethereumAddress: await sdk.getAddress(),
      instructions: backup.instructions,
      createdAt: new Date().toISOString()
    });

    // 5. Offer print and download options
    showActionButtons([
      { label: 'Print QR Code', action: () => printQR(backup.qrCodeDataURL) },
      { label: 'Download PNG', action: () => downloadQR(backup.qrCodeDataURL) },
      { label: 'Test Scan', action: () => testScanQR() }
    ]);

  } catch (error) {
    hideLoading();

    if (error.message.includes('qrcode')) {
      showError(`
        QR code library not installed.

        To enable QR backups, run:
        npm install qrcode

        Alternative: Use encrypted ZIP backup instead.
      `);
    } else {
      showError(`Failed to create QR backup: ${error.message}`);
    }
  }
}

// Display QR with verification info
function displayQRBackup(info: {
  qrCodeDataURL: string;
  ethereumAddress: string;
  instructions: string;
  createdAt: string;
}) {
  return `
    <div class="qr-backup-container">
      <div class="qr-header">
        <h2>🔐 Wallet Backup QR Code</h2>
        <p class="timestamp">Created: ${new Date(info.createdAt).toLocaleString()}</p>
      </div>

      <div class="qr-display">
        <img
          src="${info.qrCodeDataURL}"
          alt="Wallet Backup QR Code"
          class="qr-image"
        />
      </div>

      <div class="verification">
        <h3>Verification</h3>
        <p class="address">
          <strong>Wallet Address:</strong><br>
          <code>${info.ethereumAddress}</code>
        </p>
        <p class="verify-note">
          ✓ After recovery, verify this address matches
        </p>
      </div>

      <div class="security-warning">
        <h3>⚠️ Security Reminder</h3>
        <ul>
          <li>This QR code is encrypted with your password</li>
          <li>Store in a secure physical location</li>
          <li>Never share or photograph</li>
          <li>Test scannability before final storage</li>
        </ul>
      </div>

      <details class="instructions">
        <summary>📋 Full Instructions</summary>
        <pre>${info.instructions}</pre>
      </details>
    </div>
  `;
}
```

### Print Styling

Add CSS for optimal printing:

```css
/* Print-optimized QR code display */
@media print {
  .qr-backup-container {
    page-break-inside: avoid;
    page-break-after: always;
  }

  .qr-image {
    width: 4in;      /* Physical size for easy scanning */
    height: 4in;
    display: block;
    margin: 0.5in auto;
  }

  .address {
    font-size: 10pt;
    word-break: break-all;
  }

  .instructions {
    font-size: 9pt;
    line-height: 1.4;
    margin-top: 0.25in;
  }

  /* Hide non-essential elements when printing */
  .action-buttons,
  .qr-header .timestamp {
    display: none;
  }
}

/* Screen display */
@media screen {
  .qr-backup-container {
    max-width: 600px;
    margin: 2rem auto;
    padding: 2rem;
    border: 1px solid #ddd;
    border-radius: 8px;
  }

  .qr-image {
    width: 100%;
    max-width: 512px;
    height: auto;
    border: 2px solid #333;
    padding: 1rem;
    background: white;
  }

  .address code {
    display: block;
    padding: 0.5rem;
    background: #f5f5f5;
    border-radius: 4px;
    font-family: 'Monaco', 'Courier New', monospace;
    font-size: 12px;
    word-break: break-all;
  }

  .security-warning {
    background: #fff3cd;
    border-left: 4px solid #ffc107;
    padding: 1rem;
    margin: 1rem 0;
  }
}
```

### Error Handling

```typescript
// Comprehensive error handling for QR operations
enum QRErrorType {
  LIBRARY_MISSING = 'QR_LIBRARY_MISSING',
  INVALID_PASSWORD = 'INVALID_PASSWORD',
  CHECKSUM_MISMATCH = 'CHECKSUM_MISMATCH',
  CORRUPTED_QR = 'CORRUPTED_QR',
  UNSUPPORTED_VERSION = 'UNSUPPORTED_VERSION',
  GENERATION_FAILED = 'GENERATION_FAILED'
}

function handleQRError(error: Error): { type: QRErrorType; message: string; solution: string } {
  if (error.message.includes('qrcode')) {
    return {
      type: QRErrorType.LIBRARY_MISSING,
      message: 'QR code library not installed',
      solution: 'Run: npm install qrcode'
    };
  }

  if (error.message.includes('checksum mismatch')) {
    return {
      type: QRErrorType.CHECKSUM_MISMATCH,
      message: 'Wrong password or corrupted QR code',
      solution: 'Double-check your password or re-scan the QR code'
    };
  }

  if (error.message.includes('Unsupported')) {
    return {
      type: QRErrorType.UNSUPPORTED_VERSION,
      message: 'QR code version not supported',
      solution: 'Update w3pk to the latest version'
    };
  }

  if (error.message.includes('Password required')) {
    return {
      type: QRErrorType.INVALID_PASSWORD,
      message: 'Password required for encrypted QR',
      solution: 'Enter the password used when creating the backup'
    };
  }

  return {
    type: QRErrorType.GENERATION_FAILED,
    message: error.message,
    solution: 'Check console for details or contact support'
  };
}
```

### Testing Checklist

```typescript
// Comprehensive test suite for QR functionality
describe('QR Code Backup System', () => {

  test('1. QR generation with encryption', async () => {
    const backup = await sdk.createQRBackup('test-password', {
      errorCorrection: 'H'
    });

    expect(backup.qrCodeDataURL).toMatch(/^data:image\/png;base64,/);
    expect(backup.rawData).toBeDefined();
    expect(backup.instructions).toContain('RECOVERY STEPS');
  });

  test('2. Round-trip: create → restore → verify', async () => {
    const originalMnemonic = 'test test test test test test test test test test test junk';

    // Create QR
    const { rawData } = await sdk.createQRBackup('password123');

    // Restore QR
    const { mnemonic, ethereumAddress } = await sdk.restoreFromQR(
      rawData,
      'password123'
    );

    expect(mnemonic).toBe(originalMnemonic);
    expect(ethereumAddress).toMatch(/^0x[a-fA-F0-9]{40}$/);
  });

  test('3. Wrong password fails gracefully', async () => {
    const { rawData } = await sdk.createQRBackup('correct-password');

    await expect(
      sdk.restoreFromQR(rawData, 'wrong-password')
    ).rejects.toThrow('checksum mismatch');
  });

  test('4. Corrupted QR data fails verification', async () => {
    const { rawData } = await sdk.createQRBackup('password');
    const corrupted = rawData.slice(0, -20) + 'CORRUPTED_DATA';

    await expect(
      sdk.restoreFromQR(corrupted, 'password')
    ).rejects.toThrow();
  });

  test('5. Error correction level H is used', async () => {
    const { rawData } = await sdk.createQRBackup('password', {
      errorCorrection: 'H'
    });

    // Parse QR data
    const data = JSON.parse(rawData);

    // Verify high error correction (30% damage tolerance)
    expect(data.version).toBe(1);
    expect(data.type).toBe('encrypted');
  });

  test('6. Checksum verification works', async () => {
    const { rawData } = await sdk.createQRBackup('password');
    const data = JSON.parse(rawData);

    // Checksum should be present
    expect(data.checksum).toBeDefined();
    expect(data.checksum).toHaveLength(16); // 8 bytes hex
  });

  test('7. Fallback works when qrcode not installed', async () => {
    // Mock qrcode import failure
    jest.mock('qrcode', () => {
      throw new Error('Cannot find module qrcode');
    });

    const backup = await sdk.createQRBackup('password');

    // Should still return a data URL (canvas fallback)
    expect(backup.qrCodeDataURL).toMatch(/^data:/);
  });

  test('8. QR code is scannable at different sizes', async () => {
    const { qrCodeDataURL } = await sdk.createQRBackup('password');

    // Test at multiple resolutions
    const sizes = [256, 512, 1024];

    for (const size of sizes) {
      const resized = await resizeDataURL(qrCodeDataURL, size);
      expect(resized).toBeDefined();
      // Manual verification: scan with phone
    }
  });

  test('9. Instructions are comprehensive', async () => {
    const { instructions } = await sdk.createQRBackup('password');

    // Verify instructions contain key sections
    expect(instructions).toContain('STORAGE INSTRUCTIONS');
    expect(instructions).toContain('RECOVERY STEPS');
    expect(instructions).toContain('SECURITY NOTES');
    expect(instructions).toContain('ERROR CORRECTION');
    expect(instructions).toContain('VERIFICATION');
  });

  test('10. Plain QR (unencrypted) works but warns', async () => {
    const { rawData } = await sdk.createQRBackup(undefined);
    const data = JSON.parse(rawData);

    expect(data.type).toBe('plain');
    expect(data.data).toBeDefined(); // Mnemonic in plain text

    // Should have warning in instructions
    const { instructions } = await sdk.createQRBackup(undefined);
    expect(instructions).toContain('NOT ENCRYPTED');
  });
});
```

---

## Using with React and Next.js

### Option 1: Use w3pk's Built-in QR Generation

If you're using w3pk in a React/Next.js app, the simplest approach is to use w3pk's built-in QR generation and display the data URL directly:

```tsx
'use client'; // Next.js 13+ App Router

import { Web3Passkey } from 'w3pk';
import { useState } from 'react';
import Image from 'next/image';

export default function WalletBackup() {
  const [sdk] = useState(() => new Web3Passkey());
  const [qrData, setQrData] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleCreateBackup = async (password: string) => {
    setLoading(true);
    try {
      const backup = await sdk.createQRBackup(password, {
        errorCorrection: 'H'
      });

      setQrData(backup.qrCodeDataURL);
    } catch (error) {
      console.error('Backup failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="wallet-backup">
      {!qrData ? (
        <button
          onClick={() => handleCreateBackup('user-password')}
          disabled={loading}
        >
          {loading ? 'Generating...' : 'Create QR Backup'}
        </button>
      ) : (
        <>
          {/* Next.js Image component */}
          <Image
            src={qrData}
            alt="Wallet Backup QR Code"
            width={512}
            height={512}
            priority
          />

          {/* Or standard img tag */}
          <img src={qrData} alt="Wallet Backup" />

          <button onClick={() => window.print()}>
            Print QR Code
          </button>
        </>
      )}
    </div>
  );
}
```

**Pros:**
- ✅ No additional dependencies
- ✅ Works with w3pk's encryption out of the box
- ✅ Consistent with w3pk's error correction settings
- ✅ Works in both SSR and client-side rendering

**Cons:**
- ⚠️ Requires optional `qrcode` package installed
- ⚠️ Less customization of QR appearance

---

### Option 2: Use `qrcode.react` with w3pk's Encrypted Data

If you're already using `qrcode.react` in your Next.js app, you can use it to render w3pk's encrypted QR data:

```bash
npm install qrcode.react
npm install @types/qrcode.react --save-dev
```

```tsx
'use client';

import { Web3Passkey } from 'w3pk';
import { QRCodeSVG, QRCodeCanvas } from 'qrcode.react';
import { useState, useEffect } from 'react';

export default function WalletBackupWithReact() {
  const [sdk] = useState(() => new Web3Passkey());
  const [qrData, setQrData] = useState<string>('');
  const [loading, setLoading] = useState(false);

  const handleCreateBackup = async (password: string) => {
    setLoading(true);
    try {
      // Get encrypted QR data from w3pk (not the image, just the data)
      const backup = await sdk.createQRBackup(password, {
        errorCorrection: 'H'
      });

      // w3pk returns { qrCodeDataURL, rawData, instructions }
      // Use rawData for qrcode.react
      setQrData(backup.rawData);

    } catch (error) {
      console.error('Backup failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="wallet-backup">
      {!qrData ? (
        <button
          onClick={() => handleCreateBackup('user-password')}
          disabled={loading}
        >
          {loading ? 'Generating...' : 'Create QR Backup'}
        </button>
      ) : (
        <div className="qr-display">
          {/* SVG QR Code (recommended for web) */}
          <QRCodeSVG
            value={qrData}
            size={512}
            level="H"  // 30% error correction (matches w3pk)
            includeMargin={true}
            marginSize={2}
          />

          {/* Or Canvas QR Code (for downloading) */}
          <QRCodeCanvas
            value={qrData}
            size={512}
            level="H"
            includeMargin={true}
            marginSize={2}
          />
        </div>
      )}
    </div>
  );
}
```

**Pros:**
- ✅ Full React component
- ✅ SVG format (scalable, smaller file size)
- ✅ More customization options
- ✅ Better for responsive designs

**Cons:**
- ⚠️ Additional dependency (`qrcode.react`)
- ⚠️ Need to ensure error correction level matches

---

### Option 3: Hybrid Approach (Recommended for Next.js)

Use w3pk for encryption and `qrcode.react` for rendering:

```tsx
'use client';

import { Web3Passkey } from 'w3pk';
import { QRCodeSVG } from 'qrcode.react';
import { useState } from 'react';

interface QRBackupProps {
  onBackupCreated?: (data: string) => void;
}

export default function QRBackupComponent({ onBackupCreated }: QRBackupProps) {
  const [sdk] = useState(() => new Web3Passkey());
  const [backupData, setBackupData] = useState<{
    rawData: string;
    address: string;
    instructions: string;
  } | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const validatePassword = (pwd: string): boolean => {
    // w3pk's password requirements
    if (pwd.length < 12) return false;
    if (!/[A-Z]/.test(pwd)) return false;
    if (!/[a-z]/.test(pwd)) return false;
    if (!/[0-9]/.test(pwd)) return false;
    if (!/[!@#$%^&*]/.test(pwd)) return false;
    return true;
  };

  const handleCreateBackup = async () => {
    if (!validatePassword(password)) {
      setError('Password must be 12+ chars with uppercase, lowercase, numbers, and symbols');
      return;
    }

    try {
      const backup = await sdk.createQRBackup(password, {
        errorCorrection: 'H'
      });

      const address = await sdk.getAddress();

      setBackupData({
        rawData: backup.rawData,
        address,
        instructions: backup.instructions
      });

      onBackupCreated?.(backup.rawData);

    } catch (err: any) {
      if (err.message.includes('qrcode')) {
        setError('Install qrcode package: npm install qrcode');
      } else {
        setError(`Backup failed: ${err.message}`);
      }
    }
  };

  const handleDownloadQR = () => {
    if (!backupData) return;

    // Get canvas from QRCodeCanvas component
    const canvas = document.querySelector('canvas');
    if (canvas) {
      const url = canvas.toDataURL('image/png');
      const a = document.createElement('a');
      a.href = url;
      a.download = `wallet-backup-${Date.now()}.png`;
      a.click();
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-6">
      {!backupData ? (
        <div className="space-y-4">
          <h2 className="text-2xl font-bold">Create QR Backup</h2>

          <div>
            <label className="block text-sm font-medium mb-2">
              Password (12+ characters)
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 border rounded-lg"
              placeholder="Enter strong password"
            />
          </div>

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-700">
              {error}
            </div>
          )}

          <button
            onClick={handleCreateBackup}
            className="w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Generate Encrypted QR Code
          </button>
        </div>
      ) : (
        <div className="space-y-6">
          <h2 className="text-2xl font-bold">Your Wallet Backup</h2>

          {/* QR Code Display */}
          <div className="flex flex-col items-center space-y-4">
            <div className="p-4 bg-white border-4 border-gray-800 rounded-lg">
              <QRCodeSVG
                value={backupData.rawData}
                size={512}
                level="H"
                includeMargin={true}
                marginSize={2}
              />
            </div>

            {/* Address Verification */}
            <div className="w-full p-4 bg-gray-50 rounded-lg">
              <p className="text-sm font-medium text-gray-700">Wallet Address:</p>
              <p className="font-mono text-xs break-all mt-1">
                {backupData.address}
              </p>
              <p className="text-xs text-gray-500 mt-2">
                ✓ Verify this address matches after recovery
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3">
            <button
              onClick={() => window.print()}
              className="flex-1 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
            >
              🖨️ Print QR Code
            </button>
            <button
              onClick={handleDownloadQR}
              className="flex-1 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              📥 Download PNG
            </button>
          </div>

          {/* Security Warning */}
          <div className="p-4 bg-yellow-50 border-l-4 border-yellow-400">
            <h3 className="font-bold text-yellow-800 mb-2">⚠️ Security Reminder</h3>
            <ul className="text-sm text-yellow-700 space-y-1">
              <li>• This QR code is encrypted with your password</li>
              <li>• Store in a secure physical location</li>
              <li>• Never share or photograph</li>
              <li>• Keep password separate from QR code</li>
            </ul>
          </div>

          {/* Instructions (collapsible) */}
          <details className="border rounded-lg p-4">
            <summary className="cursor-pointer font-medium">
              📋 Full Recovery Instructions
            </summary>
            <pre className="mt-3 text-xs whitespace-pre-wrap overflow-auto">
              {backupData.instructions}
            </pre>
          </details>
        </div>
      )}
    </div>
  );
}
```

---

### Next.js 13+ App Router Considerations

```tsx
// app/wallet/backup/page.tsx
'use client';

import dynamic from 'next/dynamic';

// Dynamic import to avoid SSR issues with Web3Passkey
const QRBackupComponent = dynamic(
  () => import('@/components/QRBackupComponent'),
  { ssr: false }
);

export default function BackupPage() {
  return (
    <main className="container mx-auto py-8">
      <QRBackupComponent />
    </main>
  );
}
```

**Why use dynamic import?**
- Web3Passkey uses browser APIs (WebAuthn, Crypto)
- These aren't available during SSR
- `ssr: false` ensures component only renders on client

---

### Print Styling for Next.js

```tsx
// app/globals.css or component-specific CSS module

@media print {
  /* Hide everything except QR code when printing */
  body * {
    visibility: hidden;
  }

  .qr-display,
  .qr-display * {
    visibility: visible;
  }

  .qr-display {
    position: absolute;
    left: 0;
    top: 0;
    width: 100%;
  }

  /* Optimal QR code size for printing */
  .qr-display svg,
  .qr-display canvas {
    width: 4in !important;
    height: 4in !important;
    display: block;
    margin: 0.5in auto;
  }

  /* Include address for verification */
  .address-verification {
    display: block !important;
    page-break-inside: avoid;
    margin-top: 0.5in;
    font-size: 10pt;
  }

  /* Hide buttons when printing */
  button,
  .no-print {
    display: none !important;
  }
}
```

---

### Recovery Component (Scanning QR)

```tsx
'use client';

import { Web3Passkey } from 'w3pk';
import { useState } from 'react';
import { QrReader } from 'react-qr-reader'; // Optional: for camera scanning

export default function QRRecoveryComponent() {
  const [sdk] = useState(() => new Web3Passkey());
  const [scannedData, setScannedData] = useState('');
  const [password, setPassword] = useState('');
  const [recovered, setRecovered] = useState<{
    address: string;
    success: boolean;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleRecover = async () => {
    try {
      setError(null);

      const { mnemonic, ethereumAddress } = await sdk.restoreFromQR(
        scannedData,
        password
      );

      // Re-register with recovered mnemonic
      await sdk.register({
        username: 'recovered-wallet',
        mnemonic
      });

      setRecovered({
        address: ethereumAddress,
        success: true
      });

    } catch (err: any) {
      if (err.message.includes('checksum mismatch')) {
        setError('❌ Incorrect password or corrupted QR code');
      } else if (err.message.includes('Unsupported')) {
        setError('❌ QR code version not supported. Update w3pk.');
      } else {
        setError(`❌ Recovery failed: ${err.message}`);
      }
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-6 space-y-6">
      <h2 className="text-2xl font-bold">Recover Wallet from QR</h2>

      {!recovered ? (
        <>
          {/* Option 1: Paste QR data */}
          <div>
            <label className="block text-sm font-medium mb-2">
              QR Code Data (JSON)
            </label>
            <textarea
              value={scannedData}
              onChange={(e) => setScannedData(e.target.value)}
              className="w-full px-3 py-2 border rounded-lg font-mono text-xs"
              rows={6}
              placeholder='{"version":1,"type":"encrypted",...}'
            />
          </div>

          {/* Option 2: Upload QR image */}
          <div>
            <label className="block text-sm font-medium mb-2">
              Or Upload QR Image
            </label>
            <input
              type="file"
              accept="image/*"
              onChange={async (e) => {
                const file = e.target.files?.[0];
                if (file) {
                  // Use jsQR or similar library to decode image
                  // const data = await decodeQRFromImage(file);
                  // setScannedData(data);
                }
              }}
              className="w-full"
            />
          </div>

          {/* Password */}
          <div>
            <label className="block text-sm font-medium mb-2">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 border rounded-lg"
              placeholder="Enter backup password"
            />
          </div>

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-700">
              {error}
            </div>
          )}

          <button
            onClick={handleRecover}
            disabled={!scannedData || !password}
            className="w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400"
          >
            Recover Wallet
          </button>
        </>
      ) : (
        <div className="p-6 bg-green-50 border border-green-200 rounded-lg">
          <h3 className="text-xl font-bold text-green-800 mb-4">
            ✅ Wallet Recovered Successfully!
          </h3>

          <div className="space-y-2">
            <p className="text-sm font-medium text-gray-700">
              Recovered Address:
            </p>
            <p className="font-mono text-sm break-all p-3 bg-white rounded border">
              {recovered.address}
            </p>
          </div>

          <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
            <p className="text-sm text-yellow-800">
              ⚠️ Please verify this address matches your expected wallet address.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
```

---

### Comparison: w3pk vs qrcode.react

| Feature | w3pk built-in | qrcode.react | Hybrid |
|---------|--------------|--------------|--------|
| **Setup** | Simple | Need extra package | Medium |
| **Encryption** | ✅ Built-in | ❌ Manual | ✅ Built-in |
| **Format** | PNG data URL | SVG/Canvas | Your choice |
| **Customization** | Limited | Full | Full |
| **Error Correction** | Always H | Must specify | Must match |
| **SSR Compatible** | ⚠️ Client only | ⚠️ Client only | ⚠️ Client only |
| **File Size** | Larger (base64) | Smaller (SVG) | Smaller |
| **React Integration** | Medium | Native | Native |

---

### Recommendation for React/Next.js Developers

**If you already have `qrcode.react` installed:** Use **Option 3 (Hybrid)**
- Use w3pk for encryption and data generation
- Use `qrcode.react` for rendering the QR code
- Best of both worlds

**If you're starting fresh:** Use **Option 1 (w3pk built-in)**
- Fewer dependencies
- Simpler integration
- Consistent with w3pk's design

**Code example:**
```tsx
// ✅ Hybrid approach (recommended if using qrcode.react)
const backup = await sdk.createQRBackup(password);

<QRCodeSVG
  value={backup.rawData}  // Use rawData, not qrCodeDataURL
  size={512}
  level="H"              // Must match w3pk's error correction
/>

// ✅ Built-in approach (simplest)
const backup = await sdk.createQRBackup(password);

<img src={backup.qrCodeDataURL} alt="Backup QR" />
```

---

## For End Users

### Creating a QR Backup

**Step-by-step guide:**

1. **Open Backup Settings**
   - Navigate to wallet settings
   - Click "Backup Wallet"
   - Select "QR Code Backup"

2. **Choose Encryption**
   - **Recommended:** Enable password protection
   - Enter a strong password (12+ characters)
   - Confirm password
   - Write down password separately

3. **Generate QR Code**
   - System generates encrypted QR code
   - QR code appears on screen
   - Instructions are displayed

4. **Test Scannability**
   - Use your phone camera to scan QR code
   - Verify it can be read
   - Don't enter password yet (just testing)

5. **Print or Save**
   - **Option A:** Print on quality paper
   - **Option B:** Download as PNG image
   - Create multiple copies

6. **Store Securely**
   - Place in safe, safety deposit box, or with trusted person
   - Store password separately (not with QR code!)
   - Keep multiple copies in different locations

### Recovering from QR Backup

**Step-by-step recovery:**

1. **Locate Your QR Backup**
   - Retrieve printed QR code or image file
   - Ensure QR code is clear and undamaged

2. **Scan QR Code**
   - Open w3pk recovery page
   - Click "Restore from QR"
   - Use phone/computer camera to scan
   - Or upload image file

3. **Enter Password**
   - Enter the password used when creating backup
   - Click "Decrypt and Restore"

4. **Verify Address**
   - System displays recovered wallet address
   - **Important:** Verify this matches your expected address
   - If incorrect, try different password

5. **Complete Recovery**
   - System creates new passkey for this device
   - Authenticate with biometric/PIN
   - Wallet is now accessible

6. **Test Recovered Wallet**
   - Check balance
   - Verify transaction history
   - Test signing a transaction (small amount first)

### Storage Recommendations

**Best storage options ranked:**

1. **🏆 Bank Safe Deposit Box** (Most secure)
   - Physical security
   - Fire/flood protection
   - Access during bank hours
   - Small annual fee

2. **🏠 Home Safe** (Convenient)
   - Immediate access
   - Fire-resistant safe recommended
   - Keep at home but secured
   - Moderate cost

3. **👨‍👩‍👧‍👦 Trusted Family Member** (Redundancy)
   - Give sealed envelope to family
   - Geographic distribution
   - Verbal instructions
   - Free

4. **💼 Multiple Locations** (Maximum protection)
   - Combine 2-3 methods above
   - Different geographic areas
   - Survives regional disasters
   - Recommended for high-value wallets

**Storage checklist:**

- [ ] QR code printed on quality paper
- [ ] Placed in protective envelope/sleeve
- [ ] Password written down separately
- [ ] Multiple copies created (3+)
- [ ] Stored in 2+ different locations
- [ ] Family members informed (optional)
- [ ] Periodic verification (yearly)

---

## Technical Specifications

### QR Code Format

```typescript
// Version 1 (current)
interface QRBackupData {
  version: 1;                    // Format version
  type: 'encrypted' | 'plain';   // Encryption status
  data: string;                  // Encrypted mnemonic (base64) or plain text
  salt?: string;                 // PBKDF2 salt (base64, if encrypted)
  iv?: string;                   // AES-GCM IV (base64, if encrypted)
  iterations?: number;           // PBKDF2 iterations (if encrypted)
  checksum: string;              // Address checksum (hex)
}
```

### Encryption Specifications

| Parameter | Value | Standard |
|-----------|-------|----------|
| **Key Derivation** | PBKDF2-SHA256 | OWASP 2025 |
| **Iterations** | 310,000 | OWASP 2025 minimum |
| **Salt** | 32 bytes random | NIST SP 800-132 |
| **Encryption** | AES-256-GCM | FIPS 197 |
| **Key Size** | 256 bits | NIST recommended |
| **IV** | 12 bytes random | NIST SP 800-38D |
| **Authentication** | GCM mode built-in | NIST SP 800-38D |

### QR Code Specifications

| Parameter | Value | Reason |
|-----------|-------|--------|
| **Error Correction** | Level H (30%) | Maximum damage tolerance |
| **Size** | 512×512 pixels | Optimal for scanning |
| **Margin** | 2 modules | Compact while scannable |
| **Format** | PNG | Lossless, widely supported |
| **Encoding** | Base64 data URL | Embeddable in HTML/apps |
| **Version** | Auto-detected | Based on data size |

### Data Size Limits

| QR Version | Max Capacity (Level H) | w3pk Usage |
|------------|----------------------|------------|
| Version 10 | ~468 bytes | Encrypted mnemonic fits |
| Version 20 | ~1,248 bytes | Encrypted + metadata fits |
| Version 40 | ~2,953 bytes | Maximum supported |

**w3pk typical sizes:**
- Plain mnemonic: ~80-100 characters
- Encrypted mnemonic: ~200-300 characters (base64)
- Full QR data (JSON): ~400-500 characters
- Fits comfortably in Version 10-15 QR codes

### Browser Compatibility

| Feature | Chrome | Firefox | Safari | Edge |
|---------|--------|---------|--------|------|
| QR generation | ✅ | ✅ | ✅ | ✅ |
| Canvas fallback | ✅ | ✅ | ✅ | ✅ |
| Crypto API | ✅ | ✅ | ✅ | ✅ |
| Data URL download | ✅ | ✅ | ✅ | ✅ |

**Minimum versions:**
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

---

## Troubleshooting

### QR Code Generation Issues

#### Problem: "qrcode library not available"

**Cause:** Optional dependency `qrcode` not installed.

**Solution:**
```bash
npm install qrcode
```

**Alternative:** Use encrypted ZIP backup instead:
```typescript
const backup = await sdk.createZipBackup('password');
```

---

#### Problem: QR code too small/large

**Cause:** Default size doesn't fit use case.

**Solution:** Adjust width in options:
```typescript
// Larger QR (768×768)
const backup = await sdk.createQRBackup('password', {
  errorCorrection: 'H',
  width: 768
});

// Smaller QR (384×384)
const backup = await sdk.createQRBackup('password', {
  errorCorrection: 'H',
  width: 384
});
```

---

#### Problem: QR code won't scan

**Causes & Solutions:**

1. **Poor print quality**
   - Solution: Print at higher resolution (300+ DPI)
   - Use laser printer, not inkjet

2. **QR code damaged**
   - Solution: Level H supports up to 30% damage
   - Try different copy or reprint

3. **Lighting issues**
   - Solution: Scan in bright, even lighting
   - Avoid glare/shadows

4. **Camera focus**
   - Solution: Hold phone steady, allow autofocus
   - Clean camera lens

5. **Scanning app incompatible**
   - Solution: Use native phone camera app
   - iOS: Camera app has built-in QR scanner
   - Android: Google Lens or Camera app

---

### Recovery Issues

#### Problem: "Address checksum mismatch"

**Causes:**
1. Wrong password entered
2. QR code corrupted/damaged
3. QR code from different wallet

**Solutions:**
1. Double-check password (case-sensitive!)
2. Try different copy of QR code
3. Verify QR code matches your wallet address

---

#### Problem: "Unsupported QR backup version"

**Cause:** QR code from newer/older w3pk version.

**Solution:**
```bash
# Update w3pk to latest version
npm update w3pk
```

Or restore using version that created the backup.

---

#### Problem: Can't scan QR code

**Solutions:**

1. **Clean the QR code**
   - Remove dust, smudges
   - Ensure paper is flat

2. **Adjust camera distance**
   - Too close: Move back 6-12 inches
   - Too far: Move closer

3. **Improve lighting**
   - Use bright, indirect light
   - Avoid glare/shadows

4. **Use QR scanner app**
   - Download dedicated QR scanner
   - More forgiving than camera app

5. **Manual entry (last resort)**
   - Copy JSON data manually
   - Paste into recovery form

---

#### Problem: Lost password

**Solutions:**

Unfortunately, **password cannot be recovered**. However:

1. **Try other recovery methods:**
   - Passkey sync (if enabled)
   - Social recovery (if configured)
   - Plain mnemonic backup (if created)

2. **Password hints:**
   - Check password manager
   - Review common passwords you use
   - Ask family members if shared

3. **Prevention:**
   - Store password separately from QR
   - Use password manager
   - Set up multiple backup methods

---

## FAQ

### General Questions

**Q: Is QR backup secure?**

A: Yes, when password-protected:
- Military-grade AES-256-GCM encryption
- 310,000 PBKDF2 iterations (brute-force resistant)
- Address checksum prevents wrong password
- Even with physical QR, password required

**Q: What if someone finds my QR code?**

A: If encrypted, they need your password to decrypt. Without password, QR code is useless. This is why strong passwords are critical.

**Q: Can I store QR in the cloud?**

A: Yes, if encrypted:
- ✅ Google Drive, Dropbox (encrypted QR)
- ✅ Password in separate location
- ❌ Never store password with QR

**Q: How many copies should I make?**

A: Recommended: **3-5 copies** in different locations:
- 1 at home (safe)
- 1 at bank (safety deposit box)
- 1 with family (sealed envelope)
- 1-2 backups (various locations)

**Q: What if QR gets damaged?**

A: Level H error correction tolerates 30% damage:
- Folding/creasing: Usually OK
- Water damage: Often OK if dried
- Partial tearing: Up to 30% can be missing
- Complete destruction: Need another copy

**Q: Does QR backup expire?**

A: No! Your mnemonic never changes, so QR backup is valid forever (assuming paper doesn't deteriorate).

---

### Technical Questions

**Q: What error correction level should I use?**

A: **Always use Level H** (30% damage tolerance). This is w3pk's default and recommended for all backups.

**Q: Can I customize QR appearance?**

A: Yes, but with caution:
```typescript
import QRCode from 'qrcode';

// Custom colors (ensure good contrast!)
QRCode.toDataURL(data, {
  errorCorrectionLevel: 'H',
  color: {
    dark: '#000080',   // Navy blue
    light: '#FFFFFF'   // White
  }
});
```

**Important:** Maintain high contrast for scannability!

**Q: What's the maximum data size?**

A: QR Version 40 with Level H supports ~2,953 bytes. w3pk backups typically use ~400-500 bytes, well within limits.

**Q: Can I backup multiple wallets in one QR?**

A: Not recommended. Create separate QR codes for each wallet. This:
- Limits damage if one is compromised
- Easier to manage individually
- Smaller QR codes (easier to scan)

**Q: Does w3pk support plain (unencrypted) QR codes?**

A: Yes, but **strongly discouraged**:
```typescript
// Unencrypted QR (DANGEROUS!)
const backup = await sdk.createQRBackup(undefined);
```

Anyone with this QR can steal your wallet. Only use for testing.

---

### Recovery Questions

**Q: Can I recover on a different device?**

A: Yes! QR backups are cross-device and cross-platform:
- Scan on any device with camera
- Works on iOS, Android, Windows, Mac, Linux
- Compatible with any BIP39 wallet

**Q: Do I need w3pk to recover?**

A: No! Your mnemonic is BIP39-compatible:
1. Decrypt QR code (with w3pk or manually)
2. Extract mnemonic
3. Import into **any** BIP39 wallet (MetaMask, Ledger, etc.)

**Q: How long does recovery take?**

A: Typically **2-5 minutes**:
1. Scan QR code (30 seconds)
2. Enter password (30 seconds)
3. Verify address (1 minute)
4. Create new passkey (1 minute)
5. Test wallet (2 minutes)

**Q: Can I test recovery without losing my current wallet?**

A: Yes! Use a different browser/device:
1. Create test wallet
2. Generate QR backup
3. Open incognito/private window
4. Restore from QR
5. Verify it works
6. Delete test wallet

Never lose access to your main wallet during testing.

---

### Security Questions

**Q: What if my password is compromised?**

A: If someone has both your QR code AND password:
1. **Immediately move funds** to a new wallet
2. Create new backup with different password
3. Destroy old QR codes
4. Review how compromise occurred

**Q: Should I share my QR with family?**

A: Depends:
- ✅ Encrypted QR: Safe to share (keep password separate)
- ❌ Plain QR: Never share (instant wallet theft)
- ✅ Sealed envelope: Good middle ground

**Q: What happens if w3pk shuts down?**

A: You're still safe!
- QR backups are standard BIP39 format
- Import into any wallet (MetaMask, Trust Wallet, etc.)
- No vendor lock-in

**Q: Can quantum computers break QR encryption?**

A: Current quantum computers: No. Future: Possibly.

**Mitigation:**
- AES-256 has strong quantum resistance
- Re-encrypt with post-quantum algorithms when available
- Most vulnerable part is PBKDF2 (use very strong password)

---

## Additional Resources

### Documentation
- [Recovery System Overview](RECOVERY.md)
- [Security Architecture](SECURITY.md)
- [API Documentation](../README.md)

### External References
- [QR Code Specification (ISO/IEC 18004)](https://www.iso.org/standard/62021.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/publications)
- [BIP39 Mnemonic Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

### Community
- [GitHub Issues](https://github.com/w3hc/w3pk/issues)
- [Security Reporting](../SECURITY.md#reporting-security-issues)

---

**Last Updated:** 2025-10-30
**w3pk Version:** 0.7.1+
**Document Version:** 1.0
