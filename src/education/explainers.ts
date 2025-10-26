/**
 * Educational Content
 * Explainers for users to understand security concepts
 */

export interface EducationalModule {
  title: string;
  content: string;
  visual?: string;
  interactive?: string;
}

export const educationalModules: Record<string, EducationalModule> = {
  whatIsPasskey: {
    title: 'What is a Passkey?',
    content: `
Think of a passkey like your house smart lock:

🔑 Traditional Key (Password):
- Can be stolen
- Can be forgotten
- Same key opens many doors
- Written on paper or in memory

🏠 Smart Lock (Passkey):
- Biometric only (your face/finger)
- Can't be stolen or forgotten
- Unique per device
- Auto-syncs to your other devices

HOW IT WORKS:
1. You create a passkey with your fingerprint
2. Your device stores it securely (hardware-protected)
3. It syncs to your other devices automatically
4. Only YOU can use it (with your biometric)

SECURITY:
- The private key never leaves your device
- Cannot be phished (checks website domain)
- Cannot be guessed or brute-forced
- Requires physical access to your device + your biometric
`,
    interactive: 'Try authenticating now →',
  },

  whatIsRecoveryPhrase: {
    title: 'What is a Recovery Phrase?',
    content: `
Your 12 words are like a master key to your cryptocurrency wallet.

🌱 12 Words = Your Entire Wallet:
- Generate unlimited accounts
- Sign transactions
- Prove ownership of funds
- Recover on ANY wallet app

HOW IT WORKS:
1. 12 random words from dictionary
2. Creates a "seed" using math
3. Seed generates your private keys
4. Private keys control your crypto

WHY 12 WORDS?
- 2^128 possible combinations
- Would take billions of years to guess
- Easy for humans to write down
- Works in any BIP39 wallet

CRITICAL SECURITY:
⚠️  Anyone with these words = OWNS your wallet
⚠️  Cannot be changed or reset
⚠️  Lost words = Lost wallet forever
⚠️  Store safely offline

BEST PRACTICES:
✓ Write on paper (offline)
✓ Store in safe/vault
✓ Never type in computer (except during setup)
✓ Never share with anyone
✓ Make encrypted backup (password-protected)
✓ Consider social recovery (split among friends)
`,
  },

  howDoesSyncWork: {
    title: 'How Does Passkey Sync Work?',
    content: `
Your passkey and wallet use TWO layers of protection:

LAYER 1: PASSKEY (Auto-Syncs)
------------------------------
Your passkey credential syncs via:
- iCloud Keychain (Apple)
- Google Password Manager (Android)
- Microsoft Account (Windows)

What syncs:
✓ Passkey credential
✓ Public key
✓ User info

What DOESN'T sync:
✗ Your 12-word mnemonic
✗ Private keys
✗ Wallet contents

LAYER 2: ENCRYPTED WALLET (Local)
----------------------------------
Your wallet is encrypted and stored in:
- Browser's IndexedDB
- Encrypted with passkey-derived key
- Can ONLY be decrypted with passkey

THE SYNC FLOW:

Device 1 (iPhone)    →    iCloud    →    Device 2 (Mac)
  Passkey created          Syncs         Passkey available
  Wallet encrypted         ----          Decrypt with passkey


WHAT THIS MEANS:
- Passkey syncs = Convenient
- Wallet encrypted = Secure
- Need both = Protected
- Works across devices = Seamless

SECURITY:
- Even if iCloud is hacked, wallet stays encrypted
- Even if wallet is copied, can't decrypt without passkey
- Both layers needed to access funds
`,
    visual: `
┌─────────────────────────────────────────────┐
│  DEVICE 1                  DEVICE 2         │
│                                             │
│  🔑 Passkey ──────┐    ┌───── 🔑 Passkey   │
│                   │    │                    │
│  🔒 Wallet    ◄───┼────┼───► 🔒 Wallet     │
│  (encrypted)      │    │     (encrypted)    │
│                   │    │                    │
│              ☁️  iCloud  ☁️                  │
│             (passkey syncs)                 │
└─────────────────────────────────────────────┘
`,
  },

  whyBackupMatters: {
    title: 'Why Backup Matters',
    content: `
Cryptocurrency is PERMANENT. There's no "reset password" button.

REAL SCENARIOS:
---------------

💸 James lost $7.4M in Bitcoin
   - Hard drive thrown away
   - No backup
   - Bitcoin lost forever

💸 Stefan lost $200K in Ethereum
   - Forgot password
   - No recovery phrase saved
   - Wallet locked permanently

💸 Maria recovered $500K
   - Phone stolen
   - Had encrypted backup
   - Recovered in 5 minutes ✓

THE MATH:
---------

No backup:
- Lose device = Lose wallet (100% loss)
- Forget password = Lose wallet (100% loss)
- Device breaks = Lose wallet (100% loss)

With backup:
- Lose device = Recover from backup ✓
- Forget password = Use recovery phrase ✓
- Device breaks = Use social recovery ✓

BACKUP LAYERS:
--------------

Layer 1: Passkey (convenience)
- Auto-syncs
- Easy to use
- Platform-dependent

Layer 2: Encrypted Backup (universal)
- Works anywhere
- Password-protected
- Portable

Layer 3: Social Recovery (ultimate)
- Friends help you
- No single point of failure
- Most secure

RECOMMENDATION:
Use ALL THREE for maximum security!
`,
  },

  socialRecoveryExplained: {
    title: 'Social Recovery Explained',
    content: `
Social recovery lets trusted friends/family help you recover your wallet.

HOW IT WORKS (3-of-5 Example):
------------------------------

1. Your 12-word phrase is split into 5 pieces
2. Each piece goes to a trusted guardian
3. Any 3 pieces can reconstruct your phrase
4. Any 2 pieces reveal NOTHING

THE MATH (Shamir Secret Sharing):
---------------------------------

Example: Secret = "apple"

Split into 5 shares:
- Share 1: "x7k9m"
- Share 2: "p2n4q"
- Share 3: "w8j3z"
- Share 4: "r5h1v"
- Share 5: "c6y2b"

Combine any 3 → Get "apple"
Have only 2 → Impossible to recover

CHOOSING GUARDIANS:
------------------

✓ GOOD Guardians:
- Family members
- Close friends
- Geographically distributed
- Tech-savvy
- Long-term relationships

✗ BAD Guardians:
- Strangers
- Same location (house fire risk)
- Not reliable
- Can't handle QR codes

SECURITY:
---------

Math proves:
- Need EXACTLY 3 shares
- 2 shares = 0% information
- 4 shares = 100% redundancy
- Guardians can't collude unless threshold met

RECOVERY FLOW:
-------------

1. You lose wallet access
2. Contact 3 guardians
3. Each provides their share
4. System combines shares
5. Wallet reconstructed ✓

Timeline: ~24 hours
(depends on guardian availability)
`,
  },

  encryptedBackupSecurity: {
    title: 'Encrypted Backup Security',
    content: `
Your encrypted backup uses military-grade encryption.

ENCRYPTION DETAILS:
------------------

Password → PBKDF2 (310,000 iterations)
         ↓
   256-bit AES Key
         ↓
   AES-256-GCM Encryption
         ↓
   Encrypted Backup

WHAT THIS MEANS:
---------------

310,000 iterations:
- Makes brute-force extremely slow
- Would take centuries to crack
- OWASP 2025 standard

AES-256-GCM:
- Used by governments/military
- Authenticated encryption
- Cannot be tampered with

ATTACK SCENARIOS:
----------------

Q: What if Google Drive is hacked?
A: Attacker gets encrypted file (useless without password)

Q: What if someone gets your password?
A: Need BOTH password AND backup file

Q: What if someone tries to brute-force?
A: 310,000 iterations makes this impractical

Q: Can the backup be tampered with?
A: No - GCM mode detects any changes

PASSWORD STRENGTH:
-----------------

WEAK (❌ Rejected):
- "password123"
- "qwerty"
- "12345678"

GOOD (✓ Accepted):
- "MyDog-Loves-Pizza-2025!"
- "Tr0ub4dor&3-Extra-Secure"
- "correct-horse-battery-staple-99"

STRONG (✓✓ Recommended):
- 16+ characters
- Mix of upper/lower/numbers/symbols
- Not in dictionary
- Unique to this backup

STORAGE OPTIONS:
---------------

✓ Safe to store encrypted backup in:
- Google Drive
- Dropbox
- iCloud
- USB drive
- Email to yourself

The encryption makes it safe even in cloud!
`,
  },
};

/**
 * Get explainer by topic
 */
export function getExplainer(topic: string): EducationalModule | null {
  return educationalModules[topic] || null;
}

/**
 * Get all explainer topics
 */
export function getAllTopics(): string[] {
  return Object.keys(educationalModules);
}

/**
 * Search explainers
 */
export function searchExplainers(query: string): EducationalModule[] {
  const lowerQuery = query.toLowerCase();
  return Object.values(educationalModules).filter(
    (module) =>
      module.title.toLowerCase().includes(lowerQuery) ||
      module.content.toLowerCase().includes(lowerQuery)
  );
}
