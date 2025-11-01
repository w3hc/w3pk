# Changelog

All notable changes to the w3pk SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.5] - 2025-11-01

### Fixed

- **CRITICAL:** Fixed "Derivation failed" error on mobile and desktop
  - Public key is now properly stored in encrypted credentials (was returning empty string)
  - Public key is required for `deriveEncryptionKeyFromWebAuthn()` to derive encryption keys
  - This was causing all wallet operations (deriveWallet, signMessage, etc.) to fail
  - Updated `EncryptedCredential` interface to include `publicKey` field

### Changed

- Updated `EncryptedCredential` storage format:
  - Now stores: `publicKey` (needed for key derivation) AND `publicKeyFingerprint` (for verification)
  - Previous broken v0.7.4 format only stored fingerprint, causing key derivation to fail

### Migration from v0.7.4

If you registered with v0.7.4 (released earlier today), you will need to:
1. Clear your credentials
2. Re-register

This is because v0.7.4 credentials don't have the public key stored, making them unusable.

**Note:** Public keys are non-sensitive cryptographic material and are safe to store in localStorage.

## [0.7.4] - 2025-11-01 (BROKEN - DO NOT USE)

### Known Issues

- **CRITICAL BUG:** Public key not stored in credentials, causing all wallet operations to fail
  - This version is broken and should not be used
  - Upgrade to v0.7.5 immediately

### Added

- **Security:** Metadata encryption in localStorage to prevent XSS correlation attacks
  - Usernames and Ethereum addresses are now AES-256-GCM encrypted
  - Credential IDs are SHA-256 hashed to prevent enumeration
  - ~~Public keys replaced with SHA-256 fingerprints~~ (BUG: This broke key derivation)
  - New `EncryptedCredential` interface for encrypted storage format

- **Crypto utilities** in `src/wallet/crypto.ts`:
  - `hashCredentialId()` - SHA-256 hashing for credential IDs
  - `hashPublicKey()` - SHA-256 fingerprinting for public keys
  - `encryptMetadata()` - AES-GCM encryption for credential metadata
  - `decryptMetadata()` - AES-GCM decryption for credential metadata

- **Key derivation** function `deriveMetadataKey()`:
  - Uses PBKDF2-SHA256 with 100,000 iterations
  - Derives encryption keys from credential IDs
  - Fixed salt: `"w3pk-metadata-salt-v1"`

### Changed

- **BREAKING:** All `CredentialStorage` methods are now `async` and return Promises
  - `saveCredential()` → `async saveCredential()`
  - `getCredentialById()` → `async getCredentialById()`
  - `getCredentialByUsername()` → `async getCredentialByUsername()`
  - `getCredentialByAddress()` → `async getCredentialByAddress()`
  - `getAllCredentials()` → `async getAllCredentials()`
  - `userExists()` → `async userExists()`
  - `updateLastUsed()` → `async updateLastUsed()`
  - `deleteCredential()` → `async deleteCredential()`
  - `clearAll()` → `async clearAll()`

- **Performance:** Search operations by username/address are now O(n) instead of O(1)
  - Must decrypt all credentials to search by username or address
  - Direct ID lookups remain fast (O(1) with hashing overhead)

- Updated `src/auth/register.ts` to use async storage operations
- Updated `src/auth/authenticate.ts` to use async storage operations
- Updated `src/core/sdk.ts` to use async storage operations

### Security

**What this prevents:**
- XSS attacks can no longer read plaintext usernames from localStorage
- XSS attacks can no longer read plaintext Ethereum addresses from localStorage
- XSS attacks can no longer correlate user identities to wallet addresses
- Attackers cannot easily enumerate credentials via localStorage inspection

**What this doesn't prevent:**
- XSS attacks during active sessions (wallet in memory)
- File system access with credential IDs (can still decrypt metadata)

**Threat model before v0.7.4:**
```javascript
// XSS reads localStorage
const creds = JSON.parse(localStorage.getItem('w3pk_credential_abc'))
// Attacker sees: { username: "alice", ethereumAddress: "0x1234..." }
```

**Threat model after v0.7.4:**
```javascript
// XSS reads localStorage
const creds = JSON.parse(localStorage.getItem('w3pk_credential_hashed'))
// Attacker sees: { encryptedUsername: "v1kT...", encryptedAddress: "w2sQ..." }
// Cannot correlate without credential ID
```

### Migration

**BREAKING CHANGE:** No backward compatibility with v0.7.3 and earlier credentials.

Users must:
1. Export their mnemonic before upgrading to v0.7.4
2. Clear old credentials from localStorage
3. Re-register with the same mnemonic after upgrading
4. New encrypted storage format will be used automatically

This is intentional for security - we don't want to risk leaving plaintext metadata in storage.

### Documentation

- Added comprehensive "Metadata Encryption in LocalStorage (v0.7.4+)" section to `docs/SECURITY.md`
- Documented encryption details, threat model, and performance implications
- Updated security recommendations and attack scenario analysis

## [0.7.3] - 2025-10-31

### Fixed

- **Critical:** Fixed base64url decoding errors during registration that caused `Failed to execute 'atob' on 'Window': The string to be decoded is not correctly encoded` error
- Fixed backup encryption/decryption failures due to incorrect binary data encoding
- Fixed WebAuthn attestation object decoding with proper padding handling
- Fixed authentication signature verification with improved base64url support

### Added

- New `src/utils/base64.ts` module with robust base64/base64url utilities:
  - `base64UrlToArrayBuffer()` - Safely decodes base64url with automatic padding
  - `arrayBufferToBase64Url()` - Encodes to URL-safe base64url format
  - `safeAtob()` - Handles both base64 and base64url with proper padding
  - `safeBtoa()` - Handles Unicode text encoding safely

### Changed

- Updated all authentication modules to use new base64 utilities
- Updated crypto module to use consistent base64url encoding
- Improved error messages for base64 decoding failures

### Technical Details

The root cause was that WebAuthn responses use base64url encoding (URL-safe), which:
1. Removes `=` padding characters
2. Uses `-` and `_` instead of `+` and `/`

The native `atob()` function requires standard base64 with proper padding, causing decoding failures. The new utilities automatically handle padding and character conversion, making the SDK more robust when dealing with WebAuthn and other base64url-encoded data.

### Migration

No breaking changes. All existing code continues to work. The fixes are internal improvements to encoding/decoding routines.

## [0.7.2] - 2025-10-30

### Added

- Backup system with password-based encryption
- ZIP backup creation and restoration
- QR code backup support
- Social recovery features
- Security score calculation

## [0.7.1] - 2025-10-25

### Added

- Initial stealth address support (ERC-5564)
- ZK proof integration
- Chainlist API integration

## [0.7.0] - 2025-10-20

### Added

- WebAuthn-based authentication
- HD wallet derivation
- Session management
- Biometric wallet encryption

---

## Version History

- **0.7.5** - Critical fix for public key storage (current)
- **0.7.4** - Metadata encryption in localStorage (broken - do not use)
- **0.7.3** - Base64 handling improvements
- **0.7.2** - Backup system
- **0.7.1** - Stealth addresses & ZK proofs
- **0.7.0** - Initial release
