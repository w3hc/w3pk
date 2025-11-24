# Changelog

All notable changes to the w3pk SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **W3C WebAuthn Compliance Improvements**: Enhanced security with signature counter validation and RP ID hash verification
  - **Signature Counter Validation**: Detects cloned authenticators by verifying counter increases with each use
  - **RP ID Hash Verification**: Prevents phishing attacks by cryptographically verifying authentication origin
  - Added `signCount` field to `StoredCredential` interface for counter tracking
  - Added `updateSignatureCounter()` method to storage for counter updates
  - Added `arrayEquals()` utility for secure byte array comparison
  - Compliance score improved from 85/100 to 95/100
  - Fully backward compatible - existing credentials continue to work
  - Comprehensive test suite added ([test/security-validation.test.ts](./test/security-validation.test.ts)) with 9 passing tests
  - See W3C WebAuthn Level 2 specification sections 6.1 (Authenticator Data) and 7.1 (Verification)

- **CRITICAL: Removed Dangerous Exports**: Fixed security vulnerabilities that allowed applications to access sensitive key material
  - Removed `generateBIP39Wallet` export - prevented apps from generating raw mnemonics
  - Removed `deriveWalletFromMnemonic` export - prevented arbitrary private key access
  - Removed `createWalletFromMnemonic` export - prevented mnemonic manipulation
  - Removed `deriveStealthKeys` export - prevented direct stealth key access
  - Removed `getOriginSpecificAddress` export - prevented bypassing origin restrictions
  - Removed `BackupManager`, `SocialRecoveryManager`, `VaultSync` exports - prevented direct manager access
  - Applications now **CANNOT** access master mnemonic or MAIN tag private keys
  - Applications can only access non-MAIN tagged wallet private keys (e.g., 'GAMING', 'TRADING')
  - All sensitive operations must go through SDK methods with proper authentication

- **Enhanced Security Model**:
  - MAIN tag wallets: Address only (no private key exposure)
  - Non-MAIN tag wallets: Full access for app-specific use cases
  - Stealth addresses: Opt-in with documented security implications
  - `exportMnemonic()`: Permanently disabled, throws error
  - `deriveWallet()`: Removed index-based derivation, only supports origin-specific tags

### Added

- **Credential Checking Methods**: New methods to prevent accidental multiple wallet creation
  - `hasExistingCredential()` - Check if any wallets exist on device (returns boolean)
  - `getExistingCredentialCount()` - Get count of existing wallets (returns number)
  - `listExistingCredentials()` - List all wallets with metadata (username, address, timestamps)
  - Especially important for iOS/macOS where multiple passkeys can sync via iCloud and cause user confusion
  - Applications can now implement warning dialogs before allowing multiple wallet creation
  - Comprehensive test suite added ([test/credential-checking.test.ts](./test/credential-checking.test.ts)) with 12 passing tests
  - Documentation added to [Integration Guidelines](./docs/INTEGRATION_GUIDELINES.md#check-for-existing-wallet-first), [API Reference](./docs/API_REFERENCE.md), [Security Architecture](./docs/SECURITY.md#multiple-wallet-management), and [CONTRIBUTING.md](./CONTRIBUTING.md)
  - Recommended patterns for both simple auto-login and advanced warning flows

- **Build Verification**: IPFS CIDv1 hash computation for package integrity verification
  - `getCurrentBuildHash()` - Get hash for installed version from CDN
  - `getW3pkBuildHash(url)` - Compute hash from any dist URL
  - `verifyBuildHash(hash)` - Verify against trusted hash
  - `getPackageVersion()` - Get current package version
  - CLI script: `pnpm build:hash` to compute build hash
  - Uses official IPFS libraries (`ipfs-unixfs-importer`, `blockstore-core`)
  - Generates proper IPFS CIDv1 with UnixFS format
  - Browser-compatible (Web Crypto API)
  - Optional dependencies - won't bloat projects that don't need verification
  - Comprehensive documentation in [BUILD_VERIFICATION.md](./docs/BUILD_VERIFICATION.md)
  - Example usage in [examples/verify-build-hash.ts](./examples/verify-build-hash.ts)

### Fixed

- **WebAuthn Registration**: Fixed user.id encoding issue that caused registration failures
  - `user.id` now properly base64url-encoded before passing to WebAuthn
  - Previously passed plain string was being incorrectly decoded by SimpleWebAuthn
  - Fixes registration issues with usernames of all lengths (particularly noticeable with 9-character usernames)
  - No impact on existing credentials or encrypted metadata

### Added

- **Username Validation**: Usernames now support hyphens in addition to alphanumeric and underscores
  - Valid characters: letters (a-z, A-Z), numbers (0-9), underscores (_), hyphens (-)
  - Must start and end with alphanumeric character (not hyphen or underscore)
  - Examples: `web3-user`, `my-user_123`, `test-user-9`
  - Updated validation error message to reflect new rules
  - Added comprehensive test suite for username validation (32 test cases)
  - Added username encoding tests (12 test cases)

### Changed

- **Username Validation**: Updated to enforce character restrictions
  - Previous: Only checked length (3-50 characters)
  - Now: Checks length AND allowed characters with proper start/end validation
- Updated API documentation to reflect new username rules
- Improved login compatibility on Firefox Mobile and other browsers with discoverable credential issues
  - Added `allowCredentials` list to authentication options as a hint when stored credentials exist
  - Browsers can now locate credentials even when discoverable credential discovery fails
  - Enhanced error messages to guide users when credentials are not available on device
  - Graceful fallback maintains compatibility with browsers that support discoverable credentials

- **BREAKING:** Standardized date format to ISO 8601 (e.g., `2025-11-07T10:37:00Z`) across entire codebase
  - All timestamp fields now use ISO 8601 string format instead of millisecond numbers
  - Affects: `createdAt`, `lastUsed`, `lastActive`, `expiresAt`, `updatedAt`, `addedAt`, `lastVerified`, `lastSyncTime`, and all other timestamp fields
  - Updated type definitions in: `StoredCredential`, `EncryptedCredential`, `EncryptedWalletData`, `SessionData`, `SyncVault`, `DeviceInfo`, `Guardian`, `SocialRecoveryConfig`, `BackupMetadata`, `ZKProof`, `VerificationResult`, and all backup types
  - Session management, device tracking, backup metadata, and ZK proofs now use ISO 8601 format
  - **No backward compatibility** - existing stored data with numeric timestamps will need to be cleared
  - Date comparisons updated to handle ISO 8601 string format throughout the codebase

### Migration from Previous Versions

Users upgrading to this version will need to:
1. Clear all stored credentials and wallets
2. Re-register their accounts
3. Reconfigure social recovery (if previously set up)
4. Recreate backups

This is necessary because the timestamp format has changed from numeric to ISO 8601 string format.

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
