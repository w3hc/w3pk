# Changelog

All notable changes to the w3pk SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Cross-Device Wallet Sync via Passkey**: New `syncWalletWithPasskey()` SDK method for syncing a wallet to a new device using an existing cloud-synced passkey and a backup file
  - Two-step flow: prompts the user to select their synced passkey (iCloud/Google Password Manager), then uses it to decrypt the provided backup file
  - Supports all three backup encryption methods: `password`, `passkey`, and `hybrid`
  - After successful sync, re-encrypts the mnemonic for local storage, updates the current user, and starts a session — fully restoring authenticated state on the new device
  - New `src/auth/sync-auth.ts` module with exported `promptPasskeySelection()` and `authenticateWithPasskey()` helpers, and `PasskeySelectionResult` type

### Changed

- **Improved error message for cloud-synced passkeys**: When a passkey authenticates successfully but wallet data is not found locally (common on new devices with synced passkeys), the error now uses `AuthenticationError` with a clear, actionable message guiding the user to sync their account via the backup file flow
- **Code Quality Improvements**: Step 1 preparation and cleanup for backup system implementation
  - Removed debug `console.log` statements from authentication and SDK core modules
  - Improved code consistency across backup and recovery modules
  - Comprehensive code audit of backup (`src/backup/`) and recovery (`src/recovery/`) modules
  - All TypeScript types verified and properly exported

### Security

- **Fixed High Severity Vulnerability**: Resolved command injection vulnerability in transitive dependency
  - Updated `tsup` from 8.5.0 to 8.5.1 (fixes `glob@10.4.5` vulnerability)
  - Updated `tsx` from 4.20.6 to 4.21.0
  - `pnpm audit` now shows zero vulnerabilities
  - No production impact (devDependency only)

### Documentation

- Added `FLOPPY_DISK.md` - Complete implementation plan for "Floppy Disk" backup system
- Added `STEP1_AUDIT_REPORT.md` - Comprehensive code audit report with security findings
- Added `STEP1_SUMMARY.md` - Executive summary of Step 1 preparation phase
- Marked Step 1 (Preparation/Clean Up) as completed with all test results verified

## [0.8.8] - 2025-12-26

### Added

- **External Wallet Integration for EIP-7702**: Enable users to sign EIP-7702 authorizations using external wallets (MetaMask, Rabby, etc.)
  - New `requestExternalWalletDelegation()` SDK method for delegating external accounts to w3pk accounts
  - New `requestExternalWalletAuthorization()` low-level API for direct external wallet integration
  - Support for ENS account delegation to w3pk WebAuthn accounts
  - Multi-account delegation support (delegate multiple MetaMask accounts to single w3pk account)
  - Wallet provider detection utilities (`detectWalletProvider()`, `getDefaultProvider()`)
  - EIP-7702 support checking (`supportsEIP7702Authorization()`)
  - See [docs/EIP_7702.md](./docs/EIP_7702.md#external-wallets) for complete guide

- **EIP-7702 Utilities Module**: Shared encoding and verification functions
  - `encodeEIP7702AuthorizationMessage()` - Encode authorization messages according to EIP-7702 spec
  - `hashEIP7702AuthorizationMessage()` - Hash authorization messages for signing
  - `verifyEIP7702Authorization()` - Verify authorization signatures
  - Ensures consistency across all EIP-7702 implementations (internal and external wallets)
  - Proper EIP-7702 format: `0x05 || rlp([chain_id, address, nonce])`

### Changed

- **Updated `signAuthorization()` Method**: Now uses shared EIP-7702 utilities for consistent encoding
  - Same authorization format as external wallet authorizations
  - Improved signature verification
  - Better error messages for debugging

### Documentation

- Updated [EIP_7702.md](./docs/EIP_7702.md) with comprehensive external wallet integration guide
  - Added "External Wallets" section with use cases and examples
  - ENS delegation workflow documentation
  - Multi-account delegation examples
  - Hardware wallet and WalletConnect integration patterns
  - Security considerations for external wallets
- Updated [README.md](./README.md) with `requestExternalWalletDelegation()` example
- Added [examples/ens-to-w3pk-delegation.ts](./examples/ens-to-w3pk-delegation.ts) with multiple integration patterns

### Examples

- New ENS delegation example with 4 usage patterns:
  - Basic: Simple ENS → w3pk delegation
  - Advanced: Direct API usage with full control
  - Multi: Delegate multiple MetaMask accounts
  - Full: Complete real-world workflow

## [0.8.7] - 2025-12-06

### Added

- **Multiple Signing Methods**: Support for EIP-191, SIWE (EIP-4361), EIP-712, and rawHash
  - **EIP-191 (default)**: Standard Ethereum signed messages with prefix
  - **SIWE (EIP-4361)**: Sign-In with Ethereum compliant Web3 authentication
  - **EIP-712**: Structured typed data signing for permits, voting, meta-transactions
  - **rawHash**: Sign raw 32-byte hashes for Safe multisig and custom schemes
  - New `signingMethod` parameter in `signMessage()` options
  - EIP-712 requires additional options: `eip712Domain`, `eip712Types`, `eip712PrimaryType`
  - See [docs/API_REFERENCE.md](./docs/API_REFERENCE.md#signmessage) for details

- **SIWE Utilities**: Complete toolkit for Sign-In with Ethereum integration
  - `generateSiweNonce()`: Secure random nonce generation
  - `createSiweMessage()`: EIP-4361 compliant message construction
  - `parseSiweMessage()`: Parse SIWE messages into structured data
  - `validateSiweMessage()`: Validate message structure, expiration, domain
  - `verifySiweSignature()`: Verify EIP-191 signatures on SIWE messages
  - Full TypeScript types with `SiweMessage` interface
  - See [examples/siwe-login.ts](./examples/siwe-login.ts) for usage

### Fixed

- **Security Score Tracking**: Fixed security score calculation accuracy (#85)
- **Backup Restore Flow**: Fixed `restoreFromBackupFile` to properly handle encrypted backup restoration (#84)
- **EIP-7702 Authorization Signing**: Fixed `signAuthorization` method to correctly sign authorization tuples (#82)

### Documentation

- Updated [API Reference](./docs/API_REFERENCE.md) with comprehensive signing methods documentation
- Updated [Integration Guidelines](./docs/INTEGRATION_GUIDELINES.md) with signing method best practices
- Updated [README](./README.md) with signing methods feature list
- Added signing method examples and use case matrix

### Tests

- Added comprehensive test suite for signing methods (`test/sign-message.test.ts`)
  - EIP-191 signing and verification
  - SIWE message format and verification
  - EIP-712 typed data signing
  - rawHash validation and signing
  - Signature comparison tests
- Added SIWE utilities test suite (`test/siwe.test.ts`)
  - Nonce generation
  - Message creation and parsing
  - Validation (expiration, domain, chain ID)
  - Signature verification
  - Roundtrip consistency

## [0.8.6] - 2025-12-03

### Added

- **EIP-7951 PRIMARY Mode**: Sign messages directly with WebAuthn P-256 passkeys
  - New `signMessageWithPasskey()` method for PRIMARY mode message signing
  - Direct WebAuthn signature using P-256 curve (no private key exposure)
  - Returns signature components (r, s) and public key coordinates (qx, qy)
  - Compatible with EIP-7951 account abstraction wallets
  - Derives Ethereum address from P-256 public key using keccak256
  - See [docs/EIP-7951.md](./docs/EIP-7951.md) for implementation details

- **`getAddress()` Method**: Lightweight method to retrieve addresses without private key exposure
  - Get public addresses for any security mode (PRIMARY, STANDARD, STRICT, YOLO)
  - Supports tag-based address derivation
  - Perfect for UI display and address verification
  - Never exposes private keys, even in YOLO mode
  - Example: `const addr = await w3pk.getAddress('PRIMARY')`
  - See [docs/API_REFERENCE.md](./docs/API_REFERENCE.md#getaddress) for details

- **Exported Utilities**: Base64 and cryptographic utilities now publicly available
  - **Base64 Utilities**: `base64UrlToArrayBuffer`, `base64UrlDecode`, `arrayBufferToBase64Url`, `base64ToArrayBuffer`, `safeAtob`, `safeBtoa`
  - **Crypto Utilities**: `extractRS` - Extract r and s values from DER-encoded ECDSA signatures with low-s normalization

### Documentation

- Added comprehensive [EIP-7951 Implementation Guide](./docs/EIP-7951.md)
- Updated [API Reference](./docs/API_REFERENCE.md) with `signMessageWithPasskey()` method and exported utilities
- Updated [README](./README.md) with EIP-7951 PRIMARY mode examples

### Tests

- Added comprehensive test suite for EIP-7951 PRIMARY mode (`test/eip7951.test.ts`)
  - Tests for `extractRS()`: DER signature parsing, padding handling, and low-s normalization
  - Tests for base64 utilities: encoding/decoding, URL-safe characters, round-trip conversion
  - Tests for `deriveAddressFromP256PublicKey()`: address derivation, determinism, EIP-7951 compliance
  - Integration tests simulating full PRIMARY mode signature flow
  - Edge case tests for empty buffers, large buffers, and minimal signatures

## [0.8.2] - 2025-11-27

### Added

- **Persistent Sessions**: Added "Remember Me" functionality for STANDARD and YOLO modes
  - New `persistentSession` configuration option in `Web3PasskeyConfig`
  - Sessions can now survive page refreshes when enabled
  - Encrypted storage in IndexedDB using WebAuthn-derived keys
  - Configurable duration (default: 7 days) and reauth behavior
  - STRICT mode sessions are NEVER persisted for maximum security
  - Added `PersistentSessionStorage` class for encrypted session management
  - Added `PersistentSessionConfig` interface with `enabled`, `duration`, and `requireReauth` options
  - Added `restoreFromPersistentStorage()` method to SessionManager
  - Updated `startSession()` to optionally persist sessions for STANDARD/YOLO modes
  - Updated `clearSession()` to clear both RAM and persistent sessions
  - Added comprehensive tests in `test/persistent-session.test.ts`
  - See [PERSISTENT_SESSION_IMPLEMENTATION.md](./PERSISTENT_SESSION_IMPLEMENTATION.md) for full details

### Changed

- **Session Manager**: Enhanced to support both in-memory and persistent sessions
  - `startSession()` now accepts `ethereumAddress`, `publicKey`, and `securityMode` parameters
  - `clearSession()` now accepts optional `ethereumAddress` parameter and returns `Promise<void>`
  - Added security mode tracking in SDK via `currentSecurityMode` property
  - `getMnemonicFromSession()` now accepts optional `securityMode` parameter

### Documentation

- Updated [API_REFERENCE.md](./docs/API_REFERENCE.md) with persistent session configuration and usage
- Updated [INTEGRATION_GUIDELINES.md](./docs/INTEGRATION_GUIDELINES.md) with session management best practices
- Updated [SECURITY.md](./docs/SECURITY.md) with persistent session security model
- Added [PERSISTENT_SESSION_IMPLEMENTATION.md](./PERSISTENT_SESSION_IMPLEMENTATION.md) implementation guide

## [0.8.1] - 2025-11-26

### Fixed

- **Build Verification**: Fixed `getPackageVersion()` function to properly read version from package.json
  - Now uses `require('../../package.json').version` to get actual package version at build time
  - Removed hardcoded fallback version that was returning outdated '0.7.6' value
  - Function now throws error if package.json cannot be read instead of silently returning wrong version
  - Affects build hash verification and version checking functionality
  - Updated documentation in [API_REFERENCE.md](./docs/API_REFERENCE.md), [BUILD_VERIFICATION.md](./docs/BUILD_VERIFICATION.md), [INTEGRATION_GUIDELINES.md](./docs/INTEGRATION_GUIDELINES.md), and [SECURITY.md](./docs/SECURITY.md)

## [0.8.0] - 2025-11-01

### Removed

- **ZIP Backup System**: Removed redundant ZIP backup functionality in favor of simpler backup file approach
  - Removed `ZipBackupCreator` class and all ZIP-related code
  - Removed `createZipBackup()` and `restoreFromZipBackup()` methods
  - Removed `ZipBackupOptions` interface
  - Updated backup types to remove `'zip'` from method unions
  - The new `BackupFileManager` provides simpler JSON-based backup files with password/passkey/hybrid encryption
  - QR code backups remain fully supported
  - **Migration**: Users should use the new backup file system or QR codes for portable backups

### Documentation

- **Consolidated Backup Documentation**: Merged `docs/BACKUP_SYSTEM.md` and `docs/WORKFLOWS.md` into `docs/RECOVERY.md`
  - Single comprehensive source for all backup and recovery workflows
  - Clearer distinction between passkey sync and manual backup requirements
  - Enhanced explanation of cross-device sync, password backups, and social recovery
  - Updated all documentation references to use "portable" instead of outdated terminology

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

- **0.8.7** - Multiple signing methods (EIP-191, SIWE, EIP-712, rawHash), SIWE utilities (current)
- **0.8.6** - EIP-7951 PRIMARY mode, exported utilities
- **0.8.2** - Persistent sessions ("Remember Me")
- **0.8.1** - Fixed `getPackageVersion()` function
- **0.8.0** - Major cleanup: removed ZIP backups, simplified backup/recovery, removed dangerous exports
- **0.7.5** - Critical fix for public key storage
- **0.7.4** - Metadata encryption in localStorage (broken - do not use)
- **0.7.3** - Base64 handling improvements
- **0.7.2** - Backup system
- **0.7.1** - Stealth addresses & ZK proofs
- **0.7.0** - Initial release
