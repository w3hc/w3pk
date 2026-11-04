# Changelog

All notable changes to the w3pk SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **`pnpm audit --prod` reports only the `elliptic` advisory** ([#277](https://github.com/w3hc/w3pk/issues/277)). `pnpm.overrides` raise `brace-expansion` to `>=5.0.12` and `minimatch` to `>=11.0.1` in `snarkjs > ejs > jake > filelist`, which clears 7 denial-of-service advisories. None of them reached the browser bundle. `elliptic`, through `circomlibjs > ethers@5`, has no patched version
- **No exported function returns the passkey's PRF output** ([#260](https://github.com/w3hc/w3pk/issues/260)). `promptPasskeySelection()` evaluated the PRF at `PRF_INPUT` and returned it as `prfOutput`, the input to `deriveWalletKey()`, so an app could decrypt the stored mnemonic after one prompt that looked like a normal sign-in
  - `promptPasskeySelection()` and `PasskeySelectionResult` are no longer exported; `syncWalletWithPasskey()` still uses them internally
  - `authenticateWithPasskey()` is removed: it didn't request the PRF, but nothing used it
  - `test/security-restrictions.test.ts` checks neither name is exported
- **`sessionDuration: 0` caches nothing** ([#261](https://github.com/w3hc/w3pk/issues/261)). The constructor passed `config.sessionDuration || 1`, so 0 became a one-hour session and the mnemonic stayed in memory, although `docs/SECURITY.md` recommends 0 to force a prompt on every operation
  - The constructor keeps 0 (`??`), and `SessionManager` keeps no in-memory session when the duration is 0, including after a persistent-session restore
  - A session counts as expired from its expiry time (`>=`), in one shared check
  - `test/session-duration.test.ts` covers it
- **No tag on one origin derives another origin's key** ([#262](https://github.com/w3hc/w3pk/issues/262)). Origin keys sat at `m/44'/60'/0'/0/{index}` with a 31-bit `index` from `SHA-256(origin:mode:tag)`, so an app could search about 2^31 tags for one that gave another origin's index, and its private key in YOLO mode
  - **Every origin address changes** (STANDARD, STRICT and YOLO, every tag). There is no migration: move funds off the old addresses with w3pk v0.11.1 before upgrading. The registration address at `m/44'/60'/0'/0/0` doesn't change
  - Origin keys are derived at `m/13'/A'/B'/C'/D'/mode'/tag'`, every level hardened: `A'..D'` are the [SLIP-0013](https://github.com/satoshilabs/slips/blob/master/slip-0013.md) identity of the normalized origin (first 16 bytes of `SHA-256(LE32(0) ‖ origin)`), `mode'` is `STANDARD`=0', `STRICT`=1', `YOLO`=2', `PRIMARY`=3', `tag'` is 31 bits of `SHA-256(TAG)`. A leaked YOLO key no longer reveals its parent or sibling keys, which closes the non-hardened-path note in `docs/SECURITY.md`
  - `deriveIndexFromOriginModeAndTag()` is replaced by `deriveOriginPath()`, which returns the path; `getOriginSpecificAddress()` and `deriveWallet()` return `path` instead of `index`
  - `deriveWalletFromPath(mnemonic, path)` derives at a full path and throws on a missing or malformed one
  - `test/origin-derivation.test.ts` has path and address vectors and checks that no mode or tag on one origin reaches another origin's path
- **ML-KEM keys no longer come from the signing key** ([#263](https://github.com/w3hc/w3pk/issues/263)). `deriveMLKemKeypair` ran HKDF over the origin's secp256k1 private key, the key the app signs with. Once that address signs anything its public key is public, a quantum computer can recover the private key, and every recorded payload sealed to it decrypts, so the hybrid added no post-quantum protection
  - **Every ML-KEM key changes**, for every origin, mode, tag and context. Payloads sealed to the old keys can't be decrypted. There is no migration: decrypt what you need with w3pk v0.11.1 and re-encrypt after upgrading
  - The KEM keys come from the 64-byte BIP-39 seed through hash functions only: HKDF-SHA256 with salt `w3pk-kem-keypair-v4`, and in each info the purpose, the normalized origin, the mode, the uppercased tag and the context, each with a 4-byte length prefix. No secp256k1 key enters the derivation
  - `deriveMLKemKeypair(seed, { origin, mode?, tag?, context? })` replaces `deriveMLKemKeypair(privateKey, context?)`; `mlkemEncryptWithKey` and `mlkemDecryptWithKey` take the seed and the same options. `MLKemDerivationOptions` is exported
  - `w3pk.deriveMLKemPublicKey()`, `w3pk.mlkemEncrypt()` and `w3pk.mlkemDecrypt()` derive from the session mnemonic's seed, the current origin, the mode and the tag
  - `test/mlkem.test.ts` reproduces the derivation from the seed alone and checks separation across origin, mode, tag and context
- **The offline mnemonic extractor loads no remote script** ([#264](https://github.com/w3hc/w3pk/issues/264)). `standalone/extract-mnemonic.html` loaded ethers 5.7.2 from `cdn.ethers.io`, without SRI, in the page where the user types the backup password and reads the mnemonic
  - `pnpm build:standalone` (`scripts/build-standalone.mjs`, was `build-standalone-argon2.mjs`) also inlines a bundle of `@noble/hashes` (PBKDF2, HMAC-SHA512, Keccak-256) and `@noble/curves` (secp256k1). The page derives the BIP-39 seed, BIP-32 keys and EIP-55 addresses with it
  - A Content-Security-Policy (`default-src 'none'`) blocks every request from the page
  - Origin wallets are derived at `m/13'/A'/B'/C'/D'/mode'/tag'`, as in [#262](https://github.com/w3hc/w3pk/issues/262); the page derived them at the old `m/44'/60'/0'/0/{index}`. Index wallets stay at `m/44'/60'/0'/0/{index}`, and index 0 is the registration address
  - `test/standalone-extract.test.ts` checks the page makes no request and doesn't use ethers, and that it derives the same paths, addresses and keys as the SDK
- **`syncWalletWithPasskey()` checks a known passkey's assertion** ([#265](https://github.com/w3hc/w3pk/issues/265)). On the password-backup path, the passkey selection's assertion was checked against a public key only when the device had no metadata for the passkey. When it had some, neither the signature nor the counter was checked before the stored wallet was replaced; #255 closed the same gap in `restoreFromBackupFile()`
  - With metadata, the assertion runs `verifyAssertion()`, `login()`'s check: signature against the stored public key, counter checked and saved. A failure throws `AuthenticationError` before anything stored changes
  - The PRF output is zeroed on any failure after the prompt, a wrong password included
  - `PasskeySelectionResult` (internal) drops `publicKey` and `ethereumAddress`; the stored metadata is read where it is checked
  - `test/fresh-device-sync.test.ts` covers a counter behind the stored one, a stored key from another passkey, the saved counter and a wrong password
- **A replaced wallet's persistent session is deleted** ([#266](https://github.com/w3hc/w3pk/issues/266)). When `importMnemonic()`, or a restore or sync with `allowAddressChange`, moved a passkey to another address, the previous wallet was deleted but its `w3pk_session_<address>` stayed in `localStorage`. With `requireReauth: false` the session key is stored next to it, so the replaced mnemonic stayed readable until logout or expiry (7 days by default)
  - The previous address's persistent session is deleted before anything is stored, so no later failure leaves it behind
  - `SessionManager.deletePersistentSession(address)` deletes one address's persistent session
  - `test/import-mnemonic.test.ts` and `test/restore-replace-wallet.test.ts` cover it
- **A SIWE message sent as bytes gets the domain check** ([#268](https://github.com/w3hc/w3pk/issues/268)). `signMessage()` checked the domain of an `EIP191` message that contains the SIWE header only when it was a string. `personal_sign` and `eth_sign` sign hex data as bytes, and viem and ethers send SIWE messages as hex, so through the EIP-1193 provider a SIWE message for another domain got signed
  - A byte message whose text contains the SIWE header is decoded as UTF-8 and checked like a string; one that isn't valid UTF-8 throws, so a verifier that decodes it leniently can't accept it unchecked
  - `test/sign-message.test.ts` and `test/eip1193-provider.test.ts` cover raw bytes and hex through `personal_sign` and `eth_sign`
- **Registration offers ES256 only and decodes the attestation as CBOR** ([#269](https://github.com/w3hc/w3pk/issues/269)). `pubKeyCredParams` offered RS256 (`-257`), but the public key was read by scanning the attestation bytes for the EC2 `x` and `y` patterns, with no check of `kty`, `alg` or `crv`: an RS256 authenticator left an orphan passkey, and a match inside an RSA modulus stored random bytes as the P-256 key
  - `pubKeyCredParams` lists ES256 (`-7`) only
  - `src/auth/cbor.ts` is a strict CBOR decoder for the subset WebAuthn uses (integers, byte and text strings, arrays, maps, `false`, `true`, `null`, definite lengths only); it refuses tags, floats, indefinite lengths, duplicate map keys and integers outside the safe range. No dependency is added
  - The attestation object is decoded as a map with `fmt`, `attStmt` and `authData`, instead of searching its bytes for the `authData` key
  - The COSE key must have `kty` 2 (EC2), `alg` -7, `crv` 1 (P-256) and 32-byte `x` and `y` forming a point on P-256; nothing but the authenticator extensions (when `ED` is set) may follow it
  - When registration fails after the passkey is created and before anything is stored, `PublicKeyCredential.signalUnknownCredential()` asks the authenticator to drop it, where the browser supports it
  - `test/cbor.test.ts`, `test/attestation-cose-key.test.ts` and `test/register-client-data.test.ts` cover it, including RS256, Ed25519, ES384, P-384, wrong coordinate lengths and an RSA modulus that contains the old scan pattern
- **Backup files authenticate their metadata, and guardian shares name a wrong share** ([#270](https://github.com/w3hc/w3pk/issues/270)). In BackupFile v3, AES-GCM covered only the mnemonic: `credential`, `username`, `prfSalt` and the Argon2id parameters could be edited without the restore noticing, so an edited file could make a fresh device trust another passkey or register another username. Guardian shares had no checksum, so a wrong share failed with an unclear error
  - **BackupFile v3 files and guardian shares made by 0.11.x are no longer accepted.** There is no migration: after upgrading, create a new backup (`createBackupFile()`, `exportForSync()`) and set up social recovery again on a device where the wallet is, and keep the old files and shares until then. Without such a device, decrypt a v3 password file with the [extractor at commit `b14c32c`](https://github.com/w3hc/w3pk/blob/b14c32c658cc740aff78a1bbdb1cdb75c3b15a87/standalone/extract-mnemonic.html), whose link `UnsupportedBackupVersionError` gives, and combine old shares with w3pk v0.11.1
  - BackupFile v4 (`version: 4`): every field but `encryptedMnemonic` is AES-GCM `additionalData`: the label `w3pk-backup-v4`, then `version`, `createdAt`, `encryptionMethod`, the Argon2id fields, `credential.id`, `credential.publicKey`, `prfSalt` and `username` in that order, each absent (`0x00`), a length-prefixed UTF-8 string or a 4-byte integer. Editing a field throws `CryptoError`, and a field the format doesn't define is rejected
  - `encryptData()` and `decryptData()` take optional `additionalData`
  - Guardian share files are `version: 2`, with `splitId` (16 random bytes per setup) and `checksum`, an unkeyed SHA-256 over the share and its labels. `recoverFromGuardians()` throws `InvalidGuardianShareError` (`code: 'GUARDIAN_SHARE_INVALID'`, `shareIndex`, `guardianName`) for a share that is corrupted or edited, from another setup, given twice or in the old format, before combining. A share edited on purpose with a recomputed checksum isn't named; the AES-GCM tag refuses the rebuilt file
  - `UnsupportedBackupVersionError.backupFileJson` is removed: no share format rebuilds an older file anymore
  - `standalone/extract-mnemonic.html` decrypts v4 files only, with the same additional data, and points v3 and v2 files to the tools that read them. `examples/w3pk_backup_example_2026-11-04.json` (v4, password `test-password`) replaces the v3 example
  - `test/backup-file.test.ts`, `test/social-recovery.test.ts` and `test/standalone-extract.test.ts` edit each metadata field, corrupt, rename and mix shares, and check v3 files are refused
- **`sendTransaction()` only sends through an endpoint the app set** ([#273](https://github.com/w3hc/w3pk/issues/273)). Without `rpcUrls` or a per-call `rpcUrl`, it fell back to the first HTTPS chainid.network endpoint and took the nonce, gas and fees from it, so a malicious public endpoint could make the user overpay or censor transactions
  - **Set `rpcUrls` for every chain you send on** (`createWeb3Passkey({ rpcUrls: { 1: ['https://...'] } })`) or pass `options.rpcUrl`. Otherwise `sendTransaction()`, and the EIP-1193 provider's `eth_sendTransaction`, throw `WalletError: Failed to send transaction: No RPC endpoint set for chainId <id>. Set rpcUrls in the config ...` before any passkey prompt, fetch or RPC request
  - The `Failed to send transaction` error appends its cause's message
  - `getEndpoints()` and `supportsEIP7702()` still list chainid.network endpoints after the app's: they only read
  - `test/send-transaction.test.ts` checks the error for no config, an empty list and another chain's endpoints, with no prompt and no fetch

### Changed

- **Stealth address math uses `@noble/curves`** ([#272](https://github.com/w3hc/w3pk/issues/272)). The hand-written secp256k1 point addition in `src/stealth/crypto.ts` didn't handle `P + (−P)`, and its `modInverse(0)` returned 0, so a degenerate sum gave a bogus key instead of an error
  - The stealth public key is `spending_pubkey + s_h × G` with the `@noble/curves` `Point` API; the point at infinity throws `CryptoError`. `addPublicKeys`, `modInverse`, `compressPublicKey` and `publicKeyToAddress` are removed
  - `s_h` is reduced, and added to the spending key, in the curve's scalar field; a zero stealth private key throws `CryptoError` instead of being returned
  - Keys and scalars are parsed as `0x` hex bytes, so an unprefixed key is refused instead of read as decimal
  - `test/stealth-point.test.ts` has a known vector and checks `P + (−P)` and a zero private key throw
- **`stealth.signTransaction()` states its cross-origin risk** ([#274](https://github.com/w3hc/w3pk/issues/274)). Stealth keys are the same for every origin, so any origin that enables `stealthAddresses` can sign any transaction from any of the user's stealth addresses, and the passkey prompt doesn't show the transaction
  - The JSDoc, `docs/API_REFERENCE.md`, `docs/SECURITY.md` and the README say so and link [#147](https://github.com/w3hc/w3pk/issues/147)

### Fixed

- **Two passkeys for one wallet both log in** ([#267](https://github.com/w3hc/w3pk/issues/267)). Wallet records were stored by address only (`w3pk_wallet_<address>`), so registering a second passkey for a wallet the device already held, with `registerWithBackupFile()` or a restore, replaced the first passkey's record, and logging in with the first passkey threw `WalletMissingError`
  - **Wallet records are stored under `w3pk_wallet_<credentialId>` and persistent sessions under `w3pk_session_<credentialId>`.** Records stored under an address are not read anymore: there is no migration, so a passkey whose wallet was stored by an earlier version gets `WalletMissingError` and restores from a backup, and a remembered session prompts once. `logout()` clears the old sessions
  - `register()` uses the id of the passkey it just created; it looked the credential up by address, which found the wallet's first passkey
  - A record that holds another address than its passkey's counts as missing, and if pointing a passkey at a new wallet fails, its previous record (or none) is put back
  - Re-authentication for a logged-in user (the prompt behind signing, exports and `importMnemonic()`) offers only the logged-in passkey, whose PRF output the record is encrypted under; `login(userVerification, credentialId?)` takes it
  - Silent restore picks the most recent persistent session when several passkeys have one
  - `SessionManager.deletePersistentSession()` takes a credential id
  - `test/two-passkeys.test.ts` registers a second passkey from a backup and logs in with both, with and without persistent sessions
- **The chainlist cache is kept per `chainsJsonUrl`** ([#271](https://github.com/w3hc/w3pk/issues/271)). `getChainsData` kept one cache for the module, so `getEndpoints()`, `getChainById()` or `getAllChains()` with a custom `chainsJsonUrl` could return data fetched from another URL within `cacheDuration`
  - Each URL has its own entry and expiry; `clearCache()` clears them all
  - Concurrent calls for one URL share a fetch, and a failed fetch is not cached
  - `test/chainlist.test.ts` covers two URLs, sequential and concurrent, a shared fetch and a retry after a failure

## [0.11.1] - 2026-11-03

### Security

- **The wallet stored on the device is encrypted under a key from the passkey's PRF output** ([#179](https://github.com/w3hc/w3pk/issues/179)). Its key was derived from `credentialId` and `publicKey`, both stored on the device, so anyone who could read the site's storage could decrypt the mnemonic without the authenticator
  - `deriveWalletKey(prfOutput)`: HKDF-SHA256 of the PRF output at `PRF_INPUT`, info `w3pk-prf-wallet-key-v1`, separate from the persistent-session key
  - `register()` uses the PRF output from creation, or runs one assertion when the platform doesn't return it
  - `login()`, `getMnemonic()` and `importMnemonic()` take the key from their assertion's PRF output
  - `syncWalletWithPasskey()`, `importFromSync()` and `restoreFromBackupFile()` evaluate the wallet's PRF input in the assertion they already run (`prf.eval.second` for PRF backups), and now start a persistent session too; `restoreFromBackupFile()` with a password backup while logged in adds one assertion
- **The signature counter is persisted, so cloned authenticators are rejected** ([#212](https://github.com/w3hc/w3pk/issues/212)). `CredentialStorage` dropped `signCount` on save, so `login()` always compared against 0 and accepted a replayed or lower counter; `test/authenticate.test.ts` (`pnpm test:auth`) covers the counter and RP ID hash checks
- **`restoreFromBackupFile()` replaces the stored wallet only after the passkey prompt succeeds** ([#223](https://github.com/w3hc/w3pk/issues/223)). While logged in, it deleted the stored wallet and pointed the credential at the backup's address before the prompt, so a cancelled prompt or an authenticator without PRF left the device with neither wallet, and a crafted backup could swap the receiving address
  - A backup of another address than the logged-in one throws `AddressChangeError` (`currentAddress`, `newAddress`) before any prompt unless the app passes `{ allowAddressChange: true }` once the user confirms; for a PRF backup, which carries no address, the check runs after the assertion and before anything is stored
  - The new wallet is stored before the passkey points at it, and the old one is deleted only after; without a PRF output, nothing stored changes and `PrfUnsupportedError` is thrown
  - `test/restore-replace-wallet.test.ts` covers the cancelled prompt, the missing PRF and the address change
- **`syncWalletWithPasskey()` and `importFromSync()` replace the passkey's stored wallet only with the app's confirmation** ([#246](https://github.com/w3hc/w3pk/issues/246)). They replaced a wallet stored for the passkey with another address silently, logged in or not
  - Both take `options: { allowAddressChange?: boolean }` (default `false`), as `restoreFromBackupFile()` does: a backup of another address throws `AddressChangeError` (`currentAddress`, `newAddress`) after the assertion and before anything is stored, unless the app passes `{ allowAddressChange: true }` once the user confirms
  - A password backup restored by `syncWalletWithPasskey()` is marked verified only once it is stored
  - `test/restore-replace-wallet.test.ts` covers both methods, logged in and logged out
- **`restoreFromBackupFile()` with a password backup verifies the passkey assertion before replacing the stored wallet** ([#247](https://github.com/w3hc/w3pk/issues/247)). While logged in, it took the PRF output from an assertion it never checked, so a cloned authenticator or a forged signature could replace the wallet
  - The assertion runs `login()`'s check (client data, user presence, RP ID hash, signature against the stored public key, signature counter checked and saved) before anything stored changes, and throws `AuthenticationError` on failure; `recoverFromGuardians()` gets the same check
  - `verifyAssertion()` is exported from `src/auth/authenticate.ts` for that
  - `test/restore-replace-wallet.test.ts` covers a counter that is behind and a signature from another key
- **`signAuthorization()` signs EIP-7702 delegations with the origin's derived key after a fresh passkey assertion** ([#224](https://github.com/w3hc/w3pk/issues/224)). Without `privateKey`, it signed with the master key at `m/44'/60'/0'/0/0` from the session cache, so any script on the page during an active session could delegate the master account to its own contract without a prompt
  - Signs with the key of `getOriginSpecificAddress(mnemonic, origin, mode, tag)`, the address `sendTransaction()` uses; new `options.mode` and `options.tag` (default `STANDARD` / `MAIN`); `PRIMARY` mode is refused
  - Every call runs a fresh passkey assertion, even with an active session; the `requireAuth` option is removed
- **No EIP-7702 authorization is signed without a fresh passkey assertion** ([#245](https://github.com/w3hc/w3pk/issues/245)). A script could still delegate the origin account silently, by signing the authorization digest `keccak256(0x05 || rlp([chain_id, address, nonce]))` with `signMessage(digest, { signingMethod: 'rawHash' })` from the session cache, or by passing a key to `signAuthorization({ privateKey })`
  - `signMessage()` with `signingMethod: 'rawHash'` always runs a fresh passkey assertion, even with an active session, since a bare hash can't be told apart from an authorization digest; the hash is checked before the prompt
  - `signAuthorization()` loses `params.privateKey` and throws when one is passed; delegating a stealth or index-derived address is no longer supported
  - YOLO keys are exposed by design: `deriveWallet('YOLO', tag)` returns the private key, so any script holding it can sign a delegation for that address without w3pk
- **`importMnemonic()` stores the imported wallet under its own address** ([#225](https://github.com/w3hc/w3pk/issues/225)). It stored the phrase under the logged-in address and never updated the credential, `user` or the in-memory wallet, so the app showed an address whose mnemonic was gone; without a PRF output, it deleted the stored wallet
  - The phrase must be a valid BIP39 mnemonic (checksum checked), before any prompt
  - The assertion must come from the logged-in passkey; the new wallet is stored before the passkey points at it, and the old one is deleted only after. Importing is an explicit replace, so no `allowAddressChange` is needed; `onAuthStateChanged(true, user)` fires with the new address
  - Without a PRF output, nothing stored changes and `PrfUnsupportedError` is thrown; errors are no longer wrapped in a generic `WalletError`
  - `test/import-mnemonic.test.ts` covers the replacement, the missing PRF, a cancelled prompt, another passkey and invalid phrases
- **Password backups refuse weak passwords and use stronger Argon2id parameters** ([#227](https://github.com/w3hc/w3pk/issues/227)). `createPasswordBackup()` accepted any non-empty password, and Argon2id ran at OWASP's minimum (19 MiB, 2 passes), so a stolen backup or a set of guardian shares with a weak password could be brute-forced offline
  - `createBackupFile()`, `setupSocialRecovery()` and the `exportForSync(password)` fallback refuse a password that fails `isStrongPassword()` (see [#249](https://github.com/w3hc/w3pk/issues/249) below) before any passkey prompt, with the new `WeakPasswordError` (`code: 'WEAK_PASSWORD'`, `feedback: string[]`)
  - New password backups use RFC 9106's second recommendation (64 MiB, 3 passes, 4 lanes). Each file records its parameters, so older backups still restore
- **Password rules accept long passphrases and refuse common passwords** ([#249](https://github.com/w3hc/w3pk/issues/249)). `validatePasswordStrength()` required an uppercase letter, a lowercase letter, a number and a special character, so it refused passphrases such as "correct horse battery staple" and accepted short passwords that ticked every box; its common-password check matched substrings of a 7-word list
  - Rules after [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) §3.1.1.2 and the [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html): 15 to 256 characters counted in Unicode code points, no composition rules, spaces and any Unicode accepted, not a single repeated character, and not one of the 1,000 most common passwords of 15+ characters from SecLists (whole-password match, any case, ignoring spaces, dots, dashes and underscores), embedded in `src/backup/common-passwords.ts` with no network call
  - The password is NFC-normalized before validation, as key derivation already does since BackupFile v3, so existing backups restore as before
  - `isStrongPassword()` calls `validatePasswordStrength()` instead of keeping its own rules; `WeakPasswordError.feedback` gives each reason
  - `validatePasswordStrength()` returns `{ valid, feedback }`: `score` is removed
- **Credential metadata is stored in plain text and documented as readable by any script on the page** ([#226](https://github.com/w3hc/w3pk/issues/226)). `CredentialStorage` encrypted the username and address under a key from `SHA-256("w3pk-metadata-v1:" + credentialId)`, with `credentialId` stored in clear in `w3pk_credential_index`, so the encryption hid nothing. `login()` reads the account list before any passkey prompt, so no key exists that isn't already on the device
  - Entries store `id`, `publicKey`, `username`, `ethereumAddress`, `createdAt`, `lastUsed` and `signCount`; `EncryptedCredential` and `hashPublicKey()` are removed
  - Entries stored encrypted are treated as absent: they aren't listed in `allowCredentials` and don't break `register()` or address lookups
- **The EIP-1193 provider binds signatures to the active chain and signs hex messages as bytes** ([#228](https://github.com/w3hc/w3pk/issues/228)). `eth_signTypedData_v4` signed whatever chain the domain named, and `personal_sign`/`eth_sign` decoded hex to UTF-8, so data that wasn't valid UTF-8 was signed as replacement characters
  - `eth_signTypedData_v4` throws a `WalletError` when `domain.chainId` differs from the active chain, as EIP-712 asks; a domain without `chainId` is still signed. `eth_sendTransaction` refuses a `chainId` other than the active chain the same way
  - Hex data of whole bytes is signed as those bytes; other strings, odd-length hex included, are signed as text. `signMessage()` takes `string | Uint8Array` for EIP-191
- **Only HTTPS RPC endpoints are used, and endpoints set by the app come first** ([#228](https://github.com/w3hc/w3pk/issues/228)). `sendTransaction()` used the first chainid.network endpoint, `http://` ones included, and took nonce and fee data from it
  - `getEndpoints()` keeps only `https://` endpoints without API key placeholders
  - New `rpcUrls: Record<number, string[]>` config option: `sendTransaction()` uses a per-call `rpcUrl`, then `rpcUrls[chainId][0]`, then chainid.network; `w3pk.getEndpoints()` lists the app's endpoints first and keeps them when chainid.network can't be reached
- **`stealth.getKeys()` no longer returns the spending private key** ([#228](https://github.com/w3hc/w3pk/issues/228)). It returns the meta-address, both public keys and the viewing key. The docs say stealth keys are shared across origins and that the viewing key and any stealth private key are enough to compute the spending key, so only apps trusted with stealth funds should enable stealth addresses
- **The `zkProve()` circuit trust limit is documented** ([#228](https://github.com/w3hc/w3pk/issues/228)): it only refuses public signals equal to the secret or a random input, and a circuit can output any other function of the secret, the Semaphore secret included, so apps must only prove with circuits they trust
- **Assertions are checked against the request that asked for them** ([#229](https://github.com/w3hc/w3pk/issues/229)). `verifyAssertionSignature()` ignored `clientDataJSON` and the user-presence flag; it now takes the challenge it answers and rejects a `type` other than `webauthn.get`, another challenge, another origin, or a missing UP flag. `login()`, `syncWalletWithPasskey()` and `importFromSync()` pass their challenge; UV handling is unchanged
- **SIWE checks** ([#229](https://github.com/w3hc/w3pk/issues/229))
  - `validateSiweMessage()` always checks `Expiration Time` and `Not Before`, and rejects `Issued At`, `Expiration Time` or `Not Before` that isn't an RFC 3339 date (an invalid date used to pass)
  - `createSiweMessage()` and `validateSiweMessage()` reject line breaks (CR or LF) in `domain`, `uri`, `statement` and each `resources` entry
  - `signMessage()` rejects a SIWE message whose `domain` doesn't match the current origin (host and port, and scheme when given), as EIP-4361 requires; the check also runs on `EIP191` messages that contain the SIWE header, `personal_sign` included
- **The WebAuthn user handle is 32 random bytes** ([#229](https://github.com/w3hc/w3pk/issues/229)). `register()` used the username as `user.id`, which WebAuthn says must hold no personal information. Existing passkeys keep their handle; on a fresh device, `syncWalletWithPasskey()` with a password backup reads the username from a pre-0.11.1 handle, and from the backup for newer passkeys ([#250](https://github.com/w3hc/w3pk/issues/250))
- **DER signatures are parsed with length and bounds checks** ([#229](https://github.com/w3hc/w3pk/issues/229)). The parsers in `extractRS()` and assertion verification read lengths without checking them, so malformed input was read out of range; it now throws. `signMessageWithPasskey()` and the ML-KEM helpers no longer use Node's `Buffer`
- **Documented limits** ([#229](https://github.com/w3hc/w3pk/issues/229))
  - Origin keys use non-hardened BIP-32 derivation under `m/44'/60'/0'/0`: a leaked child private key plus that node's extended public key reveal every origin's key. w3pk never exposes the extended public key; the path isn't changed because that would move every address
  - `verifyBuildHash()` and `getCurrentBuildHash()` hash the package on unpkg, not the code running in the page
  - Logout drops the session's mnemonic but can't wipe it from memory: JS strings are immutable
- The guardian share document states the actual threshold instead of `${shareIndex}-of-N` ([#229](https://github.com/w3hc/w3pk/issues/229))
- **`stealth.parseAnnouncement()` and `stealth.scanAnnouncements()` no longer return stealth private keys** ([#244](https://github.com/w3hc/w3pk/issues/244)). A stealth private key minus the shared-secret hash, which the viewing key computes, is the spending key, so any script on the page could recover it and spend every stealth payment
  - `ParseAnnouncementResult` and `ParseResult` drop `stealthPrivateKey`; results carry `isForUser` and `stealthAddress`
  - New `stealth.signTransaction(announcement, tx)` signs an EIP-1559 transaction from the stealth address inside the SDK after a fresh passkey assertion, even with an active session, and returns the serialized signed transaction. It doesn't send it: the app broadcasts it with its own RPC. `tx` (`StealthTransaction`, exported from `w3pk`) must be fully populated: `to`, `chainId`, `nonce`, `gasLimit`, `maxFeePerGas`, `maxPriorityFeePerGas`, with optional `value` and `data`
- **`register()` checks the attestation's client data, RP ID hash and user presence before storing the credential** ([#248](https://github.com/w3hc/w3pk/issues/248)). It stored any credential the browser returned, whatever its `clientDataJSON` held. Now, as WebAuthn L3 §7.1 requires, it throws `RegistrationError` unless the type is `webauthn.create`, the challenge is the one sent, the origin is exactly `window.location.origin`, the authenticator data's RP ID hash is SHA-256 of `window.location.hostname`, and the UP flag is set
  - `verifyClientData(clientDataJSON, challenge, type)` and `verifyRpIdHash(authData)` are exported from `src/auth/authenticate.ts` and shared with `login()`
  - `test/register-client-data.test.ts` covers each check

### Added

- **Types used in public signatures exported from `w3pk`** ([#189](https://github.com/w3hc/w3pk/issues/189)): `RegisterResult` (new, returned by `register()`), `SecurityMode`, `SigningMethod`, `SignMessageOptions`, `PersistentSessionConfig`, `ZKProofConfig`, `ZKMethods`, `EIP1193ProviderInterface`, `DeviceSyncInfo`, `GuardianShare`, `Announcement`, `ParseAnnouncementResult`, `Chain`, `ChainlistOptions`, and the ZK proof types (`ProofType`, `ZKProof`, `VerificationResult`, `CircuitArtifacts` and the five `*ProofInput` types)
- `getSyncStatus()` is documented again in `docs/API_REFERENCE.md`
- **EIP-1193 event types** ([#210](https://github.com/w3hc/w3pk/issues/210)): `ProviderConnectInfo`, `ProviderRpcError` and `ProviderMessage`, exported from `w3pk`
- **Password backups carry the username** ([#250](https://github.com/w3hc/w3pk/issues/250)), as PRF backups do. `syncWalletWithPasskey()` restores it on a fresh device, where a passkey registered since 0.11.1 has a random user handle
  - `BackupFileManager.createPasswordBackup(mnemonic, password, credential?, username?)`; `createBackupFile()`, `setupSocialRecovery()` and the password fallback of `exportForSync()` pass the logged-in username
  - A backup without a username, with one `register()` wouldn't accept, or with one another passkey already has on the device falls back to the wallet's address; PRF backups follow the same rules

### Changed

- **Upgrading from v0.11.0 or earlier: restore the wallet from a backup.** Credential metadata stored encrypted is ignored ([#226](https://github.com/w3hc/w3pk/issues/226)), so `login()` with an existing passkey throws `SyncRequiredError` before the re-encryption below can run; restore with `restoreFromBackupFile()` (password or PRF backup), `importFromSync()` or social recovery. No migration is provided
- **Authenticators without PRF keep no wallet on the device**: the wallet stays in memory for the session and comes back from a backup on the next visit. This includes unverified assertions with `userVerification: 'preferred'`, where `login()` throws `WalletMissingError`
- **Wallets stored before this release** are re-encrypted at the next `login()` from a PRF persistent session when one exists; otherwise `login()` throws `WalletMissingError` and the wallet is restored from a backup
- `DeviceSyncManager.importFromSync()` also returns `walletPrfOutput`, the PRF output the wallet key comes from
- **Restores no longer return the mnemonic** ([#229](https://github.com/w3hc/w3pk/issues/229)): `restoreFromBackupFile()`, `syncWalletWithPasskey()` and `recoverFromGuardians()` return `{ ethereumAddress }`, so the master mnemonic is never exposed to the app
  - `recoverFromGuardians()` restores the rebuilt backup as `restoreFromBackupFile()` does: logged out, the wallet stays in memory for `register()`; logged in, it replaces the stored wallet after one assertion, with a new `options.allowAddressChange`
- `validateSiweMessage()` drops the `checkExpiration` and `checkNotBefore` options: both checks always run ([#229](https://github.com/w3hc/w3pk/issues/229))
- `PasskeySelectionResult` carries the base64url `challenge` its assertion answers ([#229](https://github.com/w3hc/w3pk/issues/229))
- **Build configuration** ([#187](https://github.com/w3hc/w3pk/issues/187)): the build output is unchanged
  - `build:zk` and `html` run with `pnpm` (`pnpm run`, `pnpm dlx serve`) instead of `npm` and `npx`, and `compile:circuits` falls back to `pnpm exec snarkjs`
  - `pnpm.overrides` keeps one entry per package: `minimatch@>=5.0.0 <5.1.8` and `jsonpath@<=1.2.1`
  - The four `tsup.config.ts` entries spread a shared `base` of format, sourcemap, minify, splitting, platform and target options
- **`Web3Passkey` types** ([#189](https://github.com/w3hc/w3pk/issues/189)): typed return values, parameters and module types
  - `getSyncStatus()` returns `DeviceSyncInfo | null`, `detectSyncCapabilities()` returns `SyncCapabilities`, `mlkemEncrypt()` returns `EncryptedPayload` and `mlkemDecrypt()` takes one
  - `w3pk.zk` is typed `ZKMethods`: the `ZKProofModule` methods, each returning a Promise, and `isAvailable()` returning `Promise<boolean>`
  - `ZKProofConfig` is the one from `w3pk/zk`: `customCircuits` takes `CircuitArtifacts` values
  - The EIP-1193 provider's `request()` takes `params?: unknown[]` and returns `Promise<unknown>`
  - `setupSocialRecovery()`, `generateGuardianInvite()` and `recoverFromGuardians()` use `GuardianShare`
  - `MLKEM_DEFAULT_CONTEXT` (`'mlkem-v1'`) replaces the six defaults of the ML-KEM context
- **No `any` in `Web3Passkey` public signatures** ([#210](https://github.com/w3hc/w3pk/issues/210)), nor in the types they reference
  - The EIP-1193 provider's `on()` and `removeListener()` have one overload per EIP-1193 event: `accountsChanged` (`string[]`), `chainChanged` (`string`), `connect` (`ProviderConnectInfo`), `disconnect` (`ProviderRpcError`) and `message` (`ProviderMessage`). Other event names no longer compile
  - `SignMessageOptions.eip712Domain` is ethers' `TypedDataDomain`
  - `CircuitArtifacts.verificationKey` is `unknown` and `VerificationResult.publicSignals` is `Record<string, string>`
- **`src/core/sdk.ts` split by feature** ([#190](https://github.com/w3hc/w3pk/issues/190)): the public API and behavior are unchanged
  - Backup and sync, social recovery, the EIP-1193 provider and ML-KEM move to `src/core/backup-sync.ts`, `social-recovery.ts`, `eip1193.ts` and `mlkem.ts`; `sdk.ts` keeps auth, session and wallet core
  - `Web3Passkey` keeps each public method's signature and JSDoc and delegates to those files, which take the internals they need through `SdkContext` (`src/core/context.ts`)
- **Repository files** ([#191](https://github.com/w3hc/w3pk/issues/191)):
  - `JUNE_9_2026_AUDIT.md` moves from the repository root to `docs/`
  - `examples/w3pk_backup_example_2026-11-02.json`, a BackupFile v3 password backup of the test mnemonic `test test … junk` (password `test-password`), replaces the v2 `examples/w3pk_backup_example_2025-12-19.json`. `docs/PORTABILITY.md` links it
- **BREAKING: the security score tops out at 70** ([#211](https://github.com/w3hc/w3pk/issues/211)), the points left without social recovery's 30, so its maximum is reachable again. Levels: `vulnerable` 0-20, `protected` 21-40, `secured` 41-60, `fort-knox` 61-70. `nextMilestone` lists the steps still missing, e.g. `Reach "fort-knox" (61+ pts): verify your backup again`. Apps comparing `total` against the old 0-100 cut-offs need the new ones

### Removed

- **BREAKING: the `options.origin` override** ([#181](https://github.com/w3hc/w3pk/issues/181)) from `deriveWallet()`, `getAddress()` (which no longer takes `options`), `signMessage()` (`SignMessageOptions.origin`), `sendTransaction()`, `deriveMLKemPublicKey()`, `mlkemEncrypt()` and `mlkemDecrypt()`. Any app could pass another site's origin and, in YOLO mode, get that origin's private key. Every derivation uses `getCurrentOrigin()`; `DerivedWallet.origin` stays as a return field
- `deriveEncryptionKeyFromWebAuthn()` and the deprecated `deriveEncryptionKey()`
- `VaultSync.createSyncPackage()`, `VaultSync.restoreFromSync()` and the `SyncVault` type, which used the same key. PRF backups (`exportForSync()`) replace them
- **BREAKING: dead modules** ([#182](https://github.com/w3hc/w3pk/issues/182)) no public entry point reached:
  - The QR backup (`QRBackupCreator`, `BackupManager.createQRBackup()`/`restoreFromQR()`, `QRBackupOptions`), with its plaintext mode and the PBKDF2 iteration count it read from the QR. The PBKDF2 helpers only it used (`encryptWithPassword()`, `decryptWithPassword()`, `deriveKeyFromPassword()`) and `getDeviceFingerprint()` go too
  - `VaultSync`, `DeviceManager` and the `DeviceInfo`, `SyncStatus`, `SyncResult` and `SyncStep` types
  - `ApiClient`, `ApiResponse`, `WebAuthnError`, the empty `wallet/signing` module and `BackupManager.simulateRecoveryScenario()` (use `RecoverySimulator`)
  - The `src/sync` and `src/backup` barrels
- **BREAKING: deprecated public API** ([#183](https://github.com/w3hc/w3pk/issues/183)), each a duplicate of an existing one:
  - `Web3Passkey.hasExistingCredential()` and `getExistingCredentialCount()`: use `listExistingCredentials()` and its `length`
  - `UserInfo.id` and `UserInfo.displayName`, which nothing set: use `ethereumAddress` and `username`
  - The `WalletInfo` type: `GeneratedWallet` and `DerivedWallet` are now exported from `w3pk`
- **BREAKING: `SocialRecoveryManager`** ([#184](https://github.com/w3hc/w3pk/issues/184)), a second guardian-recovery stack the SDK didn't use, which kept every Shamir share together in localStorage (`w3pk_social_recovery`): whoever could read the site's storage held enough shares to rebuild the backup. Use `setupSocialRecovery()`, `generateGuardianInvite()` and `recoverFromGuardians()`, which store no share on the device
  - The `Guardian`, `GuardianInvite`, `SocialRecoveryConfig`, `RecoveryShare` and `RecoveryProgress` types, and the `src/recovery` barrel
  - `getBackupStatus()` no longer reads `w3pk_social_recovery`, so its `socialRecovery` field stays unset. Apps that used `SocialRecoveryManager` can remove that key from localStorage
- **BREAKING: education wrappers on `Web3Passkey`** ([#185](https://github.com/w3hc/w3pk/issues/185)), which only added an auth check to standalone exports and returned `any`:
  - `getEducation(topic)`: use `getExplainer(topic)`, which returns `null` for an unknown topic instead of throwing
  - `simulateRecoveryScenario(scenario)` and `runRecoveryTest()`: use `new RecoverySimulator().simulateScenario(scenario, status)` and `runInteractiveTest(status)` with `status = await w3pk.getBackupStatus()`
- **BREAKING: the `socialRecovery` backup status** ([#211](https://github.com/w3hc/w3pk/issues/211)), which `getBackupStatus()` stopped setting in [#184](https://github.com/w3hc/w3pk/issues/184): `BackupStatus.socialRecovery`, `SecurityScore.breakdown.socialRecovery`, and the `SocialRecoveryStatus` and `Guardian` types in `src/backup/types.ts`. The recovery simulator no longer lists social recovery as a method or a step. `setupSocialRecovery()`, `generateGuardianInvite()` and `recoverFromGuardians()` stay
- **Internal notes from the npm package** ([#191](https://github.com/w3hc/w3pk/issues/191)): `"files"` lists `docs/*.md` instead of `docs/`, so only the top-level docs ship
- **BREAKING: external wallet delegation** ([#228](https://github.com/w3hc/w3pk/issues/228)): `requestExternalWalletDelegation()`, `requestExternalWalletAuthorization()`, `getDefaultProvider()`, `detectWalletProvider()`, `supportsEIP7702Authorization()` and the `EIP1193Provider` type. It asked the wallet to `eth_sign` a raw hash (blind signing), its `personal_sign` fallback could never verify, it delegated to the w3pk address, which has no code, and no standard RPC lets an external wallet sign an EIP-7702 authorization
  - `examples/ens-to-w3pk-delegation.ts`, `standalone/ens-delegation-demo.html`, `test/external-wallet.test.ts`, the `test:external-wallet` script and the external wallet sections of the docs

### Fixed

- **`pnpm test` runs every `test/**/*.test.ts` file** ([#186](https://github.com/w3hc/w3pk/issues/186)) through `scripts/run-tests.mjs` instead of a hand-written chain that left five files out. The `test:*` subsets use the same runner, and `node scripts/run-tests.mjs <dir or files>` runs any subset
  - `test/test.ts` is now `test/basic.test.ts`
  - `sign-authorization.test.ts` signs with an explicit `privateKey` and checks the recovered signer, so it runs in Node without WebAuthn
  - `security-validation.test.ts` is gone: it imported `vitest`, which isn't a dependency, and only asserted on constants it defined without calling the SDK
- **Test files exit non-zero when a test fails**: `console.assert` is replaced by `node:assert` and `.catch(console.error)` by an exit code. This surfaced tests that had been failing silently in `origin-derivation`, `derive-wallet-unified` and `security-restrictions` (tags passed as the security mode, a renamed index function, a check of the removed `exportMnemonic()`), now fixed
- **zk features load under a Content Security Policy without `'unsafe-eval'`** ([#188](https://github.com/w3hc/w3pk/issues/188)): `loadZKModule()` imports `w3pk/zk` with a literal `import()` instead of `new Function`, which such a policy blocks. Bundlers now resolve `w3pk/zk` into a lazy chunk, so `w3pk.zk` also works in Vite and Next.js builds, where the old bare runtime import could not resolve. snarkjs and circomlibjs still need `'wasm-unsafe-eval'` to compile WebAssembly
  - A build that resolves `w3pk` now needs `circomlibjs` installed, as it already needed `snarkjs`; both are optional dependencies installed by default
  - The error when `w3pk/zk` can't load says to install the optional dependencies snarkjs and circomlibjs, without naming a package manager
- **`pnpm build` passes when `dist/` holds a previous build** ([#206](https://github.com/w3hc/w3pk/issues/206)): `w3pk/zk` resolved through the package's own `exports` to `dist/zk/index.d.ts`, so the type build failed with TS5055. `tsconfig.json` now maps `w3pk/zk` to `src/zk/index.ts`, replacing its ambient declaration; the build output is unchanged
- **`dist/index.js` and `dist/index.mjs` no longer inline the whole `package.json`** ([#207](https://github.com/w3hc/w3pk/issues/207)): `getPackageVersion()` imports only `version`, so esbuild drops the other fields (scripts, devDependencies, keywords). The build hash changes; the declared types don't
- **`w3pk.zk` resolves properties instead of calling them** ([#208](https://github.com/w3hc/w3pk/issues/208)): `await w3pk.zk.isAvailable()` resolves to `true`, or `false` when `w3pk/zk` can't load, instead of throwing `true is not a function`
  - `await w3pk.zk` settles: the Proxy has no `then`, so it is no longer a thenable that never resolves
  - A member `ZKProofModule` doesn't have rejects with a `TypeError` instead of an error from inside the Proxy
- **Poseidon hashes are field elements** ([#209](https://github.com/w3hc/w3pk/issues/209)): circomlibjs's `buildPoseidon()` returns raw bytes in Montgomery form, which were used as-is. Every output now goes through `poseidon.F.toObject()`, so it matches what the circuits compute
  - `createCommitment()` returns the commitment as a decimal string instead of comma-joined bytes, so the threshold and range circuits accept it
  - `computeMerkleRoot()` returns a decimal string and matches `buildMerkleTree()`
  - `buildMerkleTree()`, `buildNFTHoldersMerkleTree()`, the NFT ownership proof inputs and `verifyNFTOwnership()` used `bufferToBigInt()` on those bytes, which gave a different number than the circuit; their roots, leaves and hashes change
  - Commitments, roots and NFT hashes stored before this release don't match the new values and must be recomputed
- **No dead links in `docs/EIP-7951.md`** ([#213](https://github.com/w3hc/w3pk/issues/213)): the Examples section, whose three files never existed, is gone, and the API reference link points to the `signMessageWithPasskey()` heading
- **The docs call only methods `Web3Passkey` exposes, and their relative links resolve** ([#251](https://github.com/w3hc/w3pk/issues/251)): `exportMnemonic()`, `createZipBackup()`, `generateWallet()` and `restoreFromBackup()` are gone from `README.md`, `CONTRIBUTING.md` and `docs/`, `deriveWallet()` examples pass a security mode instead of an index, and `register()` and `signMessage()` examples use their real return values. Dead links in `docs/EIP_7702.md`, `docs/ARCHITECTURE.md`, `docs/RECOVERY.md` and the API reference anchors are fixed

## [0.11.0] - 2026-11-02

### Added

- **Baby Jubjub and exponential ElGamal** ([#150](https://github.com/w3hc/w3pk/issues/150)) in `w3pk/zk`, matching circomlib's `babyjub` gadgets and circomlibjs's encodings
  - Point helpers: `babyJubAdd()`, `babyJubNeg()`, `babyJubMul()`, `isOnBabyJub()`, `isInBabyJubSubgroup()`, `packBabyJubPoint()`, `unpackBabyJubPoint()` and the curve constants (EIP-2494)
  - Keys: `generateBabyJubKeyPair()`, `deriveBabyJubKeyPair(secret)` (HKDF-SHA256, info `w3pk-babyjub-v1`), `babyJubPublicKey()` (`sk · Base8`, as `BabyPbk`), `packBabyJubPublicKey()`, `unpackBabyJubPublicKey()`
  - ElGamal `Enc(m; r) = (r · Base8, m · Base8 + r · PK)`: `elgamalEncrypt()`, `elgamalAdd()`, `elgamalRerandomize()`, `elgamalDecryptToPoint()`, and `elgamalDecrypt()` with a bounded discrete log (`babyJubDiscreteLog()`, up to 2^32)
  - Public keys and ciphertexts outside the prime-order subgroup, low-order points, the identity as a key and non-canonical encodings throw `CryptoError`
  - Native `bigint`, synchronous, with no runtime dependency on `circomlibjs`

- **ZK artifact verification** ([#151](https://github.com/w3hc/w3pk/issues/151)) in `w3pk/zk`, so a host or CDN can't swap the circuit an app proves against
  - `verifyZkArtifacts({ wasm, zkey }, pins)` computes the IPFS CIDv1 of each artifact (bytes or URL) as `ipfs add --cid-version 1` does and returns the verified bytes to prove with
  - `readZkArtifactPins(registry, keys)` reads the pins from the build-verification registry, or any contract with its `getCidByVersion(string)`
  - `ZkArtifactMismatchError` (`code: 'ZK_ARTIFACT_MISMATCH'`, with `artifact`, `expectedCid`, `actualCid`) on a mismatch; `ZK_ARTIFACT_FETCH_ERROR` and `ZK_ARTIFACT_NOT_PINNED` otherwise
  - Build verification and ZK artifacts share one CID helper, which no longer keeps a copy of the blocks in memory

- **`getSemaphoreIdentity(tag)`** ([#152](https://github.com/w3hc/w3pk/issues/152)) returns the commitment of a Semaphore v4 identity bound to the passkey, and the `credentialId` it's bound to so apps can handle rotation
  - The private key is a PRF secret under its own label (`w3pk-semaphore-v1`), out of reach of `derivePrfSecret(tag)`; it is never returned or stored
  - The commitment matches `@semaphore-protocol/identity`, a new optional dependency imported only when the method is called
  - `SemaphoreIdentity` type

- **`zkProve(tag, artifacts, publicInputs, extraWitness, options)`** ([#153](https://github.com/w3hc/w3pk/issues/153)) makes a Groth16 proof with a passkey-bound secret the app never sees, and returns only `{ proof, publicSignals }`
  - `options.secret`: `'zk'` (a Baby Jubjub private key under its own PRF label, `w3pk-zk-v1`) or `'semaphore'` (the `secretScalar` of `getSemaphoreIdentity(tag)`'s identity); neither is reachable from `derivePrfSecret(tag)`
  - `options.derive` declares inputs w3pk computes as Poseidon over the secret, other inputs and constants (e.g. a per-proposal secret); `options.random` names inputs filled with fresh randomness (e.g. ElGamal's `r`) and discarded
  - Checks the artifacts with `verifyZkArtifacts` and proves with the verified bytes; options, tag, dependencies and pins are checked before the passkey prompt
  - Runs snarkjs in a module Web Worker (`dist/zk/prove-worker.mjs`), in-thread where `Worker` doesn't exist or the worker can't start
  - Refuses proofs whose public signals contain the secret or a random input
  - `poseidon-lite` is a new optional dependency, imported only for derivations
  - `ZkArtifactMismatchError` is now exported from the main entry too
  - The secret is kept out of the API, not out of reach of malicious code on the same page; the cross-origin wallet ([#156](https://github.com/w3hc/w3pk/issues/156)) isolates it fully

### Changed

- **BREAKING: BackupFile v3** ([#154](https://github.com/w3hc/w3pk/issues/154)) replaces v2, with no compatibility layer
  - `version: 3`; `encryptedMnemonic` is `base64(iv || AES-256-GCM ciphertext)` for both methods, `password` and `prf`
  - `password`: Argon2id instead of PBKDF2, with m=19 MiB, t=2, p=1 (OWASP), a random 16-byte salt and an NFC-normalized password; `passwordEncryption` is `{ kdf: 'argon2id', salt, memoryKiB, passes, parallelism }`, read back with bounds (64 MiB, 3 passes, 4 lanes)
  - No `ethereumAddress` or `addressChecksum` in the file: restores derive the address from the decrypted mnemonic; default filenames no longer contain the address either (`w3pk-backup-<date>.json`, `w3pk-sync-<date>.json`)
  - Restoring a file that isn't v3 throws the new `UnsupportedBackupVersionError` (`code: 'BACKUP_VERSION_UNSUPPORTED'`, with `version`, and `backupFileJson` when rebuilt from guardian shares); decrypt a v2 password file with the [v0.10.6 offline tool](https://github.com/w3hc/w3pk/blob/v0.10.6/standalone/extract-mnemonic.html)
  - `createBackupFile(password)` drops its `encryptionType` parameter (a second argument throws); `BackupFileManager.createPasswordBackup(mnemonic, password, credential?)`, `createPrfBackup(mnemonic, credential, username, prfSalt, prfOutput)`, `DeviceSyncManager.exportForSync(mnemonic, credential, username, password?)` and `SocialRecovery.splitAmongGuardians(backupFile, guardians, threshold, walletAddress)` change signature
  - `restoreFromBackupFile()` restores `prf` files (one assertion, no password, as `importFromSync()`)
  - `getBackupStatus()`: new `recommendedMode` (`'password'` until a backup restores without a passkey, then `'prf'`); `hasBackup` and the score cap count only backups that restore without a passkey (file, QR, phrase, social recovery), so password-only backups aren't penalized; `exportForSync()` records PRF exports as method `'prf'`
  - `standalone/extract-mnemonic.html` decrypts v3 password files offline, with Argon2id inlined (`pnpm build:standalone` regenerates it); `docs/RECOVERY.md` links the v0.10.6 tool for v2 files

- **BREAKING: encrypted payload v3 with a hybrid KEM** ([#137](https://github.com/w3hc/w3pk/issues/137)) replaces v1 and v2, with no compatibility layer
  - Each recipient's AES-256 data key is sealed with HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180), mode_base, HKDF-SHA256, AES-256-GCM) over ML-KEM-1024 + X25519; the shared secret is `SHA3-256(ss_M || ss_X || ct_M || ct_X || pk_M || pk_X || "w3pk-MLKEM1024-X25519-v3")` (the UniversalCombiner of draft-irtf-cfrg-hybrid-kems)
  - `EncryptedPayload` is `{ version: 3, recipients: [{ publicKey, enc, ciphertext }], encryptedData, iv, authTag }`: `enc` is the ML-KEM ciphertext (1568 bytes) followed by the X25519 ephemeral key (32), `ciphertext` the sealed data key (48)
  - `deriveMLKemKeypair()` derives an X25519 key alongside the ML-KEM key (HKDF-SHA256, salt `w3pk-kem-keypair-v3`, info `ml-kem-1024:<context>` and `x25519:<context>`): public keys are 1600 bytes, private keys 3200, and `deriveMLKemPublicKey()` returns a new key for the same wallet, so recipients must re-share theirs
  - `mlkemDecrypt(payload, privateKey)` drops its `publicKey` argument, finds its entry by the public key it derives, and throws `Unsupported payload version` for anything but v3
  - New dependency: `@noble/curves` (X25519)

### Security

- **Encrypted payloads no longer rest on ML-KEM alone** ([#137](https://github.com/w3hc/w3pk/issues/137)): a v3 payload stays confidential unless both ML-KEM-1024 and X25519 are broken. v1 payloads wrapped the key by XOR with the raw ML-KEM shared secret, with no key derivation or recipient binding; v1 and v2 payloads can no longer be read. KEM keys are long-lived, so there is no forward secrecy: a leaked key exposes every payload sealed to it.

- **Password backups resist GPU guessing, and backup files no longer say whose wallet they are** ([#154](https://github.com/w3hc/w3pk/issues/154)): PBKDF2 isn't memory-hard, so a stolen v2 password file was cheap to attack on GPUs; v3 uses Argon2id. v2 files also stored the address in clear and as `addressChecksum`, an unsalted truncated SHA-256 that hashing onchain addresses reverses; v3 stores neither.

- **`passkey` and `hybrid` backups didn't use the passkey** ([#170](https://github.com/w3hc/w3pk/issues/170)): their key was `SHA-256("w3pk-v4:" + credentialId + ":" + publicKey)` with no WebAuthn ceremony. The credential ID is in the file and a public key isn't secret, so a `passkey` file decrypted from public data alone, and a `hybrid` file was only as strong as its password. **If you have a `passkey` or `hybrid` backup, log in where your wallet is and create a new `password` backup (`createBackupFile(password)`) or `prf` backup (`exportForSync()`), then delete the old file.**

### Removed

- **`passkey` and `hybrid` backup methods** ([#170](https://github.com/w3hc/w3pk/issues/170)), with no compatibility layer; `password` and `prf` remain
  - `BackupFileManager.createPasskeyBackup()`, `createHybridBackup()`, `restoreWithExistingPasskey()`, `restoreWithHybrid()` and `DeviceSyncManager.canSyncBackup()`
  - `createBackupFile()`'s `encryptionType` parameter (see BackupFile v3); `setupSocialRecovery()` and `recoverFromGuardians()` require a password (without one, social recovery split a `passkey` backup)
  - `BackupFile.encryptionMethod` is `'password' | 'prf'`; `credentialId` and `publicKeyFingerprint` are gone
  - `SyncBootstrapError` reason `'PASSKEY_BACKUP'`
  - Restoring a `passkey` or `hybrid` file (`syncWalletWithPasskey()`, `restoreFromBackupFile()`, `importFromSync()`, guardian recovery) throws the new `RemovedBackupMethodError` (`code: 'BACKUP_METHOD_REMOVED'`, with `method`); the offline `standalone/extract-mnemonic.html` refuses them too

## [0.10.5] - 2026-10-27

### Added

- **`userVerification` option** ([#167](https://github.com/w3hc/w3pk/issues/167)): `'required'` (default) or `'preferred'`, passed to `register()`, `login()` and `signMessageWithPasskey()`
  - With `'preferred'`, authenticators that can skip the biometric/PIN check (security keys, unlocked password managers) sign in with one click
  - `derivePrfSecret()` and PRF device sync always require user verification
  - `prfOutput` is dropped when the authenticator data's UV flag is clear, so an unverified login gets an in-memory session, never a different persistent session key

### Changed

- **Registration accepts any authenticator** ([#167](https://github.com/w3hc/w3pk/issues/167)): `authenticatorAttachment: "platform"` is removed, so computers without a built-in authenticator can register through a phone (QR code), a security key or a password manager

### Removed

- **AI inspection** ([#149](https://github.com/w3hc/w3pk/issues/149)): `inspect()`, `inspectNow()`, the `w3pk/inspect` and `w3pk/inspect/node` entry points and their docs are gone, since an authentication SDK shouldn't send the host app's source code to a third-party API

## [0.10.4] - 2026-10-25

### Added

- **Eviction risk** ([#160](https://github.com/w3hc/w3pk/issues/160)): apps can insist on a backup only where the browser is likely to wipe the wallet
  - `BackupStatus.evictionRisk`, computed on each `getBackupStatus()` call: `true` on WebKit (every iOS browser, Safari and other WebKit browsers on desktop) outside a home-screen app while `navigator.storage.persisted()` is not `true`, `false` elsewhere
  - `register()` returns `evictionRisk`
  - docs/INTEGRATION_GUIDELINES.md shows the gate: block on `!hasBackup && evictionRisk`, a banner on `!hasBackup` otherwise, and "Add to Home Screen" on iOS

- **Passkey-bound secrets** ([#142](https://github.com/w3hc/w3pk/issues/142)): `derivePrfSecret(tag)` returns a 32-byte secret that stays out of backups and recovery phrases
  - Evaluates the WebAuthn PRF extension on a fresh user-verified assertion at `SHA-256("w3pk-prf-v1:" + origin + ":" + tag)`, then HKDF-SHA256, so each origin and tag gets its own secret; restricted to the current user's passkey when logged in
  - Returns `{ secret, credentialId }`, so apps can tell when the passkey, and so the secret, has changed
  - Never derived from or stored with the mnemonic; nothing is written to storage or sessions
  - `PrfUnsupportedError` (exported, `code: 'PRF_UNSUPPORTED'`, with `credentialId`) when the authenticator returns no PRF output, with no fallback
  - Tags must be non-empty and can't contain `:`, so no origin and tag pair collides with another
  - `PrfSecret` is exported; docs/API_REFERENCE.md documents the threat model

- **Passwordless device sync** ([#143](https://github.com/w3hc/w3pk/issues/143)): a device where the passkey synced restores the wallet with one passkey prompt and no password, even with no data for the passkey
  - New backup `encryptionMethod: 'prf'`: `encryptedMnemonic`, `prfSalt` (32 random bytes per backup), `credential: { id, publicKey }`, `username`, `addressChecksum`; the key is HKDF-SHA256 over the passkey's WebAuthn PRF output at `SHA-256("w3pk-prf-sync-v1" || prfSalt)`, then AES-256-GCM
  - `syncWalletWithPasskey()` and `importFromSync()` restore PRF backups with one assertion restricted to the backup's passkey, then reject an altered ciphertext, address or address checksum
  - `generateSyncQR()` and `parseSyncQR()` carry PRF backups
  - PRF works in Chrome 108+ and Safari 17+ / iOS 17+, not in Firefox, and passkeys sync within one ecosystem only: docs/RECOVERY.md and docs/PORTABILITY.md describe the flow and the password fallback

### Changed

- **`exportForSync(password?)`** ([#143](https://github.com/w3hc/w3pk/issues/143)) emits a PRF backup instead of a passkey-encrypted one; without PRF support it throws `PrfUnsupportedError`, or falls back to a password backup when given `password`. With an active session it takes one prompt, the PRF assertion
- **`importFromSync()`** ([#143](https://github.com/w3hc/w3pk/issues/143)) takes PRF backups only; other backups go through `syncWalletWithPasskey()`

### Fixed

- **Fresh-device sync** ([#141](https://github.com/w3hc/w3pk/issues/141)): on a device where the passkey synced through the platform but has no data, `syncWalletWithPasskey()` decrypted the backup without storing anything, and `importFromSync()` required a `login()` that throws `SyncRequiredError` there
  - Password backups made while logged in carry `credential: { id, publicKey }`, the passkey that owns the wallet; the public key is not a secret, and a fresh device needs it for `login()` and the wallet key
  - `syncWalletWithPasskey()` saves the passkey's metadata when it's missing (username from the passkey's user handle), stores the wallet, starts a session and fires `onAuthStateChanged(true, user)`; it also restores the wallet where the metadata is present and the wallet record is gone
  - `importFromSync()` no longer requires a login: logged out, it prompts for the passkey; it restores the wallet, starts a session and fires `onAuthStateChanged(true, user)` where this device has the passkey's metadata
  - `SyncBootstrapError` (exported, `code: 'SYNC_BOOTSTRAP_FAILED'`, with `reason` and `credentialId`) when a backup can't set up a fresh device: passkey or hybrid backups (`'PASSKEY_BACKUP'`), password backups made before this release (`'NO_CREDENTIAL'`), or a backup of another passkey (`'CREDENTIAL_MISMATCH'`)
  - `PasskeySelectionResult` has `username`
  - A fresh device checks the backup's public key against the passkey's assertion signature before saving it (`SyncBootstrapError` with `reason: 'PUBLIC_KEY_MISMATCH'`); `PasskeySelectionResult` has the `assertion`

## [0.10.3] - 2026-10-13

### Added

- **Backup status** ([#140](https://github.com/w3hc/w3pk/issues/140)): apps can tell whether the user has a backup, push for one at registration and warn while none exists
  - `getBackupStatus()` returns `hasBackup`, `lastBackupAt` and `methods` (`'file' | 'qr' | 'phrase'`), read from the `w3pk_backups` records of the current wallet; it is typed `Promise<BackupStatus>` instead of `any`
  - `confirmRecoveryPhraseBackup()` records that the user wrote down the recovery phrase
  - `register()` returns `hasBackup`, `false` for a new wallet
  - Without a backup, the security score is capped at 20, the level is `vulnerable` and `nextMilestone` asks for a backup
  - `BackupMethod` is exported from the package root

### Fixed

- **`login()` succeeding without a wallet** ([#139](https://github.com/w3hc/w3pk/issues/139)): `login()` resolved and fired `onAuthStateChanged(true, …)` when the passkey had no wallet on this device, so the next `getAddress()` threw a generic `Failed to get address`
  - `SyncRequiredError` (`credentialId`, code `SYNC_REQUIRED`): the passkey authenticated, but this device has no credential metadata; replaces the plain `AuthenticationError` message apps had to match by text
  - `WalletMissingError` (`credentialId`, `ethereumAddress`, code `WALLET_MISSING`): the credential metadata is here, but the wallet record is gone
  - In both cases the user is not logged in and `onAuthStateChanged(true, …)` never fires
  - Both are exported from the package root

- **Wallets lost to IndexedDB eviction** ([#138](https://github.com/w3hc/w3pk/issues/138)): Chrome's storage-pressure eviction deleted the IndexedDB wallet but kept the credential in localStorage, so the passkey logged in to a wallet that no longer existed
  - The encrypted wallet (`w3pk_wallet_<address>`), persistent sessions (`w3pk_session_<address>`) and backup metadata (`w3pk_backups`) live in localStorage, next to the credential metadata, so eviction removes all of them or none
  - The `Web3PasskeyWallet`, `Web3PasskeyPersistentSessions` and `Web3PasskeyBackup` IndexedDB stores are removed with no migration: wallets created before this release need a restore from a backup file or the recovery phrase
  - With `requireReauth: false`, the PRF-derived session key is stored as base64url next to the blob instead of as a non-extractable `CryptoKey`, since localStorage only holds strings
  - `navigator.storage.persist()` is requested after register, login and restore, and `w3pk.storagePersisted` exposes the answer
  - `IndexedDBWalletStorage` is renamed `LocalStorageWalletStorage`; the wallet, session and backup stores take an optional `Storage`
  - docs/SECURITY.md and docs/BROWSER_COMPATIBILITY.md document what still wipes localStorage (Safari's 7-day cap, clearing site data, private browsing)

- **SIWE login against siwe-based servers** ([#135](https://github.com/w3hc/w3pk/issues/135)):
  - `createSiweMessage` always writes the blank line after the statement slot, so messages without a `statement` follow EIP-4361 and parse with the [siwe](https://github.com/spruceid/siwe) library (previously rejected by siwe v3)
  - `signMessage` rejects `mode: 'PRIMARY'` with `signingMethod: 'SIWE'`: PRIMARY addresses come from the passkey's P-256 key, so an EIP-191 signature could never recover to them
  - `examples/siwe-login.ts` shows the server-issued nonce flow

### Changed

- **ML-KEM key wrapping is versioned and authenticated** ([#133](https://github.com/w3hc/w3pk/issues/133)):
  - `mlkemEncrypt` writes `version: 2` payloads: the AES key is wrapped with AES-KW (RFC 3394) under a KEK derived from the ML-KEM shared secret with HKDF-SHA256 (info `w3pk-mlkem-kek-v2`); recipient ciphertexts grow from 1600 to 1608 bytes
  - `mlkemDecrypt` reads v2 and legacy v1 payloads (no `version`, XOR-wrapped key), rejects IVs that are not 12 bytes and auth tags that are not 16 bytes, and without a public key hint tries each recipient until one passes the authenticated checks
  - `EncryptedPayload` gains an optional `version` field

- **docs/SECURITY.md**: fixed the vulnerability-reporting channel (previously pointed at a nonexistent README email; now points to GitHub Security Advisories); added a section on EU Cyber Resilience Act disclosure timelines as they relate to w3pk (FOSS) vs. commercial integrators, with a brief note on the US and China regimes
- **docs/POST_QUANTUM.md**: refreshed the post-quantum roadmap to reflect current Ethereum PQ migration planning

## [0.10.2] - 2026-07-10

### Changed

- **Persistent sessions are now encrypted with WebAuthn PRF-derived keys** (renewal-boundary PRF):
  - `login()` and `register()` request the WebAuthn PRF extension with a fixed input, yielding a deterministic per-credential secret that only exists during a user-verified assertion
  - The persistent-session mnemonic blob is encrypted under an HKDF-SHA256 key derived from that secret — no longer under a key recomputable from stored `credentialId`/`publicKey`
  - `requireReauth: true`: the key is never stored; every restore re-derives it from a live assertion (blob is hardware-bound at rest)
  - `requireReauth: false`: the key is stored as a non-extractable `CryptoKey` for silent restore; re-keyed at every real (prompted) login — the persistent-session `duration` is the renewal interval
  - Authenticators without PRF support no longer get persistent sessions (in-memory sessions only); there is no fallback to weaker encryption
  - Persistent-session DB bumped to v3: pre-existing records (old encryption scheme) are dropped, users re-key with one normal login
  - Removed `encryptMnemonicForPersistence` / `decryptMnemonicFromPersistence`; `SessionManager.startSession` and `restoreFromPersistentStorage` now take a PRF-derived `CryptoKey` instead of a WebAuthn public key

### Added

- **ML-KEM Post-Quantum Encryption with Deterministic Key Derivation**:
  - **Instance Methods (Recommended)**:
    - `w3pk.deriveMLKemPublicKey(options?)` - Derive your ML-KEM public key for sharing
    - `w3pk.mlkemEncrypt(plaintext, recipientPublicKeys, options?)` - Encrypt for self + recipients
    - `w3pk.mlkemDecrypt(payload, options?)` - Decrypt encrypted data
    - Supports STANDARD, STRICT, and YOLO modes (PRIMARY mode not supported)
    - Default mode: STANDARD (private key never exposed to app)
  - **Deterministic Key Derivation**:
    - `deriveMLKemKeypair(privateKey, context)` - Derive ML-KEM keypair from Ethereum private key using HKDF-SHA256
    - Same input always produces same output (reproducible keys)
    - No need to store separate ML-KEM keys
  - **Low-Level Functions**:
    - `mlkemEncrypt()` - Encrypt data using ML-KEM-1024 + AES-256-GCM for one or multiple recipients
    - `mlkemDecrypt()` - Decrypt ML-KEM encrypted data with auto-detection of recipient
    - `mlkemEncryptWithKey()` - Convenience function with automatic key derivation
    - `mlkemDecryptWithKey()` - Convenience function with automatic key derivation
  - **Security Features**:
    - NIST FIPS 203 compliant (ML-KEM-1024)
    - Multi-recipient encryption - Encrypt once, multiple people can decrypt
    - HKDF-based deterministic derivation with domain separation
    - Hybrid encryption: KEM for key exchange + AES-256-GCM for data
    - Secure key zeroization - all secrets wiped from memory after use
    - Cross-platform compatible (browser and Node.js)
  - **Key Sizes**:
    - ML-KEM public key: 1568 bytes
    - ML-KEM private key: 3168 bytes
    - Ciphertext per recipient: 1600 bytes (1568 KEM + 32 encrypted AES key)

### Changed

- **`logout()` and `clearSession()` now surface persistent storage failures**: Previously, a failure to clear persistent sessions from IndexedDB was swallowed with a `console.warn`, so apps could believe a device was fully logged out while a persistent session remained. These methods now throw a `StorageError` in that case. The in-memory session is always cleared (and `onAuthStateChanged(false)` still fires) before the error propagates, so apps only need to handle the error if they want to inform the user or retry the cleanup. Internal expiry cleanup and the stale-session recovery path in `login()` are unaffected.

### Documentation

- **Updated `docs/POST_QUANTUM.md`**:
  - Added deterministic key derivation section
  - Added w3pk instance methods (recommended usage)
  - Added mode support matrix (STANDARD/STRICT/YOLO)
  - Comprehensive API reference for all ML-KEM functions
- **Updated `docs/API_REFERENCE.md`**:
  - Added instance methods section for ML-KEM
  - Added deterministic key derivation function
  - Reorganized into instance methods vs standalone functions
- **Updated CHANGELOG.md**: Documented ML-KEM feature addition with full details

## [0.9.3] - 2026-02-28

### Changed

- **BREAKING: Social Recovery Now Uses Backup File Fragments**: Completely redesigned social recovery system for improved security
  - Guardians now store fragments of encrypted backup files instead of mnemonic fragments
  - **Double encryption security model**: Backup file is encrypted with password (Layer 1), then split into shares (Layer 2)
  - Password is never shared with guardians - only the coordinator knows it
  - Recovery requires both threshold guardian shares AND the original password
  - Even if all guardians collude, they cannot decrypt the backup file without the password

- **SocialRecoveryManager API Changes**:
  - `setupSocialRecovery()` now takes `backupFileJson` instead of `mnemonic`
  - `recoverFromGuardians()` now returns `{ backupFileJson, ethereumAddress }` instead of `{ mnemonic, ethereumAddress }`
  - `addGuardian()` now requires `backupFileJson` parameter

### Security

- **Improved Guardian Security**: Guardians hold fragments of encrypted data only
  - Mathematically proven security with Shamir Secret Sharing (GF(256) polynomial interpolation)
  - Attack with threshold shares still requires password to decrypt
  - No single guardian or collusion of guardians can access wallet without password
  - Guardians can safely store shares in password managers (already encrypted)

### Documentation

- Updated `docs/RECOVERY.md` with new backup file-based social recovery flow
- Updated `docs/API_REFERENCE.md` with new `SocialRecoveryManager` API
- Updated guardian explainer text to clarify encrypted backup file fragments
- Added detailed cryptography section explaining double encryption model
- Updated all recovery workflow examples and FAQ

### Migration Guide

For existing host applications using social recovery:

**Before (v0.9.2 and earlier):**
```typescript
// Setup - splits mnemonic
const guardians = await setupSocialRecovery(guardiansList, threshold);

// Recovery - returns mnemonic
const { mnemonic } = await recoverFromGuardians(shares);
```

**After (v0.9.3+):**
```typescript
import { SocialRecoveryManager } from 'w3pk';

// Setup - create password-encrypted backup and split it
const { blob } = await w3pk.createBackupFile('password', 'MyPassword123!');
const backupFileJson = await blob.text();
const socialRecovery = new SocialRecoveryManager();
const guardians = await socialRecovery.setupSocialRecovery(
  backupFileJson,
  ethereumAddress,
  guardiansList,
  threshold
);

// Recovery - reconstruct backup file, then decrypt with password
const { backupFileJson } = await socialRecovery.recoverFromGuardians(shares);
await w3pk.registerWithBackupFile(backupFileJson, 'MyPassword123!', 'username');
```

## [0.9.2] - 2026-02-27

### Added

- **Post-Quantum Cryptography Documentation**: Comprehensive roadmap for quantum-safe migration
  - New `docs/POST_QUANTUM.md` document (formerly `QUANTUM_READINESS.md`)
  - Aligned with [Ethereum quantum resistance roadmap](https://x.com/VitalikButerin/status/2027075026378543132) (February 2026)
  - 4-phase migration strategy: EIP-7702 → ERC-4337 (interim) → EIP-8141 (long-term)
  - Gas cost estimates for post-quantum signatures (ERC-4337: ~300-850k gas, EIP-8141: near-zero with STARK aggregation)
  - Integration plan with [Ethereum Kohaku](https://github.com/ethereum/kohaku) for interim solution
  - Hash function selection discussion (Poseidon2/Poseidon1/BLAKE3)
  - Timeline: 18-36 months for full quantum-safe deployment
  - Active links to all EIPs, NIST standards, and research papers

### Documentation

- **Post-Quantum Cryptography section added to `docs/SECURITY.md`**: Summary of quantum threat, migration strategy, and link to detailed documentation
- **Updated `README.md`**: Added Post-Quantum Cryptography to documentation list
- **Security Inspection**: Added W3HC sponsorship acknowledgment for inspection API calls in `README.md` and `docs/SECURITY.md`

## [0.9.1] - 2026-02-26

### Added

- **Onchain Build Registry**: DAO-maintained version registry on OP Mainnet for decentralized build verification
  - Contract address: [`0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a`](https://optimistic.etherscan.io/address/0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a)
  - Host applications can verify W3PK builds against immutable onchain registry
  - Provides decentralized source of truth for official releases
  - DAO-controlled governance via contract ownership

### Changed

- **Build Verification Documentation**: Updated all documentation to reference onchain registry
  - `README.md`: Added onchain registry section with contract details
  - `docs/BUILD_VERIFICATION.md`: All examples now query onchain registry instead of hardcoded hashes
  - `docs/SECURITY.md`: Updated security best practices to use onchain verification
  - Replaced "on-chain" terminology with "onchain" throughout

### Documentation

- Updated integration examples to show onchain registry verification pattern
- Added OP Mainnet registry contract information across all relevant docs
- Clarified that host applications (not SDK) should perform build verification

## [0.9.0] - 2026-02-26

### Added

- **Security Inspection Module**: AI-powered analysis of web3 applications to identify transaction and signing methods
  - Browser-based inspection: `inspect()` and `inspectNow()` - analyze running apps from browser console or app code
  - Node.js inspection: `gatherCode()` and `inspect()` - scan local application files for security analysis
  - Integration with Rukh API for AI-powered security report generation
  - Focus modes: analyze all code or focus on transaction/signing operations only
  - Keyword-based filtering for transaction-relevant code (signMessage, sendTransaction, Contract interactions, etc.)
  - Smart snippet extraction with context for efficient analysis
  - Export via `w3pk/inspect` (browser) and `w3pk/inspect/node` (Node.js)
  - Comprehensive JSDoc documentation for all inspection APIs
  - TypeScript types: `BrowserInspectOptions`, `BrowserInspectResult`, `InspectOptions`, `InspectResult`

- **`getEIP1193Provider()` method**: Returns an EIP-1193 compatible provider backed by the SDK, enabling direct integration with ethers `BrowserProvider`, viem's `custom` transport, wagmi connectors, RainbowKit, and any other EIP-1193 consumer
  - Supported methods: `eth_accounts`, `eth_requestAccounts`, `eth_chainId`, `eth_sendTransaction`, `personal_sign`, `eth_sign`, `eth_signTypedData_v4`, `wallet_switchEthereumChain`
  - Emits `chainChanged` event on `wallet_switchEthereumChain`; supports `on` / `removeListener`
  - Multiple independent instances (each with its own `chainId` state)
  - `options.mode`, `options.tag`, `options.chainId`, `options.rpcUrl` for full control
  - Unsupported methods throw a descriptive `WalletError`

- **`sendTransaction()` method**: New SDK method for sending on-chain transactions using the derived wallet for any security mode (STANDARD, STRICT, YOLO)
  - Mirrors the same authentication and derivation flow as `signMessage()` — session management, mode/tag/origin resolution, STRICT-mode re-auth
  - Accepts `to`, `value` (wei), `data` (hex calldata), `chainId` (required), plus optional overrides: `gasLimit`, `maxFeePerGas`, `maxPriorityFeePerGas`, `nonce`
  - Auto-resolves RPC endpoint via `getEndpoints(chainId)` from chainlist; override with `options.rpcUrl`
  - Returns `{ hash, from, chainId, mode, tag, origin }` — the same metadata shape as other signing methods
  - PRIMARY mode throws a descriptive error with guidance to use `signMessageWithPasskey()` + a bundler (full bundler integration deferred to v2)
  - Throws `WalletError` with clear messages for: unauthenticated user, no RPC for chainId, PRIMARY mode without rpcUrl

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
