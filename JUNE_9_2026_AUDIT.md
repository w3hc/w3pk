# Security Audit — w3pk

**Target:** `w3pk` — Passwordless Web3 authentication SDK (encrypted wallets, privacy features)
**Repository:** https://github.com/w3hc/w3pk
**Version reviewed:** `0.10.1` (source at commit `b0fce4a`)
**License:** GPL-3.0
**Audit type:** Independent source-code review (manual, white-box)
**Audit date:** June 9, 2026 — **revised July 8, 2026** to reflect PR #126 (PRF removal), PR #124 (inspection size limits), and commit `b0fce4a` (session-clear error surfacing)
**Auditor:** Claude (Anthropic) — automated assistant review

---

## 1. Disclaimer & scope

This is an informal code review intended to surface security-relevant observations. It is **not** a substitute for a professional, paid audit by a specialized firm (e.g. Trail of Bits, Cure53, Least Authority, OpenZeppelin), nor for a formal cryptographic review. No dynamic testing, fuzzing, or runtime instrumentation was performed; findings are based on static reading of the TypeScript source.

**In scope:** the SDK source under `src/` — key derivation and encryption (`src/wallet/crypto.ts`), wallet generation and origin derivation, IndexedDB storage, session management, password-based backups (`src/backup/`), Shamir social recovery (`src/recovery/`), the host-app inspection feature (`src/inspect/`), and the public API surface in `src/core/sdk.ts`.

**Out of scope:** the on-chain build registry contract, the live demo site, the Rukh API backend, the WebAuthn authenticator/browser implementation itself, third-party dependencies (`ethers`, ML-KEM library, circom toolchain), and the ZK circuits' soundness.

---

## 2. Executive summary

w3pk is an ambitious, feature-rich SDK. Several design choices are commendable: AES-256-GCM for all symmetric encryption, PBKDF2 iteration counts aligned to OWASP guidance (210k for wallet keys, 310k for backups), random per-ciphertext IVs, and a from-scratch Shamir implementation over GF(256) for social recovery.

However, the most security-critical property — protecting the wallet mnemonic at rest — is not delivered. The original June 9 review described an insecure key derivation (AES key derived from the **public** credential ID and public key with a **hardcoded salt**) as a "legacy fallback" alongside an in-progress WebAuthn PRF migration. That framing is now obsolete: PR #126 ("Remove PRF enforcement", merged June 9) **deleted the PRF-based derivation entirely**. The public-data derivation, renamed `deriveEncryptionKeyFromWebAuthn`, is now the *sole* key-derivation path for every persisted secret — wallet mnemonics, persistent sessions, backups, and the sync vault. What was a reachable fallback is now the intentional design.

The practical consequence is unchanged and remains critical: an attacker with read access to the victim's IndexedDB (malicious extension, XSS, forensic/shared device access, storage sync leakage) can reconstruct the encryption key from public values and decrypt the mnemonic offline, without the authenticator and without any biometric/PIN interaction. The biometric/PIN prompt gates the *UX flow*, not the *cryptography*. Compounding this, the code comments and `docs/SECURITY.md` now describe this scheme as "authentication-gated encryption" and "hardware-backed security" (F-2), which materially overstates what it provides.

### Findings at a glance

| ID | Severity | Title | Status since June 9 |
|----|----------|-------|---------------------|
| F-1 | **Critical** | Sole key-derivation path derives AES keys from public data; mnemonic decryptable offline | Worsened — PRF path deleted (PR #126); this is now the only path |
| F-2 | **High** | Docs and code comments claim "authentication-gated"/"hardware-backed" encryption the KDF does not provide | Reframed — replaces the now-moot registration/migration finding |
| F-3 | **High** | Host-app inspection transmits source code (incl. potential secrets) to a third-party API | Partially mitigated — PR #124 added size caps and a README privacy notice |
| F-4 | **Medium** | YOLO mode exposes raw private keys to the host application | Unchanged |
| F-5 | **Medium** | Hardcoded salts defeat PBKDF2's purpose in the primary (and only) derivation path | Worsened — no longer confined to legacy branches |
| F-6 | **Medium** | Shamir implementation is unauthenticated and not constant-time | Unchanged |
| F-7 | **Low** | Device "fingerprint" presented as a binding control but explicitly weak | Unchanged |
| F-8 | **Low** | Password strength validation is shallow (no breach/entropy check, substring-only common-list) | Unchanged |
| F-9 | **Informational** | Broad sensitive material handled as JS strings (non-zeroizable); persistent sessions widen exposure window | Slightly improved — `b0fce4a` surfaces persistent-session clear failures |

---

## 3. Detailed findings

### F-1 — Sole key-derivation path derives AES keys from public data *(Critical)*

**Location:** `src/wallet/crypto.ts` → `deriveEncryptionKeyFromWebAuthn` (lines 21–66); consumed at every persistence call site: `src/core/sdk.ts` (8 sites), `src/backup/backup-file.ts` (4), `src/sync/vault.ts` (2), `src/core/persistent-session.ts` (2).

Since PR #126, the only key derivation in the SDK is:

```
key = PBKDF2(SHA-256("w3pk-v4:" + credentialId + ":" + publicKey), salt = SHA-256("w3pk-salt-v4"), 210k iters)
```

The credential ID and the public key are **not secrets** — the credential ID is a public WebAuthn handle and the public key is, by definition, public. Both are stored alongside the ciphertext in the same IndexedDB. PBKDF2 over public, low-entropy input with a fixed salt provides essentially no protection: anyone who can read the stored ciphertext can also read the inputs needed to reconstruct the key and decrypt the mnemonic offline, entirely bypassing the authenticator and any biometric/PIN gate.

The previous PRF-based derivation (authenticator-held secret, random 32-byte per-ciphertext salt) and the `deriveEncryptionKeyAuto` dispatcher were deleted in PR #126; there is no code path in which decryption cryptographically requires the authenticator. The runtime `console.warn` that used to flag this path was also removed, so the derivation now executes silently.

A dead v2 variant (`deriveEncryptionKey`, salt `"w3pk-salt-v2"`) remains in the file with no call sites.

**Impact:** Full compromise of the wallet seed (all derived addresses/keys) for **every** user, given local storage read access (malicious extension, XSS in an embedding origin, shared/forensic device access, sync/backup leakage). This is no longer a lifecycle edge case — it is the design.

**Recommendation:**
- Derive persistence keys only from secret material: reintroduce WebAuthn PRF output (with a random per-ciphertext salt) as the KDF input, and where PRF is unavailable require a user-set password instead. Never persist a mnemonic under a key derived from public values.
- Delete `deriveEncryptionKeyFromWebAuthn` in its current form along with the dead v2 `deriveEncryptionKey`. Since backward compatibility is not a requirement for this project, no fallback branch or storage-format migration is needed — remove the old scheme outright and let existing test data be regenerated.

---

### F-2 — Documentation and code comments overstate at-rest protection *(High)*

**Location:** `src/wallet/crypto.ts` header ("Requires biometric/PIN authentication", "Hardware-backed security") and `deriveEncryptionKeyFromWebAuthn` docstring ("Authentication-gated encryption via biometric/PIN"); `docs/SECURITY.md` ("Encrypted storage — AES-256-GCM encryption at rest", "Persistent session encryption — WebAuthn-derived key encryption"); README security framing.

The June 9 version of this finding concerned registration storing the mnemonic under the legacy key with no re-encryption to PRF on first login. PR #126 removed the PRF path entirely, so that finding is moot; what replaces it is a documentation-integrity problem of comparable severity.

After #126, the code and docs continue to describe the encryption as authentication-gated and WebAuthn/hardware-backed. Cryptographically it is neither: the biometric/PIN ceremony gates the SDK's *control flow*, but the AES key is computable from data at rest (F-1), so an attacker who bypasses the SDK (reads IndexedDB directly) faces no authenticator requirement at all. For a security SDK, claims of this kind are load-bearing — integrators will make threat-model decisions (e.g. "safe on shared devices", "safe if IndexedDB leaks") based on them.

**Impact:** Integrators and end users are given a false model of the at-rest protection, leading to misplaced reliance (e.g. storing high-value seeds, enabling long persistent sessions) that the actual cryptography does not support.

**Recommendation:**
- Until F-1 is fixed, state plainly in `docs/SECURITY.md`, the README, and the `crypto.ts` comments that at-rest encryption keys are derived from credential metadata stored alongside the ciphertext, and that local-storage read access defeats it.
- Once F-1 is fixed, make the docs describe the actual KDF inputs and threat model rather than the authentication UX.

---

### F-3 — Host-app inspection transmits source code to a third-party API *(High, partially mitigated)*

**Location:** `src/inspect/node.ts` (`gatherCode`, `inspect` → `fetch(\`${rukhUrl}/ask\`)`), `src/inspect/browser.ts`.

The inspection feature gathers application source files and POSTs them to `https://rukh.w3hc.org/ask` for AI analysis. The README notes calls are "sponsored by W3HC."

**Mitigations since June 9 (PR #124):** collection is now capped at 100 KB total by default (`maxTotalSizeKB`, on top of the 500 KB per-file cap), and the README carries a privacy notice stating that source code and the user's IP are visible to the external API. These reduce volume and improve disclosure.

**Remaining gaps:** the caps limit *how much* leaves the machine, not *what*. The default include patterns sweep `**/*.json` — a common home for service-account keys, API tokens, and deployment credentials — and there is still no secret-file exclusion, no high-entropy-token redaction, and no per-run consent prompt; the notice lives only in the README. The destination remains a third-party service outside the developer's trust boundary.

**Recommendation:**
- Exclude common secret-bearing files by default (`.env*`, `*.pem`, `id_*`, `*.key`, credential-looking JSON) and scan/redact high-entropy tokens before transmission.
- Require explicit opt-in consent at the call site (not just README text) and offer a self-hosted endpoint option.
- Default to dry-run output (what *would* be sent) so users can review before any network call.

---

### F-4 — YOLO mode exposes raw private keys to the host app *(Medium)*

**Location:** `src/core/sdk.ts` `deriveWallet('YOLO', …)` returns `privateKey`; signing paths use it directly.

YOLO mode hands the derived private key to the embedding application. This is documented and intentional ("advanced use cases"), but it negates the SDK's core isolation guarantee for that tag, and a compromised or malicious host origin gains a spendable key. STANDARD/STRICT correctly keep the key inside the SDK.

**Impact:** Any XSS or malicious code in a YOLO-using origin can steal the private key for that tag.

**Recommendation:** Keep YOLO clearly gated and loud in docs; consider requiring an explicit per-call opt-in flag and emitting a one-time runtime warning. Ensure YOLO-derived keys are isolated to their tag (they are, via origin/mode/tag derivation) so blast radius is limited to that tag, and document that explicitly.

---

### F-5 — Hardcoded salts in the primary derivation path *(Medium)*

**Location:** `src/wallet/crypto.ts` (`"w3pk-salt-v4"` in `deriveEncryptionKeyFromWebAuthn`; `"w3pk-salt-v2"` in the dead `deriveEncryptionKey`).

A static salt means PBKDF2 provides no protection against precomputation across users, and combined with public input (F-1) the 210k iterations buy nothing. The June 9 review noted this was confined to legacy branches while the modern path used random 32-byte salts via `generateSalt()`; PR #126 deleted both the modern path and `generateSalt()`, so the hardcoded salt is now in the **only** derivation the SDK performs.

This finding is kept separate from F-1 because it must be fixed independently: even after moving to secret KDF input, a per-ciphertext random salt (stored with the ciphertext) is required.

**Recommendation:** Remove both hardcoded salts along with the functions that contain them (see F-1 — no compatibility path is needed). Any replacement KDF must use a random per-ciphertext salt stored alongside the ciphertext.

---

### F-6 — Shamir secret sharing is unauthenticated and not constant-time *(Medium)*

**Location:** `src/recovery/shamir.ts`.

The GF(256) implementation looks structurally correct (primitive polynomial `0x11b`, generator 3, Lagrange interpolation). Two concerns:

1. **No integrity/authentication on shares.** A malicious or corrupted guardian share is not detected; reconstruction silently yields a wrong secret (or, in adversarial settings, an attacker who controls enough shares can influence the result without detection). Consider committing to the secret (e.g. include an authenticated hash/MAC of the reconstructed value) so tampering is caught.
2. **Table-lookup multiply/divide are not constant-time.** Timing side-channels are largely theoretical in a browser JS context but worth noting for a security-critical primitive.

Also confirm shares are transmitted/stored only in encrypted form; the recovery flow reconstructs an *encrypted backup file*, which is good, but guardian-side handling should be documented.

**Recommendation:** Add authenticated reconstruction (verify a stored commitment of the secret). Document the threat model for guardians. Consider a reviewed library or VSS scheme if stronger guarantees are needed.

---

### F-7 — Device fingerprint marketed as binding but explicitly weak *(Low)*

**Location:** `src/backup/encryption.ts` `getDeviceFingerprint()`.

The fingerprint is a SHA-256 of `userAgent | language | timezone | screen size | colorDepth`. The code honestly comments it is "NOT cryptographically strong." It is trivially spoofable and unstable across browser updates. As long as it is never used as an actual access-control or key-binding control this is acceptable, but ensure UI/docs don't imply it secures backups.

**Recommendation:** Use only as a non-security UX hint (e.g. "this backup was made on a different device"). Do not feed it into any key derivation.

---

### F-8 — Shallow password-strength validation *(Low)*

**Location:** `src/backup/encryption.ts` `validatePasswordStrength`, `src/utils/validation.ts` `isStrongPassword`.

Validation is composition-rule based (length + character classes) with a tiny `commonPasswords` substring list. It does not estimate entropy (e.g. zxcvbn) or check against breach corpora, so predictable passwords meeting the rules (e.g. `Password1!Password1!`) pass with high scores. Since backup security ultimately rests on this password (PBKDF2 310k is good but not magic), weak passwords are the practical limiting factor. If a user password becomes the wallet-KDF input per the F-1 recommendation, this validation becomes correspondingly more security-critical.

**Recommendation:** Integrate an entropy estimator (zxcvbn-style) and optionally a k-anonymity breach check (HIBP range API). Raise the effective bar for backup passwords specifically.

---

### F-9 — Sensitive material as non-zeroizable JS strings; session exposure window *(Informational)*

Mnemonics and private keys are handled as JavaScript strings, which cannot be reliably zeroized and may linger in the GC heap, dev tools, or memory dumps. Persistent sessions with `requireReauth: false` and long durations (the README shows 30 days) keep decrypted material reachable for extended periods. STRICT mode correctly forbids persistent sessions.

**Improvement since June 9:** commit `b0fce4a` (July 8) makes `logout()` and `clearSession()` surface persistent-session clear failures as a `StorageError` instead of failing silently, while still clearing the in-memory session and firing the auth-state callback — so an app can now detect that encrypted session material may remain on the device. `SessionManager.clearSession()` also overwrites the in-memory mnemonic before releasing it.

**Recommendation:** Minimize lifetime of plaintext secrets; prefer `Uint8Array` buffers that can be overwritten where feasible; default persistent-session durations conservatively and document the trade-off prominently.

---

## 4. Positive observations

- **AES-256-GCM** everywhere for symmetric encryption, with random 12-byte IVs prepended to ciphertext.
- **PBKDF2 iteration counts** align with current OWASP guidance (210k wallet / 310k backup, SHA-256).
- **Origin/mode/tag key isolation** via SHA-256-derived BIP32 indices gives clean per-origin, per-tag address separation; origin normalization handles default ports sensibly.
- **Master mnemonic is not exposed** through the public API (`exportMnemonic` is not surfaced to apps), and STANDARD/STRICT keep private keys inside the SDK.
- **Inspection data volume is now bounded** (100 KB total by default since PR #124) with a README privacy notice.
- **Session-clear failures are now observable** (commit `b0fce4a`) instead of silently swallowed, and the in-memory mnemonic is overwritten on clear.
- **Reproducible-build / on-chain registry** intent and the self-inspection tooling show a mature security posture overall.

*(The June 9 review credited the WebAuthn PRF extension as the intended key source; that credit is withdrawn — PR #126 removed PRF support.)*

---

## 5. Prioritized recommendations

1. **Replace the key derivation (F-1, F-2, F-5).** Reintroduce a secret-input KDF — WebAuthn PRF output, or a user-set password where PRF is unavailable — with random per-ciphertext salts, and delete the public-data derivation and both hardcoded salts outright. No compatibility or migration layer is needed; a clean break in the storage format is acceptable for this project.
2. **Correct the security claims (F-2)** in `docs/SECURITY.md`, the README, and `crypto.ts` comments so they describe what the cryptography actually binds to, not the authentication UX.
3. **Finish hardening the inspection feature (F-3):** secret-file exclusion (especially under the default `**/*.json` pattern), redaction, explicit per-run consent, self-host option, dry-run default. The size caps from PR #124 are a good start.
4. **Authenticate Shamir reconstruction (F-6)** and document the guardian threat model.
5. **Strengthen password validation (F-8)** with entropy/breach checks — this becomes critical if a password becomes the wallet-KDF input per recommendation 1.
6. **Tighten defaults (F-9):** conservative persistent-session lifetimes, minimize plaintext-secret lifetime.
7. **Commission a professional audit** before any production use protecting real funds, including a cryptographer review of the ZK circuits and ML-KEM integration, which were out of scope here.

---

## 6. Methodology

Manual static review of the `main` branch source (TypeScript) focused on key management, encryption, storage, recovery, and data-egress paths, cross-referenced against the README's claimed feature set. Severity reflects a combination of impact (seed/key compromise being highest) and reachability under default configuration. No execution, dependency analysis, or on-chain/contract review was performed.

**Revision note (July 8, 2026):** the original June 9 review was written against a tree that still contained the WebAuthn PRF derivation path. Later the same day, PR #126 removed PRF support, invalidating the original F-1/F-2/F-5 framing ("legacy fallback", "incomplete migration"). This revision re-reads the source at commit `b0fce4a` and restates those findings against the current design; F-3 and F-9 were updated for PR #124 and commit `b0fce4a` respectively. Finding IDs are kept stable with the June 9 version.

*This review reflects the state of the repository at commit `b0fce4a` and may not match later commits or published npm artifacts. Verify the installed build against the project's on-chain registry before relying on it.*
