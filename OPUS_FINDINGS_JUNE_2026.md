# w3pk Security Audit Findings

**Target:** [w3hc/w3pk](https://github.com/w3hc/w3pk) — `114-audit` branch
**Commit:** `c82a69affb472598babd7570c3e57613a84e7162`
**Scope:** `src/` per README, excluding `src/inspect`, `src/zk`, `src/education`, plus the
`docs`, `examples`, `scripts`, `standalone`, and `test` folders. Solidity contract excluded.
**Codebase size:** ~11,904 lines of TS/JS in scope.

> This document is an independent code review, **not** a substitute for a full professional
> audit. It reflects manual reading of the security-critical modules (wallet/key derivation,
> backup encryption, Shamir recovery, social recovery, stealth addresses, origin derivation,
> SIWE, sync, persistent sessions). It has not been fuzzed, formally verified, or run against
> a test suite. Absence of a finding in a module is not proof that module is safe.

---

## Severity summary

| # | Severity | Finding | Location |
|---|----------|---------|----------|
| 1 | Critical | Wallet encryption key derived entirely from public WebAuthn data | `src/wallet/crypto.ts` |
| 2 | Critical | Broken `recoverFromShares` threshold logic in backup-based recovery | `src/recovery/backup-based-recovery.ts` |
| 3 | High | Hardcoded constant salt in WebAuthn KDF | `src/wallet/crypto.ts` |
| 4 | High | Stealth scalars not reduced mod curve order (ERC-5564) | `src/stealth/crypto.ts` |
| 5 | Medium | GF(256) table construction in Shamir needs verification | `src/recovery/shamir.ts` |
| 6 | Medium | Shamir share combination has no integrity/authenticity check | `src/recovery/shamir.ts`, recovery managers |
| 7 | Medium | P-256 → Ethereum address derivation skips EIP-55 checksum | `src/wallet/origin-derivation.ts` |
| 8 | Medium | Origin-derived index uses only 32 bits of SHA-256 with modulo bias | `src/wallet/origin-derivation.ts` |
| 9 | Medium | Persistent sessions: at-rest mnemonic protection inherits findings #1/#3 | `src/core/persistent-session.ts` |
| 10 | Low | Weak password-strength acceptance threshold | `src/backup/encryption.ts` |
| 11 | Low | Guardian shares transported/stored with weak handling guidance | `src/recovery/social.ts` |
| 12 | Low | SIWE parser is hand-rolled and diverges from EIP-4361 ABNF | `src/siwe/index.ts` |
| 13 | Low | Device fingerprint and sync-method detection are spoofable | `src/backup/encryption.ts`, `src/sync/*` |
| 14 | Info | Deprecated `deriveEncryptionKey` (v2) still present | `src/wallet/crypto.ts` |
| 15 | Info | `console.error`/`console.warn` may leak diagnostic detail | multiple |

---

## 1. Critical — Wallet encryption key derived entirely from public WebAuthn data

**File:** `src/wallet/crypto.ts` — `deriveEncryptionKeyFromWebAuthn`

The AES-GCM key protecting the BIP39 mnemonic is derived solely from `credentialId` and,
optionally, the WebAuthn `publicKey`:

```
keyMaterial = `w3pk-v4:${credentialId}:${publicKey}`
```

Both inputs are **public**. The WebAuthn `credential.id` is transmitted in the clear and stored
next to the ciphertext (`src/auth/authenticate.ts` persists `credentialId: credential.id`); the
public key is public by definition. The biometric/PIN prompt gates only the *ceremony*, not the
key material — no authenticator secret (PRF / `hmac-secret` output, signature, UV-derived value)
enters the KDF.

**Impact:** Anyone holding the ciphertext plus the credential ID (which travels with it) can
recompute the key offline and decrypt the mnemonic. The 210,000 PBKDF2 iterations add nothing
because the "password" is a known constant. This is a full break of the WebAuthn-protected
encryption.

**Propagation:** the same primitive is reused in `src/sync/vault.ts` (`createSyncPackage` /
`restoreFromSync`), `src/sync/backup-sync.ts` (passkey export/import), and
`src/core/persistent-session.ts`. All inherit the weakness.

**Recommendation:** Use the WebAuthn **PRF extension** (or `hmac-secret`) to obtain a
per-credential secret that never leaves the authenticator and feed that into the KDF. The
encryption key must depend on a value an attacker holding the ciphertext cannot reconstruct.

---

## 2. Critical — Broken `recoverFromShares` threshold logic

**File:** `src/recovery/backup-based-recovery.ts` — `SocialRecovery.recoverFromShares`

This method calls `combineShares(shareBytes, shares.length)` — it passes the **number of shares
provided** as the threshold, rather than the **threshold the secret was actually split with**.

```
const recoveredBytes = combineShares(shareBytes, shares.length);
```

In `shamir.ts`, `combineShares(shares, threshold)` uses `shares.slice(0, threshold)` and
Lagrange-interpolates assuming the polynomial degree is `threshold - 1`. If the caller supplies
a number of shares different from the original split threshold, interpolation reconstructs the
**wrong** secret (silently, since GF(256) interpolation always returns *a* value). The only thing
catching it afterward is a JSON-parse + address-match check, which will usually throw "invalid
shares" — but can in principle yield a corrupted-but-parseable result.

The companion implementation in `src/recovery/social.ts` (`recoverFromGuardians`) does this
**correctly**, reading `threshold` from the embedded share metadata. The two recovery managers
are inconsistent, and the `backup-based-recovery.ts` one is wrong.

**Impact:** Recovery via this code path fails (or, worst case, mis-reconstructs) whenever the
number of presented shares ≠ the original threshold — which is the normal case when more than the
minimum number of guardians respond. Loss-of-access risk for funds protected by social recovery.

**Recommendation:** Embed the original `threshold` in each share's metadata and always pass that
value to `combineShares`. Add round-trip tests for `M < provided ≤ N`.

---

## 3. High — Hardcoded constant salt in WebAuthn KDF

**File:** `src/wallet/crypto.ts` — `deriveEncryptionKeyFromWebAuthn` (and deprecated
`deriveEncryptionKey`)

The PBKDF2 salt is a fixed value derived from the literal string `"w3pk-salt-v4"` (and
`"w3pk-salt-v2"`). A constant, globally known salt gives no per-user separation and permits
precomputation across all users.

**Note:** the password-based backup path in `src/backup/encryption.ts` does this correctly
(random per-encryption salt). The WebAuthn path should follow that pattern.

**Recommendation:** Generate a random unique salt per encryption and store it with the ciphertext.

---

## 4. High — Stealth scalars not reduced modulo the curve order

**File:** `src/stealth/crypto.ts` — `multiplyGeneratorByScalar`, `addPrivateKeys`

The ERC-5564 routines hash the ECDH shared secret with `keccak256` and use the raw 32-byte result
directly as a secp256k1 scalar:

- `multiplyGeneratorByScalar(hashedSharedSecret)` calls `new ethers.Wallet(scalar)` on the raw
  hash. If the hash is `0` or `≥ n` (curve order), ethers throws — a small but nonzero failure
  probability per announcement, producing intermittent, hard-to-reproduce errors.
- `addPrivateKeys` reduces `(k1 + k2) mod n` correctly, but the `s_h` term entering it is the
  unreduced hash; the spec computes `s_h` as a scalar and consistency between the public-key side
  (`s_h × G`) and the private-key side (`spending_privkey + s_h`) requires the **same reduced
  scalar** be used on both sides.

Because the public-key path (`multiplyGeneratorByScalar`) and the private-key path
(`addPrivateKeys`) treat `s_h` inconsistently with respect to reduction, there is risk that a
derived stealth address cannot be spent by the derived private key in edge cases.

**Additional concern:** `addPublicKeys` implements raw secp256k1 point addition in `BigInt` with
no handling for the point-at-infinity case (`x1 === x2 && y1 !== y2`), and uses `computeSharedSecret`
returning a value treated as the ECDH x-coordinate hashed directly — verify it matches the ERC-5564
shared-secret definition (the standard hashes the compressed shared point, conventions vary).

**Impact:** Potentially unspendable stealth funds in edge cases; intermittent failures.

**Recommendation:** Reduce `s_h` mod `n` once, reject `0`, and use that single reduced scalar on
both the public-key and private-key sides. Use a vetted secp256k1 library (e.g. `@noble/secp256k1`)
for point/scalar arithmetic rather than hand-rolled BigInt math, and add cross-check tests asserting
`address(stealthPrivKey) === stealthAddress` over many randomized runs.

---

## 5. Medium — GF(256) table construction in Shamir needs verification

**File:** `src/recovery/shamir.ts` — `GF256`

Log/exp tables are built for indices 0–254 followed by `EXP_TABLE[255] = EXP_TABLE[0]`. `divide`
computes `(LOG[a] - LOG[b] + 255) % 255` (range 0–254) and `multiply` reduces by `% 255`, so the
`EXP_TABLE[255]` entry is dead but harmless. The real risk is that a subtle off-by-one in field
construction silently corrupts recovered secrets without throwing.

**Recommendation:** Add an exhaustive round-trip test
(`combineShares(splitSecret(x, t, n), t) === x`) over all 256 byte values and representative
`(t, n)` pairs, plus known-answer vectors against a reference implementation. Gate the recovery
feature on this.

---

## 6. Medium — Shamir share combination has no integrity/authenticity check

**Files:** `src/recovery/shamir.ts` (`combineShares`); `src/recovery/social.ts`,
`src/recovery/backup-based-recovery.ts`

`combineShares` blindly takes the first `threshold` shares and interpolates. A single corrupted or
maliciously crafted share silently yields a wrong secret. Downstream JSON-parse + address-match
checks catch *most* corruption but are not cryptographic integrity guarantees, and a malicious
guardian can grief recovery by submitting a bad share that's indistinguishable until reconstruction
fails.

**Recommendation:** Use an authenticated share format — e.g. include a hash commitment to the
secret and/or a per-share MAC so individual shares can be validated before combination, and so a
bad share can be attributed.

---

## 7. Medium — P-256 → Ethereum address derivation skips EIP-55 checksum

**File:** `src/wallet/origin-derivation.ts` — `deriveAddressFromP256PublicKey`

The function returns `'0x' + hash.slice(-40)` directly (lower-case, unchecksummed), unlike the rest
of the codebase which uses `ethers.getAddress(...)`. Downstream comparisons that assume EIP-55
checksumming (e.g. strict equality against a checksummed address) can produce false mismatches, and
unchecksummed addresses surfaced to users reduce typo protection.

**Recommendation:** Wrap the result in `ethers.getAddress(...)`.

---

## 8. Medium — Origin-derived index uses 32 bits of SHA-256 with modulo bias

**File:** `src/wallet/origin-derivation.ts` — `deriveIndexFromOriginModeAndTag`

The derivation reads only the first 4 bytes of the SHA-256 digest (`getUint32(0)`) and computes
`uint32 % MAX_INDEX` where `MAX_INDEX = 0x7fffffff`. Two issues: (a) only 32 bits of entropy feed
the index, and (b) `2^32 % (2^31 - 1)` introduces a small modulo bias toward low indices. While
BIP32 non-hardened indices are inherently public and this is not a secret, collisions between
distinct (origin, mode, tag) tuples would map two different sites to the **same** derived wallet,
which is a correctness/privacy concern.

**Recommendation:** Document the collision model explicitly, or widen the index space and use
rejection sampling instead of modulo to remove bias.

---

## 9. Medium — Persistent sessions inherit the WebAuthn at-rest weakness

**File:** `src/core/persistent-session.ts`

Persistent sessions store an `encryptedMnemonic` in IndexedDB, encrypted via
`deriveEncryptionKeyFromWebAuthn` (findings #1/#3). The module correctly refuses to persist
`STRICT` mode and enforces expiry, but "remember me" here means a mnemonic encrypted with public
inputs sits at rest in the browser. The `credentialId` is also stored in the same record, i.e. the
ciphertext and the (public) key-derivation input live together.

**Recommendation:** Fix #1/#3 first; persistent sessions are only as strong as the underlying KDF.
Consider also requiring a fresh WebAuthn assertion (UV) to unwrap the session even when "remember
me" is on.

---

## 10. Low — Weak password-strength acceptance threshold

**File:** `src/backup/encryption.ts` — `validatePasswordStrength`

Accepts `valid: true` at `score >= 50` with no remaining feedback — satisfiable with length plus
two character classes, weak for a wallet backup password.

**Recommendation:** Raise the bar and/or adopt an entropy estimator (e.g. zxcvbn) instead of a
heuristic score.

---

## 11. Low — Guardian-share handling guidance encourages risky storage

**File:** `src/recovery/social.ts` (and `backup-based-recovery.ts`)

The generated guardian explainer text states shares are "Safe to store digitally" and suggests
screenshots. While a single share below threshold is individually useless, the human-facing copy
underplays that an attacker collecting `threshold` shares (e.g. via compromised cloud backups of
several guardians) fully reconstructs the **password-encrypted** backup — whose password may itself
be weak (finding #10). Guidance should emphasize that shares are sensitive and that the backup
password is the last line of defense.

**Recommendation:** Tighten the guardian instructions; recommend offline/encrypted storage and warn
against screenshots/unencrypted cloud.

---

## 12. Low — Hand-rolled SIWE parser diverges from EIP-4361 ABNF

**File:** `src/siwe/index.ts` — `parseSiweMessage` / `validateSiweMessage`

The parser splits on lines and pattern-matches prefixes rather than following the EIP-4361 ABNF.
Edge cases (statements containing lines that begin with field prefixes, missing/optional-field
ordering, CRLF vs LF, resources block termination) can be mis-parsed. SIWE messages are a security
boundary for authentication; parser ambiguity can enable confusion between what a user signed and
what a server validates. `validateSiweMessage` also does not verify the signer address against the
recovered signature (out of this function's scope, but worth confirming the caller does).

**Recommendation:** Use a maintained SIWE library (e.g. the `siwe` package or viem's helpers), or
add a conformance test corpus. Ensure callers always verify the signature recovers to `address`.

---

## 13. Low — Device fingerprint and platform detection are spoofable

**Files:** `src/backup/encryption.ts` (`getDeviceFingerprint`), `src/sync/*` (UA sniffing)

`getDeviceFingerprint` is already documented as non-cryptographic; confirmed it must never enter key
material (it currently does not). Sync-method/platform detection relies on `navigator.userAgent`
substring checks, which are trivially spoofable and brittle. These are used only for UX routing, so
impact is low, but they should not gate any security decision.

**Recommendation:** Keep fingerprint strictly out of key derivation; treat platform detection as a
non-authoritative hint.

---

## 14. Info — Deprecated v2 KDF still present

**File:** `src/wallet/crypto.ts` — `deriveEncryptionKey`

The `@deprecated` v2 derivation remains exported and shares the same structural flaws as #1/#3
(public inputs + constant salt). Dead crypto paths are a foot-gun.

**Recommendation:** Remove once migration is complete, or clearly fence it behind a one-way
migration routine.

---

## 15. Info — Diagnostic logging

Several modules use `console.error` / `console.warn` (e.g. `device-manager.ts`, `social.ts`,
sync paths). Confirm no secret material (mnemonic, private key, share data, credential secrets) is
ever logged, including in error objects passed to the custom `*Error` wrappers.

---

## Overall assessment

The architecture (WebAuthn-gated wallet, password-encrypted backup files, Shamir social recovery,
ERC-5564 stealth, origin-scoped derivation) is reasonable, and the **password-based** backup
encryption is implemented to a good standard (random salt, AES-256-GCM, 310k PBKDF2 iterations).

However, the **WebAuthn-protected** confidentiality story is fundamentally broken (#1, #3, #9): the
key is derived from public values, so any party holding the stored ciphertext can decrypt it. There
is also at least one **correctness bug in social recovery** (#2) that can prevent legitimate
recovery, and the **hand-rolled cryptography** in stealth addresses (#4) and Shamir (#5/#6) needs
either replacement with vetted libraries or exhaustive test coverage before it can be trusted with
funds.

**Recommendation:** Treat findings #1, #2, #3, and #4 as release blockers. After remediation, this
code should still undergo a full third-party audit (with fuzzing and known-answer vectors for all
crypto primitives) before being used to store meaningful value.