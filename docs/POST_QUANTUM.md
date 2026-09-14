# Post-Quantum Cryptography

## Executive Summary

w3pk's data-encryption layer is already post-quantum: **ML-KEM-1024** (NIST FIPS 203) ships today for encrypting data at rest and in transit. What remains quantum-vulnerable is **transaction signing** — secp256k1 (Ethereum) and P-256 (WebAuthn passkeys) both fall to Shor's algorithm on a cryptographically relevant quantum computer (CRQC). Expert consensus, including the Ethereum Foundation's own estimate, puts CRQC arrival in the **early-to-mid 2030s**, and no immediate action is required.

Crucially, **the signature problem is not ours to solve unilaterally.** A w3pk transaction is only as quantum-safe as the L1 rules that accept it. Ethereum's own migration — the [lean Ethereum](https://blog.ethereum.org/2025/07/31/lean-ethereum) programme — targets **roughly 2029** for core L1 post-quantum infrastructure (consensus signatures, execution-layer verification), with full ecosystem migration extending past that. w3pk's signature strategy is therefore to track that protocol timeline rather than build a bespoke, pre-standard PQ signature stack that would need to be thrown away once the protocol-native path lands.

The full technical detail behind Ethereum's plan lives with the Ethereum Foundation's own sources — [pq.ethereum.org](https://pq.ethereum.org/), the [lean Ethereum announcement](https://blog.ethereum.org/2025/07/31/lean-ethereum), and the [EF Protocol Architecture roadmap](https://strawmap.org/) — this document summarizes only what drives w3pk decisions.

### What w3pk will do when Ethereum is ready

Ethereum's official target for core L1 post-quantum infrastructure is **~2029** (the EF's own planning language; some trackers cite December 2029 as the working milestone). The action w3pk takes is gated on two concrete protocol events, not on the calendar date itself:

| Trigger | w3pk action |
| --- | --- |
| **EIP-8141 (frame transactions / native account abstraction) ships on mainnet**, with a working PQ signature path (precompile or validation-frame verifier) | Ship an opt-in `quantumSafe` account mode: a validation frame that requires a hybrid classical + PQ signature (secp256k1 + whatever ML-DSA/hash-based scheme Ethereum standardizes). No forced migration — existing EOAs and finalized history remain valid regardless. |
| **Hybrid mode proves stable in production** (gas costs acceptable, tooling mature, no incidents) | Make `quantumSafe: true` the default for **new** wallets created via `register()`. Existing wallets stay opt-in. |
| **Ethereum's consensus/execution layers complete PQ migration** (fork milestones L*/M* and beyond) | Offer a one-time, user-initiated migration path from classical-only to hybrid/PQ-only accounts. Never auto-migrate funds or force a breaking change without explicit user action. |

Until the first trigger fires, w3pk deliberately does **not** deploy interim smart-contract PQ signature verifiers (e.g., pre-standard ERC-4337 PQ verifier contracts). That infrastructure is not part of Ethereum's actual roadmap — the real path is EIP-8141 validation frames — and building on a throwaway interim layer would mean migrating twice. w3pk's only actionable signature-side task today is watching the fork milestones (below) and keeping the SDK's existing [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) account-abstraction support in place, since that's the on-ramp to whatever native AA scheme ships.

### Current status

- ✅ **Quantum-resistant encryption, shipped** — ML-KEM-1024 (FIPS 203) + AES-256-GCM, see [ML-KEM Encryption](#ml-kem-encryption) below
- ✅ **Migration-ready** — [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) account delegation gives a path to whatever account-abstraction scheme Ethereum ships
- ⚠️ **Signature vulnerability, by design (for now)** — secp256k1 and P-256 signing is classical-only; this tracks Ethereum's own L1 timeline rather than a w3pk-specific one
- 🔮 **No user action needed today** — nothing here changes what a w3pk integrator or end user does; this is an architecture-tracking document

### Risk assessment

**Low/moderate risk (already mitigated):**
- ✅ Encrypted backups, session storage (AES-256-GCM) — 128-bit quantum security, negligible harvest-now-decrypt-later (HNDL) exposure
- ✅ Data encrypted with `mlkemEncrypt`/`mlkemDecrypt` — post-quantum secure today
- ✅ PBKDF2 key derivation — Grover's algorithm halves effective security; current iteration counts (210k/310k/100k) leave ample margin for the 2030s

**High risk (tracks Ethereum's own timeline, not w3pk's):**
- ⚠️ Transaction signatures (secp256k1 ECDSA) — broken by Shor's algorithm on a CRQC; fix depends on Ethereum shipping EIP-8141 + a PQ verification path
- ⚠️ WebAuthn passkeys (P-256 ECDSA) — same underlying vulnerability; FIDO Alliance PQ support is not expected before 2027-2028
- ⚠️ Stealth addresses (ERC-5564 ECDH) — key agreement step is quantum-vulnerable; no standardized PQ replacement exists yet

---

## Ethereum's post-quantum roadmap (summary)

Full detail: [pq.ethereum.org](https://pq.ethereum.org/) and the [lean Ethereum announcement](https://blog.ethereum.org/2025/07/31/lean-ethereum). This section extracts only what shapes w3pk's decisions.

Ethereum depends on four families of public-key cryptography broken by Shor's algorithm: ECDSA (secp256k1) for account signatures, BLS signatures for validator attestations, KZG polynomial commitments for blob data availability, and pairing-based SNARKs at the application layer. The EF's [Post-Quantum team](https://pq.ethereum.org/) frames the realistic failure mode as **stolen funds and impersonation**, not rewriting finalized history — past transactions stay valid regardless of what happens later.

The response is the **lean Ethereum** programme (Justin Drake, July 2025), which makes the hash function the single cryptographic primitive across consensus, data, and execution:

| Layer | Current | Post-quantum replacement | Status |
| --- | --- | --- | --- |
| Consensus (validator signatures) | BLS12-381 | **leanXMSS** — hash-based, Merkle-tree signatures | Research/spec phase |
| Aggregation | Native algebraic (BLS) | **leanVM** — Cairo-inspired zkVM producing one SNARK per slot | Reference implementation exists |
| Execution (account signatures) | ECDSA (secp256k1) | **EIP-8141 frame transactions** — account-defined validation logic | Specification phase |
| Data availability | KZG commitments (pairing-based) | STARK-style or lattice-based commitments | Not yet efficient at scale |

**Execution layer — EIP-8141** is the piece that matters most for w3pk. It introduces a new transaction type that decomposes validation into **frames**, letting an account define its own signature-checking logic via an `APPROVE` opcode. This is what gives wallets (including w3pk) the ability to adopt a PQ scheme on their own schedule, without a network-wide flag day. It supersedes most of what ERC-4337 does today with off-chain bundlers.

Whole-scheme verifier drafts already exist: [EIP-8051](https://eips.ethereum.org/EIPS/eip-8051) (`VERIFY_MLDSA`, FIPS 204-compliant, plus a cheaper `VERIFY_MLDSA_ETH` variant), [EIP-8355](https://eips.ethereum.org/EIPS/eip-8355) (extends ML-DSA to security levels III/V), and an older [Falcon](https://eips.ethereum.org/EIPS/eip-7619) proposal. The execution-layer team currently favors a **vector math precompile** (e.g. [EIP-7885](https://eips.ethereum.org/EIPS/eip-7885)) over locking in one whole-scheme verifier, to avoid betting the protocol on an algorithm that later falls to cryptanalysis.

### Fork milestones

These are planning milestones, not commitments — names and ordering may change.

| Fork | Milestone | Layer |
| --- | --- | --- |
| I* | PQ key registry | Consensus |
| J* | PQ signature precompiles | Execution |
| L* | PQ attestations, real-time CL proofs, leanVM | Consensus + Data |
| M* | PQ signature aggregation, PQ blobs | Execution + Data |
| Longer term | Full PQ consensus, PQ transactions, PQ sampling | All layers |

The nearest real fork is **Hegotá** (targeted 2027), which is not itself a PQ fork but the gate that decides whether later PQ forks land on schedule. Its two must-ship EIPs are [EIP-7805](https://eips.ethereum.org/EIPS/eip-7805) (FOCIL) and **EIP-8141**. If either hits friction, the whole downstream PQ schedule slips — this is the single most important thing for w3pk to watch.

### Threat model and residual exposure (EF's own ordering)

1. User accounts — largest pool of value, public keys exposed after first transaction
2. High-value operational keys — exchanges, bridges
3. Governance multisigs
4. Validator keys — affect consensus participation, not direct asset custody

"Harvest now, decrypt later" is a **confidentiality** problem, not an ownership one for signatures: recording transactions today doesn't enable retroactive theft, since blockchains are integrity systems built on signatures, not encryption. The forward-looking risk is that exposed public keys become derivable once a CRQC exists — which is exactly the harvest risk `mlkemEncrypt`/`mlkemDecrypt` already close for **data**, since that scheme provides genuine forward confidentiality today.

On timing: the EF is more conservative than headline quantum-computing news. Most engineering roadmaps place cryptographic relevance in the **early-to-mid 2030s**. [Google Quantum AI's March 2026 analysis](https://research.google/blog/safeguarding-cryptocurrency-by-disclosing-quantum-vulnerabilities-responsibly/) lowered the estimate for breaking 256-bit elliptic curve cryptography to roughly 1,200 logical qubits, and NIST anticipates deprecating ECDSA by 2030 and disallowing it by 2035.

---

## w3pk's current cryptographic architecture

### Asymmetric cryptography (quantum-vulnerable, by protocol necessity)

| Component | Algorithm | Use case | Quantum threat |
| --- | --- | --- | --- |
| Ethereum signing | secp256k1 ECDSA | Transaction/message signatures | High — Shor's algorithm |
| WebAuthn passkeys | P-256 (ES256) | Authentication signatures | High — Shor's algorithm |
| Stealth addresses | secp256k1 ECDH | Privacy-preserving key exchange | High — Shor's algorithm |
| HD derivation | BIP32/BIP44 | Hierarchical key generation | High — inherits ECDSA's exposure |

### Post-quantum cryptography (shipped)

| Component | Algorithm | Use case | Quantum security |
| --- | --- | --- | --- |
| Data encryption | ML-KEM-1024 (FIPS 203) + AES-256-GCM | `mlkemEncrypt`/`mlkemDecrypt` — backups, messaging, any data at rest/in transit | Post-quantum secure |

### Symmetric cryptography (already quantum-resistant)

| Component | Algorithm | Use case | Quantum security |
| --- | --- | --- | --- |
| Wallet/backup/session encryption | AES-256-GCM | Mnemonic storage, backups, sessions | 128-bit (sufficient) |

### Key derivation

| Component | Algorithm | Parameters | Quantum resistance |
| --- | --- | --- | --- |
| Wallet encryption | PBKDF2-SHA256 | 210,000 iterations | Moderate — Grover's algorithm halves effective security |
| Backup encryption | PBKDF2-SHA256 | 310,000 iterations | Moderate |
| Metadata encryption | PBKDF2-SHA256 | 100,000 iterations | Moderate |

### Hash functions

| Component | Algorithm | Use case | Quantum security |
| --- | --- | --- | --- |
| General hashing | SHA-256 | Checksums, derivation | 128-bit collision (sufficient) |
| Ethereum hashing | Keccak-256 | ERC-5564, addresses | 128-bit collision (sufficient) |

---

## ML-KEM Encryption

w3pk supports **ML-KEM-1024** (NIST FIPS 203) encryption for quantum-resistant data protection, with multi-recipient support and deterministic key derivation from private keys. See [`src/crypto/mlkem.ts`](../src/crypto/mlkem.ts).

### How it works

1. A random AES-256 key is generated per message.
2. The plaintext is encrypted with AES-256-GCM using that key.
3. For each recipient, a shared secret is encapsulated with their ML-KEM-1024 public key, and used to wrap the AES key.
4. Each recipient decrypts with their private key to recover the AES key, then decrypts the payload.

This is a KEM+DEM hybrid (asymmetric PQ key encapsulation wrapping a symmetric cipher) — not a classical+PQ dual key-exchange combiner. ML-KEM-1024 alone generates the shared secret; there is no secp256k1/X25519 component mixed into the encapsulation step.

### Deterministic key derivation

```typescript
import { deriveMLKemKeypair, mlkemEncryptWithKey, mlkemDecryptWithKey } from 'w3pk';

const ethPrivateKey = '0x1234...';
const keypair = await deriveMLKemKeypair(ethPrivateKey, 'my-app');
// { publicKey: Uint8Array(1568), privateKey: Uint8Array(3168) }

// Same input always produces the same keypair
const sameKeypair = await deriveMLKemKeypair(ethPrivateKey, 'my-app');
```

Uses HKDF-SHA256 with salt `"mlkem-keypair-v1"` and the provided context string to derive a 64-byte seed, from which the ML-KEM-1024 keypair is generated. All sensitive material is zeroized after use.

### Encrypt/decrypt with a w3pk instance (recommended)

```typescript
import { createWeb3Passkey } from 'w3pk';

const w3pk = createWeb3Passkey();
await w3pk.login();

const myPublicKey = await w3pk.deriveMLKemPublicKey();
const serverPubKey = await fetch('/api/mlkem-public-key').then(r => r.text());

const encrypted = await w3pk.mlkemEncrypt('my secret data', [serverPubKey]);
// You can also decrypt, since you're auto-added as a recipient

const plaintext = await w3pk.mlkemDecrypt(encrypted);
```

Your Ethereum private key never leaves the w3pk instance, matching the security model of `signMessage()` and `sendTransaction()`.

**Supported modes:**
- ✅ **STANDARD** (default) — private key derived internally
- ✅ **STRICT** — same as STANDARD, always requires WebAuthn re-authentication
- ✅ **YOLO** — private key available to app
- ❌ **PRIMARY** — not supported; uses P-256 WebAuthn keys, not Ethereum keys, so there's no secp256k1 material to derive an ML-KEM seed from

### Low-level API

```typescript
import { deriveMLKemKeypair, mlkemEncryptWithKey, mlkemDecryptWithKey, mlkemEncrypt, mlkemDecrypt } from 'w3pk';

// Derive-from-key convenience wrappers
const serverKeypair = await deriveMLKemKeypair(serverEthKey, 'server');
const encrypted = await mlkemEncryptWithKey('my secret data', myEthPrivateKey, [serverKeypair.publicKey], 'client');
const plaintext = await mlkemDecryptWithKey(encrypted, myEthPrivateKey, 'client');

// Direct, key-management-agnostic API
const encryptedDirect = await mlkemEncrypt('my secret data', [publicKey1, publicKey2]);
const plaintextDirect = await mlkemDecrypt(encryptedDirect, privateKey);
```

### API reference

#### `w3pk.deriveMLKemPublicKey(options?): Promise<string>`
Derives your ML-KEM-1024 public key (base64, 1568 bytes) for sharing.
**Options:** `context` (default `'mlkem-v1'`), `mode` (`STANDARD`/`STRICT`/`YOLO`), `tag`, `origin`, `requireAuth`.

#### `w3pk.mlkemEncrypt(plaintext, recipientPublicKeys, options?): Promise<EncryptedPayload>`
Encrypts for yourself plus additional recipients. Same options as above.

#### `w3pk.mlkemDecrypt(payload, options?): Promise<string>`
Decrypts data encrypted for your wallet. `context`/`mode`/`tag`/`origin`/`requireAuth` must match encryption.

#### `deriveMLKemKeypair(privateKey, context?): Promise<MLKemKeypair>`
Low-level deterministic keypair derivation. Returns `{ publicKey: Uint8Array(1568), privateKey: Uint8Array(3168) }`.

#### `mlkemEncryptWithKey(plaintext, senderPrivateKey, recipientPublicKeys, senderContext?): Promise<EncryptedPayload>`
Derives the sender's keypair, then encrypts for sender + recipients (sender's public key is auto-included as first recipient).

#### `mlkemDecryptWithKey(payload, privateKey, context?): Promise<string>`
Derives a keypair, then decrypts.

#### `mlkemEncrypt(plaintext, publicKeys): Promise<EncryptedPayload>`
Raw encryption for one or more recipients. Each `publicKeys` entry is base64 or `Uint8Array`, 1568 bytes.
**Returns:** `{ recipients: [{ publicKey, ciphertext }], encryptedData, iv, authTag }` — `ciphertext` is 1600 bytes (1568 KEM + 32 wrapped AES key), `iv` is 12 bytes, `authTag` is 16 bytes.

#### `mlkemDecrypt(payload, privateKey, publicKey?): Promise<string>`
Decrypts a payload from `mlkemEncrypt()`. Passing your `publicKey` (1568 bytes) speeds up recipient lookup; otherwise every recipient entry is tried.

### Security properties

- ✅ ML-KEM-1024 (NIST FIPS 203) — post-quantum secure key encapsulation
- ✅ AES-256-GCM — 128-bit quantum security for the payload
- ✅ Key zeroization — shared secrets wiped from memory after use
- ✅ Cross-platform — browser and Node.js
- ⚠️ Deterministic derivation from the Ethereum private key means ML-KEM key secrecy is capped by secp256k1 key secrecy — this scheme protects data confidentiality against a future quantum adversary, but does not add independent key-generation entropy beyond the wallet's existing secret

---

## What w3pk is deliberately not doing yet

- **No interim on-chain PQ signature verifiers.** Pre-EIP-8141 architectures (bundler-based smart-contract accounts with a bolted-on PQ verifier) are not part of Ethereum's actual roadmap and would need to be replaced once EIP-8141 ships. Building on them now means migrating twice for no lasting benefit.
- **No PQ signing scheme committed in code.** Which exact algorithm to use (ML-DSA via EIP-8051/8355, Falcon via EIP-7619, or a hash-based Winternitz scheme) is still an open execution-layer question upstream. Committing to one now risks shipping the wrong thing.
- **No changes to WebAuthn/passkey authentication.** FIDO Alliance's own PQ specification work isn't expected to produce browser support before 2027-2028; P-256 stays as-is until that lands.

---

## Roadmap maturity: closing the gaps

The trigger table above tracks Ethereum's protocol schedule, which covers *when w3pk can act* on signatures. It does not by itself cover everything a post-quantum migration roadmap needs (per [NIST SP 1800-38](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc) and [CISA's Quantum-Readiness guidance](https://www.cisa.gov/resources-tools/resources/quantum-readiness-migration-post-quantum-cryptography)): an inventory alone isn't a plan, and a plan that only reacts to an external protocol isn't crypto-agile. The items below are owned by w3pk directly, independent of Ethereum's timeline, and get checked at every "Next Review" date above.

### Internally-owned checkpoints (every review cycle)

- [ ] Re-verify the `mlkem` npm package (currently `mlkem@2.7.0`, [dajiaji/crystals-kyber-js](https://github.com/dajiaji/crystals-kyber-js)) is still maintained, still passes the NIST ML-KEM KAT vectors and the pq-crystals/kyber reference tests, and has no open security advisories.
- [ ] Re-check the FIDO Alliance's WebAuthn PQ status — no PQ COSE algorithm identifier is registered as of this writing, so P-256 passkeys stay as-is; flag the moment one lands.
- [ ] Re-check whether `ethers` (currently `^6.0.0`, used for transaction construction and secp256k1 signing) has announced any PQ or hybrid-signing support, since a signing-path change there would predate w3pk's own EIP-8141 integration.
- [ ] Re-confirm EIP-8141 and the Hegotá fork's status directly against [pq.ethereum.org](https://pq.ethereum.org/) and [strawmap.org](https://strawmap.org/) — don't rely on this document staying current between reviews.

### Crypto-agility target design (not yet implemented)

The SDK has no algorithm-selection config today — signing is hardcoded to secp256k1/P-256, and encryption is hardcoded to ML-KEM-1024 + AES-256-GCM. That's fine while there is only one option to choose from, but it means "add hybrid signing" is currently a code change, not a config flip. Per NIST's crypto-agility guidance (CSWP 39), the target shape before the first EIP-8141 trigger fires should be something like:

```typescript
// Target shape — does not exist in src/ yet.
// Introduce this when the first trigger in "What w3pk will do when Ethereum is ready" fires,
// not before — there is nothing to make agile until a second signature scheme actually exists.
interface CryptoConfig {
  version: number;
  signatures: {
    ethereum: 'secp256k1' | 'hybrid-secp256k1-pq';
    postQuantum?: string; // whatever scheme Ethereum standardizes via EIP-8051/8355/7619
  };
}
```

This is a placeholder for design intent, not a commitment to this exact shape — the real interface depends on which PQ scheme Ethereum's execution layer actually standardizes.

### Operational runbook (draft — to be finalized before the first trigger fires)

1. **Dry run on testnet first.** Hybrid signing gets exercised against a testnet deployment of the relevant EIP-8141 validation frame before any mainnet opt-in ships.
2. **ML-KEM context rotation.** `deriveMLKemKeypair`'s `context` parameter already provides domain separation; if the ML-KEM implementation itself ever needs replacing (library vulnerability, algorithm deprecation), bump the default context (e.g. `mlkem-v2`) rather than reusing `mlkem-v1`, and keep the old context decryptable for existing backups rather than breaking them.
3. **Fail closed on hybrid mismatch.** If a hybrid account's classical and PQ signatures disagree (one verifies, one doesn't), the transaction is rejected outright. There is no partial-trust mode where either signature alone is accepted once hybrid mode is active for an account.
4. **No global cutover switch.** Hybrid mode is opt-in per account via the trigger table above. w3pk does not flip existing wallets to hybrid or PQ-only signing without explicit user action, even after Ethereum completes its own migration (fork milestones L*/M* and beyond).

### Dependency PQ posture

| Dependency | Role | PQ status | What we watch |
| --- | --- | --- | --- |
| `mlkem` (`^2.7.0`) | ML-KEM-1024 encryption | Post-quantum today | Maintenance activity, KAT test results, disclosed vulnerabilities |
| `ethers` (`^6.0.0`) | Transaction construction, secp256k1 signing | Classical only | Any announced hybrid/PQ signing support |
| WebAuthn / FIDO2 | Passkey authentication (P-256) | Classical only | FIDO Alliance PQ working-group output; no registered PQ COSE algorithm yet |
| Ethereum L1 (via EIP-8141) | Transaction validation | Classical only, PQ path specified but not shipped | Hegotá fork outcome, EIP-8141 mainnet status |

---

## Quantum computing timeline

- **Conservative estimate:** 10-15 years to a CRQC
- **EF's own estimate:** early-to-mid 2030s
- **Google Quantum AI (March 2026):** ~1,200 logical qubits needed to break 256-bit ECC, down from prior estimates
- **NIST:** deprecating ECDSA by 2030, disallowing it by 2035 (hybrid PQ modes are exempted from the 2035 disallowance per NIST IR 8547, as long as the PQ component is approved)

Dormant-funds exposure — the governance question nobody has answered — is much smaller for Ethereum than for Bitcoin: the EF estimates roughly 0.1% of ETH supply is long-dormant, against ~5% of BTC in early address formats. That gap is part of why "do nothing yet" is a defensible position for Ethereum today.

---

## Key takeaways

### For developers
1. w3pk's data-encryption layer is already post-quantum (ML-KEM-1024) — use it today for anything that needs long-term confidentiality.
2. Transaction-signature quantum-safety is gated on Ethereum's own protocol timeline, not on w3pk shipping something early.
3. The actionable trigger is **EIP-8141 reaching mainnet with a working PQ verification path** — see [What w3pk will do when Ethereum is ready](#what-w3pk-will-do-when-ethereum-is-ready).
4. Watch the **Hegotá** fork (2027) — it's the gate for whether the rest of the PQ schedule holds.

### For users
1. Your funds are safe today; no immediate quantum threat exists.
2. Backups and sessions are already quantum-resistant (AES-256-GCM).
3. Data you encrypt with `mlkemEncrypt` is already post-quantum secure.
4. Any future signature migration will be opt-in — nothing changes without you choosing it.

### For auditors
1. Current cryptography follows standard best practice; ML-KEM-1024 usage matches FIPS 203.
2. The signature-side gap is acknowledged and explicitly deferred to Ethereum's protocol timeline, not silently ignored.
3. No speculative or unverified interim PQ infrastructure has been deployed.

---

## References

### Standards
- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) — key encapsulation, used by w3pk today
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) — signatures, candidate for Ethereum's execution layer
- [NIST FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final) — hash-based signatures
- [EIP-8141: Frame transactions](https://eips.ethereum.org/EIPS/eip-8141) — the trigger this document tracks
- [EIP-8051](https://eips.ethereum.org/EIPS/eip-8051), [EIP-8355](https://eips.ethereum.org/EIPS/eip-8355) — `VERIFY_MLDSA` precompile drafts
- [EIP-7619: Falcon](https://eips.ethereum.org/EIPS/eip-7619)
- [EIP-7702: Set EOA account code](https://eips.ethereum.org/EIPS/eip-7702)
- [ERC-5564: Stealth address protocol](https://eips.ethereum.org/EIPS/eip-5564)

### Ethereum's roadmap
- [pq.ethereum.org](https://pq.ethereum.org/) — EF Post-Quantum team
- [lean Ethereum announcement](https://blog.ethereum.org/2025/07/31/lean-ethereum)
- [leanEthereum GitHub organisation](https://github.com/leanEthereum)
- [strawmap.org](https://strawmap.org/) — EF Protocol Architecture roadmap

### Other
- [Google Quantum AI: safeguarding cryptocurrency](https://research.google/blog/safeguarding-cryptocurrency-by-disclosing-quantum-vulnerabilities-responsibly/)
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [pqaudit.org](https://pqaudit.org/) — independent PQC standards/audit-firm index

---

## Document Maintenance

**Version:** 2.1
**Last Updated:** 2026-09-13
**Next Review:** 2027-03-13 (6 months, or sooner if the Hegotá fork's EIP-8141 status changes)
**Maintained By:** Julien Béranger ([@julienbrg](https://github.com/julienbrg))

**Changelog:**
- 2026-09-13: Added "Roadmap maturity: closing the gaps" — internally-owned review checkpoints, a labeled not-yet-implemented crypto-agility target design, a draft operational runbook (testnet dry run, ML-KEM context rotation, fail-closed hybrid verification, no global cutover), and a dependency PQ-posture table (`mlkem`, `ethers`, WebAuthn/FIDO2), per NIST SP 1800-38 and CISA quantum-readiness guidance
- 2026-09-13: Complete rewrite aligned with the Ethereum Foundation's public post-quantum roadmap (pq.ethereum.org, the lean Ethereum announcement, and the EIPs cited above)
  - Replaced speculative/unverifiable content (interim ERC-4337 PQ verifier contracts, unconfirmed testnet addresses) with Ethereum's actual documented roadmap (lean Ethereum, leanXMSS, leanVM, EIP-8141, fork milestones)
  - Added an explicit action-trigger table: what w3pk does, and when, gated on EIP-8141 reaching mainnet with a working PQ verification path
  - Replaced the "Ethereum quantum resistance roadmap" tweet citation with the EF's actual public sources (pq.ethereum.org, lean Ethereum blog post, strawmap.org)
  - Corrected the ML-KEM "future" backup/stealth-address examples that referenced a nonexistent `@kohaku-eth/ml-kem` package — w3pk's `mlkemEncrypt`/`mlkemDecrypt` already is that hybrid scheme, using the shipped `mlkem` npm package
  - Added a dedicated "what w3pk is deliberately not doing yet" section explaining why no interim PQ signature infrastructure is being built
- 2026-03-21: Added ML-KEM encryption utilities with deterministic key derivation
- 2026-02-27: Updated to reference Ethereum's quantum roadmap; added EIP-8141 discussion
- 2026-02-26: Initial version

---

## Questions or Feedback?

1. Open an issue: [GitHub Issues](https://github.com/w3hc/w3pk/issues)
2. Join the discussion: [Element Matrix](https://matrix.to/#/@julienbrg:matrix.org)
3. Email: see [README.md](../README.md) for contact details
