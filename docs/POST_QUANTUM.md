# Post-Quantum Cryptography

## Executive Summary

w3pk's data-encryption layer is already post-quantum: a hybrid **ML-KEM-1024** (NIST FIPS 203) + **X25519** KEM, framed as HPKE (RFC 9180), ships today for encrypting data at rest and in transit. What remains quantum-vulnerable is **transaction signing** — secp256k1 (Ethereum) and P-256 (WebAuthn passkeys) both fall to Shor's algorithm on a cryptographically relevant quantum computer (CRQC). Expert consensus, including the Ethereum Foundation's own estimate, puts CRQC arrival in the **early-to-mid 2030s**, and no immediate action is required.

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

- ✅ **Quantum-resistant encryption, shipped** — HPKE over ML-KEM-1024 (FIPS 203) + X25519, with AES-256-GCM, see [ML-KEM Encryption](#ml-kem-encryption) below
- ✅ **Migration-ready** — [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) account delegation gives a path to whatever account-abstraction scheme Ethereum ships
- ⚠️ **Signature vulnerability, by design (for now)** — secp256k1 and P-256 signing is classical-only; this tracks Ethereum's own L1 timeline rather than a w3pk-specific one
- 🔮 **No user action needed today** — nothing here changes what a w3pk integrator or end user does; this is an architecture-tracking document

### Risk assessment

**Low/moderate risk (already mitigated):**
- ✅ Encrypted backups, session storage (AES-256-GCM) — 128-bit quantum security, negligible harvest-now-decrypt-later (HNDL) exposure
- ✅ Data encrypted with `mlkemEncrypt`/`mlkemDecrypt` — post-quantum secure today, and still safe if ML-KEM alone falls to classical cryptanalysis
- ✅ Backup password key derivation (Argon2id, 64 MiB, 3 passes, 4 lanes) — Grover's algorithm only gives a square-root speedup on password guessing, which the memory-hard cost still dominates; the password's own strength is the limit, quantum or not
- ✅ Wallet key from the passkey's PRF output (HKDF-SHA256, 256-bit) — 128-bit quantum security

**High risk (tracks Ethereum's own timeline, not w3pk's):**
- ⚠️ Transaction signatures (secp256k1 ECDSA) — broken by Shor's algorithm on a CRQC; fix depends on Ethereum shipping EIP-8141 + a PQ verification path
- ⚠️ WebAuthn passkey signatures (P-256 ECDSA) — same underlying vulnerability, which matters where the signature is the security boundary: `PRIMARY` mode's smart account checks it on-chain ([EIP-7951](./EIP-7951.md)), so a CRQC that recovers the private key from the account's published public key can sign for it. The SDK's local assertion check is classical too. See [WebAuthn and passkeys](#webauthn-and-passkeys) for why the other modes' wallet keys don't depend on it
- ⚠️ Stealth addresses (ERC-5564 ECDH) — key agreement step is quantum-vulnerable: a CRQC recovers the viewing key from the public meta-address and links every recorded announcement to its recipient; no standardized PQ replacement exists yet
- ⚠️ ElGamal over Baby Jubjub — ciphertexts published today become readable; see [Harvest now, decrypt later](#harvest-now-decrypt-later)

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

"Harvest now, decrypt later" is a **confidentiality** problem, not an ownership one for signatures: recording transactions today doesn't enable retroactive theft, since blockchains are integrity systems built on signatures, not encryption. The forward-looking risk is that exposed public keys become derivable once a CRQC exists — which is exactly the harvest risk `mlkemEncrypt`/`mlkemDecrypt` already close for **data**: a recorded payload stays confidential against a future quantum adversary (though not against a later leak of the recipient's key, see [What a leaked key exposes](#what-a-leaked-key-exposes)).

On timing: the EF is more conservative than headline quantum-computing news. Most engineering roadmaps place cryptographic relevance in the **early-to-mid 2030s**. [Google Quantum AI's March 2026 analysis](https://research.google/blog/safeguarding-cryptocurrency-by-disclosing-quantum-vulnerabilities-responsibly/) lowered the estimate for breaking 256-bit elliptic curve cryptography to roughly 1,200 logical qubits, and NIST anticipates deprecating ECDSA by 2030 and disallowing it by 2035.

---

## w3pk's current cryptographic architecture

### Asymmetric cryptography (quantum-vulnerable, by protocol necessity)

| Component | Algorithm | Use case | Quantum threat |
| --- | --- | --- | --- |
| Ethereum signing | secp256k1 ECDSA | Transaction/message signatures | High — Shor's algorithm |
| WebAuthn passkeys | P-256 (ES256) | Authentication signatures, `PRIMARY` on-chain signing | High — Shor's algorithm (not the PRF wallet key, see below) |
| Stealth addresses | secp256k1 ECDH | Privacy-preserving key exchange | High — Shor's algorithm |
| HD derivation | BIP32/BIP44 | Hierarchical key generation | High — inherits ECDSA's exposure |
| ZK encryption | ElGamal over Baby Jubjub | Homomorphic tallies, encrypted values in circuits | High — Shor's algorithm, recorded ciphertexts |
| ZK proofs | Groth16 over BN254 | `zkProve`, Semaphore | Soundness only — proofs stay zero-knowledge |

### Post-quantum cryptography (shipped)

| Component | Algorithm | Use case | Quantum security |
| --- | --- | --- | --- |
| Data encryption | HPKE over ML-KEM-1024 (FIPS 203) + X25519, AES-256-GCM | `mlkemEncrypt`/`mlkemDecrypt` — backups, messaging, any data at rest/in transit | Post-quantum secure (hybrid) |

### Symmetric cryptography (already quantum-resistant)

| Component | Algorithm | Use case | Quantum security |
| --- | --- | --- | --- |
| Wallet/backup/session encryption | AES-256-GCM | Mnemonic storage, backups, sessions | 128-bit (sufficient) |

### Key derivation

| Component | Algorithm | Parameters | Quantum resistance |
| --- | --- | --- | --- |
| Wallet encryption | HKDF-SHA256 of the WebAuthn PRF output | 256-bit key material | Strong — 128-bit quantum security |
| Backup encryption | Argon2id | 64 MiB, 3 passes, 4 lanes (RFC 9106's second recommendation) | Bounded by password strength, not by the algorithm |

### Hash functions

| Component | Algorithm | Use case | Quantum security |
| --- | --- | --- | --- |
| General hashing | SHA-256 | Checksums, derivation | 128-bit collision (sufficient) |
| Hybrid KEM combiner | SHA3-256 | `mlkemEncrypt` shared secret | 128-bit collision (sufficient) |
| Ethereum hashing | Keccak-256 | ERC-5564, addresses | 128-bit collision (sufficient) |

---

## WebAuthn and passkeys

A passkey holds two independent secrets, and only one of them is quantum-vulnerable:

| Secret | What it does in w3pk | Algorithm | Recoverable from public data by a CRQC? |
| --- | --- | --- | --- |
| Credential private key | Signs assertions; in `PRIMARY` mode, signs UserOperations checked on-chain | P-256 ECDSA (COSE `-7`, the only algorithm `register()` requests) | Yes — the public key is stored by the SDK, and published on-chain in `PRIMARY` mode |
| PRF secret (CTAP2 `hmac-secret`) | Its output, through HKDF-SHA256, is the key that encrypts the mnemonic in `STRICT`, `STANDARD` and `YOLO` modes, and the seed of the ZK and Semaphore secrets | HMAC-SHA256 over a per-credential random key | No — it is symmetric, never leaves the authenticator, and nothing public is derived from it |

So in `STRICT`, `STANDARD` and `YOLO` modes, a quantum adversary who can forge assertions still can't decrypt the stored wallet: that needs the PRF output, which only the authenticator can compute, after user verification. Forged assertions would only defeat the SDK's local assertion check, which runs in the same page as the attacker anyway.

`PRIMARY` mode is the exception: the passkey's P-256 signature *is* the account's authorization on-chain, so it inherits the full Shor exposure, like secp256k1 EOAs.

One caveat on the PRF path: between the browser and a roaming authenticator (USB, NFC, or a phone over the hybrid transport), CTAP encrypts the PRF salts and outputs under a P-256 ECDH shared secret. Decrypting a recorded exchange later needs local capture of USB or NFC traffic, or, for the hybrid transport, the QR code secret that is mixed into the tunnel's keys, so this is a much narrower exposure than a published public key.

### ML-DSA passkeys: ecosystem status (November 2026)

WebAuthn selects the signature algorithm by COSE identifier, so post-quantum passkeys need no protocol change: [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964) registers ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204) as COSE `-48`, `-49` and `-50`, with the new `AKP` key type. What is missing is deployment:

| Project | Role | Status | Policy |
| --- | --- | --- | --- |
| [1Password](https://1password.com/blog/post-quantum-passkeys) | Authenticator | Shipped 2026-10-20 (8.12.44); creation not yet on iOS or the native macOS autofill extension | Creates an ML-DSA passkey only when the site asks for it; existing passkeys stay classical, an in-place upgrade is being worked on with W3C and FIDO |
| [Yubico](https://www.darkreading.com/identity-access-management-security/beyond-phishing-resistant-yubico-identity-verification-gap) | Hardware authenticator | Public beta; beta keys can't be updated in the field. Shipping firmware 5.8 has no PQ keys | Beta only |
| Apple, Google | Platform passkeys | No ML-DSA passkeys announced; Apple's CryptoKit has ML-DSA-65/87, including in the Secure Enclave | — |
| [SimpleWebAuthn](https://simplewebauthn.dev/docs/14.0.x/advanced/server/pqc-ml-dsa-support) | TypeScript server library | v14: ML-DSA-44/65/87 on Node ≥ 24.7 | ML-DSA-44 is first in the default list when the runtime supports it |
| [webauthn4j](https://github.com/webauthn4j/webauthn4j/pull/1337) | Java server library | 0.32.0 (2026-11-02), JDK 17/21 backports | Library support |
| [Keycloak](https://github.com/keycloak/keycloak/issues/50084) | Identity server | Planned for 27.0 | Opt-in only: classical stays the default, nothing deprecated, migration out of scope; waits on FIDO conformance test vectors and a production authenticator |
| Passkey smart wallets (Coinbase Smart Wallet, Safe, ZeroDev) | On-chain P-256 accounts | No public PQ statement found | — |

The pattern is the same everywhere: opt-in, classical by default, no forced migration. No on-chain wallet has moved, since nothing on Ethereum can verify ML-DSA yet ([EIP-8051](https://eips.ethereum.org/EIPS/eip-8051) is a draft).

ML-DSA public keys are large (about 1.3 KB for ML-DSA-44, 2.6 KB for ML-DSA-87, against 64 bytes for ES256), which matters for credential storage and backup files. Whether ML-DSA passkeys also support the PRF extension, which w3pk can't work without, has not been checked.

---

## Harvest now, decrypt later

Signatures can't be forged retroactively: a CRQC lets an attacker sign *from then on*, not rewrite what was already accepted. Confidentiality and privacy are different: anything recorded today, on-chain or in transit, can be read or linked once a CRQC exists. This is what a recording adversary learns later from each w3pk feature:

| Feature | What is recorded | What a CRQC reveals later | Status |
| --- | --- | --- | --- |
| `mlkemEncrypt` payloads | Ciphertexts, recipients' public keys | Nothing, unless ML-KEM-1024 is also broken | ✅ Post-quantum |
| Encrypted wallet, sessions, backup files | AES-256-GCM ciphertexts | Nothing: the keys come from the PRF output or the backup password, not from a public key | ✅ Symmetric |
| Stealth addresses (ERC-5564) | The public stealth meta-address, and each announcement's ephemeral public key and view tag | The viewing private key, from the meta-address: every past and future stealth payment to that recipient becomes linkable to them | ⚠️ Retroactive deanonymization, no standardized PQ scheme |
| ElGamal over Baby Jubjub (`elgamalEncrypt`) | Ciphertexts, often published on-chain (ballots, tallies) | The private key from the public key, or `m` directly from each ciphertext: every published value becomes readable | ⚠️ Classical, no PQ replacement keeps the additive homomorphism in-circuit |
| Groth16 proofs (`zkProve`, Semaphore) | Proofs, public signals, nullifiers | Nothing about the witness: Groth16's zero-knowledge holds against any adversary. What breaks is **soundness**: a CRQC can recover the BN254 setup trapdoor and forge proofs | ✅ Privacy holds, ⚠️ forgeable later |
| Semaphore identity | The commitment `Poseidon(publicKey)` in a group | Nothing while the Baby Jubjub public key stays unpublished: the commitment is a hash. If an app publishes the public key, a CRQC recovers the private key and can link every nullifier the identity produced | ✅ As long as the public key stays private |
| Sender signatures inside payloads (`signMessage`) | secp256k1 signatures inside decrypted content | Nothing new about the content, but an archived signature stops proving who wrote it, since anyone could have produced it after a CRQC exists | ⚠️ Authenticity of archives, not confidentiality |
| P-256 credential public keys | Public keys stored by the SDK and, in `PRIMARY` mode, on-chain | The credential private key: forged assertions, and `PRIMARY` UserOperations | ⚠️ See [WebAuthn and passkeys](#webauthn-and-passkeys) |

Apps should keep data that must stay confidential for years out of ElGamal ciphertexts and stealth announcements, and seal it with `mlkemEncrypt` instead.

---

## ML-KEM Encryption

w3pk encrypts data for one or more recipients with a **hybrid ML-KEM-1024 + X25519 KEM**, framed as [HPKE](https://www.rfc-editor.org/rfc/rfc9180) (payload `version: 3`), with deterministic key derivation from the BIP-39 seed. See [`src/crypto/mlkem.ts`](../src/crypto/mlkem.ts).

### Why hybrid

A payload sealed to the user can be kept and decrypted locally for years, so it shouldn't rest on one assumption. Lattices may take serious hits from AI-accelerated cryptanalysis before a quantum computer exists, and elliptic curves may too. A v3 payload stays confidential unless **both** ML-KEM-1024 and X25519 are broken.

### How it works (payload v3)

1. A random AES-256 data key encrypts the plaintext once with AES-256-GCM (12-byte IV, 16-byte tag).
2. For each recipient, the data key is sealed with single-shot HPKE `Seal` (RFC 9180 mode_base, KDF HKDF-SHA256, AEAD AES-256-GCM, `info` = `w3pk-payload-v3`, empty `aad`) over the hybrid KEM:
   - `Encap(pk)`: split `pk = pk_M || pk_X`; `(ct_M, ss_M) = ML-KEM-1024.Encaps(pk_M)`; draw an ephemeral X25519 key `e`, `ct_X = X25519(e, G)`, `ss_X = X25519(e, pk_X)`; `enc = ct_M || ct_X`.
   - `Decap(enc, sk)`: `ss_M = ML-KEM-1024.Decaps(ct_M, sk_M)`, `ss_X = X25519(sk_X, ct_X)`.
   - Combiner: `ss = SHA3-256(ss_M || ss_X || ct_M || ct_X || pk_M || pk_X || "w3pk-MLKEM1024-X25519-v3")`.
3. HPKE's key schedule turns `ss` into the AES-256-GCM key and nonce that seal the 32-byte data key (48 bytes with the tag).

The combiner is the *UniversalCombiner* of [draft-irtf-cfrg-hybrid-kems](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/), and [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)'s combiner plus the ML-KEM ciphertext and public key. X-Wing omits those two because ML-KEM's Fujisaki-Okamoto transform makes that safe (C2PRI). Including them doesn't rely on that property, binds each entry to both of its recipient's public keys, and costs a few kilobytes of hashing per recipient. All inputs are fixed-length, so plain concatenation is unambiguous. ML-KEM-1024 is used instead of X-Wing's ML-KEM-768 for more margin on long-lived secrets.

The HPKE suite id is `HPKE || 0xFE42 || 0x0001 || 0x0002`. No KEM id is registered for ML-KEM-1024 + X25519 and the registry has no private-use range, so `0xFE42` is unassigned and only domain-separates the key schedule. The key schedule is tested against RFC 9180's test vectors.

Payloads of any other version (v1: AES key XOR-ed with the raw ML-KEM shared secret; v2: ML-KEM-only AES-KW) are rejected, with no compatibility path.

### What a leaked key exposes

The user's KEM keys are **long-lived** and deterministic: there is no forward secrecy. Anyone who obtains a private key, or the mnemonic it is derived from, can decrypt **every payload ever sealed to it**, past and future. Rotating means deriving a keypair under a new `context` and re-encrypting what must stay secret.

The keys are derived from the wallet's BIP-39 seed through hash functions only, so they are only as secret as the mnemonic, including how it is stored on the device. No secp256k1 key enters the derivation: a signing key whose public key is published (and so recoverable by a quantum computer) reveals nothing about the KEM keys.

### No sender authentication

Payloads have no sender authentication. Every recipient learns the shared data key, so any recipient can seal new content for the others, and anyone with the recipients' public keys can encrypt to them. A payload that decrypts proves nothing about who sent it.

To prove who wrote the content, sign it inside the payload: sign the plaintext together with the recipients' public keys and a timestamp, encrypt the signed message, and have each recipient verify the signature after decrypting. Signing the ciphertext instead doesn't work: anyone can strip the signature and sign the same ciphertext as themselves.

```typescript
import { verifyMessage } from 'ethers';

// Sender
const to = [recipientPubKey];
const message = JSON.stringify({ data: 'my secret data', to, at: Date.now() });
const { signature } = await w3pk.signMessage(message, { mode: 'STANDARD', tag: 'MAIN' });
const encrypted = await w3pk.mlkemEncrypt(JSON.stringify({ message, signature }), to);

// Recipient: senderAddress and myPubKey are known in advance, not read from the payload
const signed = JSON.parse(await w3pk.mlkemDecrypt(encrypted));
if (verifyMessage(signed.message, signed.signature).toLowerCase() !== senderAddress.toLowerCase()) {
  throw new Error('Not signed by the expected sender');
}
const { data, to: intended, at } = JSON.parse(signed.message);
if (!intended.includes(myPubKey) || Date.now() - at > MAX_AGE_MS) {
  throw new Error('Not addressed to me, or stale');
}
```

- Verify the exact signed string, as transmitted: `JSON.stringify` isn't canonical, so re-serializing a parsed object can change the bytes.
- `to` stops a recipient from forwarding signed content to someone else as if it were addressed to them, and `at` (or a nonce) lets recipients refuse replays.
- The signing address depends on the origin, mode and tag passed to `signMessage()`: recipients must hold that exact address. Use STANDARD, STRICT or YOLO: the PRIMARY address comes from the passkey's P-256 key and isn't recovered from an EIP-191 signature. In STRICT mode, signing prompts for the passkey once more.
- Without a w3pk instance, sign with any secp256k1 key, such as an ethers `Wallet`'s `signMessage()`.
- The signature is secp256k1, so this authentication is classical: unlike the encryption, it doesn't hold against a quantum adversary.

### FrodoKEM

FrodoKEM-1344 rests on plain LWE, without the algebraic structure ML-KEM relies on, so it would hedge against structured-lattice attacks. It is not used, for two reasons: no audited JavaScript implementation exists, so it would need WebAssembly, and each recipient entry would grow by about 21 KB. Revisit if an audited implementation appears.

### Deterministic key derivation

```typescript
import { deriveMLKemKeypair } from 'w3pk';
import { Mnemonic, getBytes } from 'ethers';

const seed = getBytes(Mnemonic.fromPhrase(mnemonic).computeSeed());
const keypair = await deriveMLKemKeypair(seed, {
  origin: 'https://example.com',
  mode: 'STANDARD',   // default
  tag: 'MAIN',        // default
  context: 'my-app',  // default 'mlkem-v1'
});
// { publicKey: Uint8Array(1600), privateKey: Uint8Array(3200) }
```

The input is the 64-byte [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) seed: PBKDF2-HMAC-SHA512 of the NFKD mnemonic, salt `mnemonic`, 2048 iterations, no passphrase. HKDF-SHA256 extracts a PRK from it with salt `w3pk-kem-keypair-v4`, then expands a 64-byte ML-KEM-1024 seed and a 32-byte X25519 secret key. Each `info` is five fields, each prefixed with its UTF-8 length as a 4-byte big-endian integer: the purpose (`ml-kem-1024` or `x25519`), the origin normalized as for origin-specific addresses (`normalizeOrigin` in [`src/wallet/origin-derivation.ts`](../src/wallet/origin-derivation.ts)), the mode, the uppercased tag and the context. The public key is `pk_M (1568) || pk_X (32)` and the private key `sk_M (3168) || sk_X (32)`. The same seed and options always give the same keypair, any change to the origin, mode, tag or context gives an unrelated one, and all intermediate secrets are zeroized.

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

The seed and the KEM private key never leave the w3pk instance, matching the security model of `signMessage()` and `sendTransaction()`. The keypair is bound to the current origin, the mode and the tag.

**Supported modes:**
- ✅ **STANDARD** (default)
- ✅ **STRICT** — always requires WebAuthn re-authentication
- ✅ **YOLO**
- ❌ **PRIMARY** — not supported

### Low-level API

```typescript
import { deriveMLKemKeypair, mlkemEncryptWithKey, mlkemDecryptWithKey, mlkemEncrypt, mlkemDecrypt } from 'w3pk';

// Derive-from-seed convenience wrappers
const origin = 'https://example.com';
const serverKeypair = await deriveMLKemKeypair(serverSeed, { origin, context: 'server' });
const encrypted = await mlkemEncryptWithKey('my secret data', mySeed, [serverKeypair.publicKey], { origin, context: 'client' });
const plaintext = await mlkemDecryptWithKey(encrypted, mySeed, { origin, context: 'client' });

// Direct, key-management-agnostic API
const encryptedDirect = await mlkemEncrypt('my secret data', [publicKey1, publicKey2]);
const plaintextDirect = await mlkemDecrypt(encryptedDirect, privateKey);
```

### API reference

#### `w3pk.deriveMLKemPublicKey(options?): Promise<string>`
Derives your hybrid public key (base64, 1600 bytes) for sharing.
**Options:** `context` (default `'mlkem-v1'`), `mode` (`STANDARD`/`STRICT`/`YOLO`, default `STANDARD`), `tag` (default `MAIN`), `requireAuth`. The origin is always the current one.

#### `w3pk.mlkemEncrypt(plaintext, recipientPublicKeys, options?): Promise<EncryptedPayload>`
Encrypts for yourself plus additional recipients. Same options as above. No sender authentication: sign the content inside the payload with `signMessage()` (see [No sender authentication](#no-sender-authentication)).

#### `w3pk.mlkemDecrypt(payload, options?): Promise<string>`
Decrypts data encrypted for your wallet. The origin, `context`, `mode` and `tag` must match encryption.

#### `deriveMLKemKeypair(seed, { origin, mode?, tag?, context? }): Promise<MLKemKeypair>`
Low-level deterministic keypair derivation from a 64-byte BIP-39 seed. Throws on a seed of any other length, an unknown mode or an invalid origin. Returns `{ publicKey: Uint8Array(1600), privateKey: Uint8Array(3200) }`.

#### `mlkemEncryptWithKey(plaintext, senderSeed, recipientPublicKeys, senderOptions): Promise<EncryptedPayload>`
Derives the sender's keypair, then encrypts for sender + recipients (sender's public key is auto-included as first recipient).

#### `mlkemDecryptWithKey(payload, seed, options): Promise<string>`
Derives a keypair, then decrypts.

#### `mlkemEncrypt(plaintext, publicKeys): Promise<EncryptedPayload>`
Raw encryption for one or more recipients. Each `publicKeys` entry is base64 or `Uint8Array`, 1600 bytes. No sender authentication: any recipient can seal new content for the others.
**Returns:** `{ version: 3, recipients: [{ publicKey, enc, ciphertext }], encryptedData, iv, authTag }`: `enc` is 1600 bytes (1568 ML-KEM ciphertext + 32 X25519 ephemeral key), `ciphertext` is the 48-byte sealed data key, `iv` is 12 bytes and `authTag` 16 bytes.

#### `mlkemDecrypt(payload, privateKey): Promise<string>`
Decrypts a v3 payload. The recipient entry is found by the public key derived from `privateKey` (3200 bytes); any other version throws `Unsupported payload version`. The IV must be 12 bytes and the auth tag 16 bytes.

### Security properties

- ✅ Hybrid ML-KEM-1024 (NIST FIPS 203) + X25519 — confidential unless both are broken
- ✅ HPKE (RFC 9180) key schedule, with a combiner over both shared secrets, both ciphertexts and both recipient public keys — altering either half of `enc`, or moving an entry to another recipient, fails decryption
- ✅ AES-256-GCM — 128-bit quantum security for the payload and the sealed data key
- ✅ Key zeroization — shared secrets wiped from memory after use
- ✅ Cross-platform — browser and Node.js
- ⚠️ No forward secrecy — a leaked KEM private key exposes every payload sealed to it
- ⚠️ No sender authentication — any recipient can seal new content for the others; sign the content inside the payload to prove who wrote it (see [No sender authentication](#no-sender-authentication))
- ⚠️ Deterministic derivation from the wallet's BIP-39 seed means KEM key secrecy is capped by the mnemonic's secrecy — this scheme protects data confidentiality against a future quantum adversary, but does not add independent key-generation entropy beyond the wallet's existing secret

---

## What w3pk is deliberately not doing yet

- **No interim on-chain PQ signature verifiers.** Pre-EIP-8141 architectures (bundler-based smart-contract accounts with a bolted-on PQ verifier) are not part of Ethereum's actual roadmap and would need to be replaced once EIP-8141 ships. Building on them now means migrating twice for no lasting benefit.
- **No PQ signing scheme committed in code.** Which exact algorithm to use (ML-DSA via EIP-8051/8355, Falcon via EIP-7619, or a hash-based Winternitz scheme) is still an open execution-layer question upstream. Committing to one now risks shipping the wrong thing.
- **No changes to WebAuthn/passkey authentication yet.** ML-DSA passkeys exist (see [ML-DSA passkeys: ecosystem status](#ml-dsa-passkeys-ecosystem-status-november-2026)), but outside `PRIMARY` mode they wouldn't protect the wallet key, which already comes from the quantum-resistant PRF output. In `PRIMARY` mode, an ML-DSA credential would have no account at all, since nothing on-chain verifies ML-DSA. P-256 stays the only requested algorithm until an on-chain verifier ships, or until opt-in ML-DSA credentials for the other modes are shown to support PRF.

---

## Roadmap maturity: closing the gaps

The trigger table above tracks Ethereum's protocol schedule, which covers *when w3pk can act* on signatures. It does not by itself cover everything a post-quantum migration roadmap needs (per [NIST SP 1800-38](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc) and [CISA's Quantum-Readiness guidance](https://www.cisa.gov/resources-tools/resources/quantum-readiness-migration-post-quantum-cryptography)): an inventory alone isn't a plan, and a plan that only reacts to an external protocol isn't crypto-agile. The items below are owned by w3pk directly, independent of Ethereum's timeline, and get checked at every "Next Review" date above.

### Internally-owned checkpoints (every review cycle)

- [ ] Re-verify the `mlkem` npm package (currently `mlkem@2.7.0`, [dajiaji/crystals-kyber-js](https://github.com/dajiaji/crystals-kyber-js)) is still maintained, still passes the NIST ML-KEM KAT vectors and the pq-crystals/kyber reference tests, and has no open security advisories.
- [ ] Re-check whether an audited JavaScript FrodoKEM implementation exists, and whether an HPKE KEM id is registered for ML-KEM-1024 + X25519.
- [ ] Re-check the ML-DSA passkey ecosystem (COSE `-48`/`-49`/`-50`, [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964)): which authenticators create ML-DSA passkeys, whether any of them supports PRF, whether Apple's or Google's platform passkeys do, and whether FIDO has published PQ conformance test vectors.
- [ ] Re-check whether a post-quantum stealth address scheme has been registered for ERC-5564.
- [ ] Re-check whether `ethers` (currently `^6.0.0`, used for transaction construction and secp256k1 signing) has announced any PQ or hybrid-signing support, since a signing-path change there would predate w3pk's own EIP-8141 integration.
- [ ] Re-confirm EIP-8141 and the Hegotá fork's status directly against [pq.ethereum.org](https://pq.ethereum.org/) and [strawmap.org](https://strawmap.org/) — don't rely on this document staying current between reviews.

### Crypto-agility target design (not yet implemented)

The SDK has no algorithm-selection config today — signing is hardcoded to secp256k1/P-256, and encryption is hardcoded to HPKE over ML-KEM-1024 + X25519 with AES-256-GCM. That's fine while there is only one option to choose from, but it means "add hybrid signing" is currently a code change, not a config flip. Per NIST's crypto-agility guidance (CSWP 39), the target shape before the first EIP-8141 trigger fires should be something like:

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
2. **ML-KEM context rotation.** `deriveMLKemKeypair`'s `context` parameter already provides domain separation; if the ML-KEM implementation itself ever needs replacing (library vulnerability, algorithm deprecation), bump the payload version and the derivation salt, as v3 did for the hybrid KEM and v4 for the seed-based derivation (`w3pk-kem-keypair-v4`), rather than reusing the old ones.
3. **Fail closed on hybrid mismatch.** If a hybrid account's classical and PQ signatures disagree (one verifies, one doesn't), the transaction is rejected outright. There is no partial-trust mode where either signature alone is accepted once hybrid mode is active for an account.
4. **No global cutover switch.** Hybrid mode is opt-in per account via the trigger table above. w3pk does not flip existing wallets to hybrid or PQ-only signing without explicit user action, even after Ethereum completes its own migration (fork milestones L*/M* and beyond).

### Dependency PQ posture

| Dependency | Role | PQ status | What we watch |
| --- | --- | --- | --- |
| `mlkem` (`^2.7.0`) | ML-KEM-1024 encryption | Post-quantum today | Maintenance activity, KAT test results, disclosed vulnerabilities |
| `@noble/curves` (`^2.4.0`), `@noble/hashes` | X25519, HKDF, SHA3-256 for the hybrid KEM and HPKE | Classical (X25519), hedged by ML-KEM | Audits, disclosed vulnerabilities |
| `ethers` (`^6.0.0`) | Transaction construction, secp256k1 signing | Classical only | Any announced hybrid/PQ signing support |
| WebAuthn / FIDO2 | Passkey authentication (P-256), PRF wallet key (HMAC-SHA256) | Signatures classical, PRF symmetric; ML-DSA COSE IDs registered, first authenticators shipping | PRF support on ML-DSA passkeys, platform passkeys, FIDO conformance test vectors |
| `snarkjs` (`^0.7.6`) | Groth16 proofs over BN254 | Zero-knowledge holds, soundness classical | Any PQ proof system usable from circom circuits |
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
3. Data you encrypt with `mlkemEncrypt` is already post-quantum secure, as long as your keys stay private.
4. Any future signature migration will be opt-in — nothing changes without you choosing it.

### For auditors
1. Current cryptography follows standard best practice; ML-KEM-1024 usage matches FIPS 203, and the hybrid KEM follows RFC 9180 and draft-irtf-cfrg-hybrid-kems.
2. The signature-side gap is acknowledged and explicitly deferred to Ethereum's protocol timeline, not silently ignored.
3. No speculative or unverified interim PQ infrastructure has been deployed.

---

## References

### Standards
- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) — key encapsulation, used by w3pk today
- [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180) — framing of encrypted payloads
- [draft-irtf-cfrg-hybrid-kems](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/) and [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) — hybrid KEM combiners
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) — signatures, candidate for Ethereum's execution layer
- [NIST FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final) — hash-based signatures
- [RFC 9964: ML-DSA for JOSE and COSE](https://www.rfc-editor.org/rfc/rfc9964) — the COSE identifiers ML-DSA passkeys use
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

**Version:** 2.4
**Last Updated:** 2026-11-08
**Next Review:** 2027-03-13 (6 months, or sooner if the Hegotá fork's EIP-8141 status changes)
**Maintained By:** Julien Béranger ([@julienbrg](https://github.com/julienbrg))

**Changelog:**
- 2026-11-08: Backup key derivation described as Argon2id; WebAuthn risk split between the P-256 credential key and the PRF wallet key; added the ML-DSA passkey ecosystem status and a "harvest now, decrypt later" inventory (stealth addresses, ElGamal, Groth16, Semaphore); updated the checkpoints and the dependency table ([#331](https://github.com/w3hc/w3pk/issues/331))
- 2026-11-04: KEM keys derive from the BIP-39 seed, origin, mode, tag and context instead of the origin's secp256k1 signing key (salt `w3pk-kem-keypair-v4`, [#263](https://github.com/w3hc/w3pk/issues/263)); every ML-KEM key changes
- 2026-11-01: Encrypted payloads move to v3, HPKE over a hybrid ML-KEM-1024 + X25519 KEM ([#137](https://github.com/w3hc/w3pk/issues/137)); documented the combiner, the FrodoKEM decision and what a leaked key exposes; v1 and v2 are no longer readable
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
