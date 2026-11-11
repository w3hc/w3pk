# Zero-Knowledge Cryptography Utilities

Comprehensive cryptographic utilities for zero-knowledge proofs, key derivation, and privacy-preserving operations in the w3pk SDK.

---

## 📚 Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Core Utilities](#core-utilities)
  - [Key Stretching & Derivation](#key-stretching--derivation)
  - [Salted Hashing](#salted-hashing)
  - [Iterative Hashing](#iterative-hashing)
  - [Merkle Trees](#merkle-trees)
  - [Commitments](#commitments)
  - [Baby Jubjub and ElGamal](#baby-jubjub-and-elgamal)
  - [Semaphore Identities](#semaphore-identities)
  - [NFT Ownership Proofs](#nft-ownership-proofs)
  - [Membership, Threshold and Range Circuits](#membership-threshold-and-range-circuits)
  - [Trusted Setup](#trusted-setup)
  - [Circuit Artifact Verification](#circuit-artifact-verification)
  - [Proving with a Passkey-Bound Secret](#proving-with-a-passkey-bound-secret)
- [Use Cases](#use-cases)
- [Security Considerations](#security-considerations)
- [API Reference](#api-reference)
  - [Key Stretching](#key-stretching)
  - [Salted Hashing](#salted-hashing-1)
  - [Iterative Hashing](#iterative-hashing-1)
  - [Merkle Trees](#merkle-trees-1)
  - [Other Utilities](#other-utilities)
  - [NFT Ownership Utilities](#nft-ownership-utilities)
  - [Baby Jubjub](#baby-jubjub)
  - [ElGamal](#elgamal)
  - [Artifact Verification](#artifact-verification)
- [Examples](#examples)
- [Testing](#testing)
- [Performance Benchmarks](#performance-benchmarks)
- [Resources](#resources)

---

## Overview

The w3pk SDK provides a comprehensive suite of zero-knowledge cryptographic utilities designed for privacy-preserving applications. These utilities enable:

- **Password Security**: PBKDF2-based key stretching
- **Deterministic Derivation**: Reproducible key generation
- **Privacy-Preserving Identifiers**: Salted hashing for user IDs
- **Commitment Schemes**: Cryptographic commitments for ZK proofs
- **Merkle Proofs**: Membership verification without revealing identity
- **Baby Jubjub and ElGamal**: Curve keys and additively homomorphic encryption that circom circuits can check

All utilities are built on Web Crypto API standards and are compatible with both browser and Node.js environments.

---

## Installation

```bash
npm install w3pk ethers
```

For zero-knowledge proof features:
```bash
npm install snarkjs circomlibjs
```

For `zkProve()` derivations, also `poseidon-lite`; for Semaphore identities, `@semaphore-protocol/identity`.

**Content Security Policy**

w3pk loads `w3pk/zk` with a plain `import()`, so it needs no `'unsafe-eval'`. snarkjs and circomlibjs compile WebAssembly, which needs `'wasm-unsafe-eval'`: `script-src 'self' 'wasm-unsafe-eval'`. Without it, zk calls fail with a `CompileError` from `WebAssembly.compile()`.

---

## Core Utilities

### Key Stretching & Derivation

#### `stretchKey()`

Stretches a key using PBKDF2 (Password-Based Key Derivation Function 2) to derive a cryptographically secure key from a password or input string.

**Signature:**
```typescript
async function stretchKey(
  input: string,
  salt: string,
  iterations?: number,  // Default: 10000
  keyLength?: number    // Default: 32 bytes
): Promise<string>
```

**Use Cases:**
- Password hashing for authentication
- Deterministic wallet key derivation
- Secure key generation from user input
- Privacy-preserving credential systems

**Example:**
```typescript
import { stretchKey } from 'w3pk/zk/utils'

// Hash a password for storage
const password = "MySecurePassword123!"
const userSalt = "user-12345-unique-salt"
const iterations = 100000  // Higher = more secure but slower

const hashedPassword = await stretchKey(password, userSalt, iterations)
// hashedPassword: "a7b2c9d1e5f4..." (64 hex characters)

// Verify password later
const loginPassword = "MySecurePassword123!"
const verifyHash = await stretchKey(loginPassword, userSalt, iterations)
const isValid = hashedPassword === verifyHash  // true
```

**Security Properties:**
- ✅ Resistant to rainbow table attacks (salt-based)
- ✅ Configurable iteration count for future-proofing
- ✅ Deterministic output for same input+salt
- ✅ Computationally expensive to brute-force

---

### Salted Hashing

#### `hashWithSalt()`

Combines data with a salt and hashes using SHA-256, creating deterministic but unpredictable identifiers.

**Signature:**
```typescript
async function hashWithSalt(
  data: string,
  salt: string
): Promise<string>
```

**Use Cases:**
- Creating privacy-preserving user IDs
- Deterministic address derivation
- Content fingerprinting
- Anonymous credential systems

**Example:**
```typescript
import { hashWithSalt } from 'w3pk/zk/utils'

// Create privacy-preserving user ID
const email = "alice@example.com"
const appSecret = "my-app-secret-2024"

const userId = await hashWithSalt(email, appSecret)
// userId: "8f3c7a2b..." (64 hex characters)

// Same email always produces same ID
const verifyId = await hashWithSalt(email, appSecret)
console.log(userId === verifyId)  // true

// Different email produces different ID
const bobId = await hashWithSalt("bob@example.com", appSecret)
console.log(userId !== bobId)  // true
```

**Security Properties:**
- ✅ One-way function (cannot reverse)
- ✅ Deterministic for same input
- ✅ Avalanche effect (small change = completely different output)
- ✅ Collision-resistant

---

### Iterative Hashing

#### `iterativeHash()`

Applies SHA-256 hashing multiple times to increase computational cost, making brute-force attacks impractical.

**Signature:**
```typescript
async function iterativeHash(
  data: string,
  salt: string,
  iterations: number
): Promise<string>
```

**Use Cases:**
- Commitment secrets for zero-knowledge proofs
- Slow password hashing
- Time-lock puzzles
- Proof-of-work systems

**Example:**
```typescript
import { iterativeHash } from 'w3pk/zk/utils'

// Create commitment secret
const secretValue = "my-secret-vote"
const nonce = "random-nonce-12345"
const iterations = 10000

const commitment = await iterativeHash(secretValue, nonce, iterations)
// commitment: "2d4e8f1c..." (64 hex characters)

// Verify commitment later
const revealed = await iterativeHash(secretValue, nonce, iterations)
console.log(commitment === revealed)  // true

// Different values produce different commitments
const otherCommitment = await iterativeHash("other-vote", nonce, iterations)
console.log(commitment !== otherCommitment)  // true
```

**Security Properties:**
- ✅ Computationally expensive (configurable)
- ✅ Resistant to brute-force attacks
- ✅ Deterministic verification
- ✅ No trusted setup required

---

### Merkle Trees

#### `buildMerkleTree()`

Constructs a Merkle tree from a list of leaves using Poseidon hash, enabling efficient membership proofs.

**Signature:**
```typescript
async function buildMerkleTree(
  leaves: string[]
): Promise<{
  root: string
  tree: string[][]
}>
```

**Use Cases:**
- Anonymous voting (prove you're eligible without revealing identity)
- Allowlist management
- Credential verification

**Example:**
```typescript
import { buildMerkleTree, generateMerkleProof } from 'w3pk/zk/utils'

// Build tree of verified users
const verifiedUsers = [
  '0x1111111111111111111111111111111111111111',
  '0x2222222222222222222222222222222222222222',
  '0x3333333333333333333333333333333333333333',
  '0x4444444444444444444444444444444444444444'
]

const { root, tree } = await buildMerkleTree(
  verifiedUsers.map(addr => BigInt(addr).toString())
)

console.log(`Merkle Root: ${root}`)
console.log(`Tree Levels: ${tree.length}`)

// Generate proof for user at index 2
const myIndex = 2
const { pathIndices, pathElements } = generateMerkleProof(tree, myIndex)

// Now you can prove you're in the set without revealing which user you are!
console.log(`Proof depth: ${pathIndices.length}`)
```

**Security Properties:**
- ✅ Efficient verification (O(log n))
- ✅ Compact proofs (~32 bytes per level)
- ✅ Tamper-evident (any change invalidates root)
- ✅ Privacy-preserving (doesn't reveal position)

---

### Commitments

#### `generateBlinding()`

Generates a cryptographically secure random blinding factor for commitments.

**Signature:**
```typescript
function generateBlinding(): bigint
```

**Example:**
```typescript
import { generateBlinding } from 'w3pk/zk/utils'

// Generate random blinding for commitment
const blinding = generateBlinding()
// blinding: 98234729847298374982734n (random 256-bit number)

// Each call produces different value
const blinding2 = generateBlinding()
console.log(blinding !== blinding2)  // true
```

---

### Baby Jubjub and ElGamal

`w3pk/zk` implements [Baby Jubjub (EIP-2494)](https://eips.ethereum.org/EIPS/eip-2494) and exponential ElGamal on it, matching circomlib's `babyjub` gadgets and circomlibjs's encodings, so values built here can be checked in circom circuits. The code is synchronous native `bigint` and needs neither `circomlibjs` nor `snarkjs`.

- Points are affine `[x, y]` tuples (`BabyJubPoint`), the layout circom signals use
- The base point `B` is `BABYJUB_BASE8` (`8 · Generator`), which generates the prime-order subgroup of order `l = BABYJUB_SUBORDER`
- A public key is `sk · B` with `sk` in `[1, l)`, as circomlib's `BabyPbk` computes it
- A ciphertext is `Enc(m; r) = (r · B, m · B + r · PK)`

#### Keys

```typescript
import {
  generateBabyJubKeyPair,
  deriveBabyJubKeyPair,
  packBabyJubPublicKey,
  unpackBabyJubPublicKey,
} from 'w3pk/zk'

const { privateKey, publicKey } = generateBabyJubKeyPair()

// Deterministic, e.g. from a passkey-bound secret
const { secret } = await w3pk.derivePrfSecret('zk-identity')
const keys = deriveBabyJubKeyPair(secret)

// 32 bytes, as circomlibjs's packPoint
const packed = packBabyJubPublicKey(keys.publicKey)
const pk = unpackBabyJubPublicKey(packed) // throws on invalid or low-order points
```

`deriveBabyJubKeyPair(secret)` takes a secret of at least 16 bytes and computes `sk = HKDF-SHA256(secret, info = "w3pk-babyjub-v1", 64 bytes) mod (l - 1) + 1`. It is not circomlib EdDSA's `prv2pub`, whose scalars can exceed `l`; an EdDSA scalar `S` gives the same public key as `babyJubPublicKey(S % l)`.

#### Exponential ElGamal

```typescript
import {
  elgamalEncrypt,
  elgamalAdd,
  elgamalRerandomize,
  elgamalDecrypt,
} from 'w3pk/zk'

const ballots = [1n, 0n, 1n].map((v) => elgamalEncrypt(publicKey, v))
const tally = ballots.reduce(elgamalAdd)          // Enc(2)
const mixed = elgamalRerandomize(publicKey, tally) // same plaintext, fresh randomness
elgamalDecrypt(privateKey, mixed, ballots.length)  // 2n
```

The message is encoded as `m · B`, so decryption recovers a point and then solves a bounded discrete log: `elgamalDecrypt` takes `maxValue` (at most 2^32) and throws when the plaintext is outside `[0, maxValue]`. `elgamalDecryptToPoint` returns `m · B` for any `m`. Pass `r` to `elgamalEncrypt` or `elgamalRerandomize` when a proof needs it as a witness; it defaults to a fresh random scalar.

#### Validation

Every function that takes a public key or ciphertext checks it first and throws `CryptoError` on:

- coordinates outside `[0, p)` or points off the curve
- points outside the prime-order subgroup, including the 8 low-order points and any point with a torsion component (`isInBabyJubSubgroup` checks `l · P = (0, 1)`)
- the identity as a public key
- packed encodings with `y ≥ p`, no point on the curve, or a sign bit on `x = 0`

Scalar multiplication runs a Montgomery ladder over at least 256 bits, so the number of point operations doesn't depend on the scalar. JavaScript `bigint` arithmetic is not constant time, so this is not a guarantee against a local timing attacker.

---

### Semaphore Identities

`w3pk.getSemaphoreIdentity(tag)` returns the commitment of a [Semaphore v4](https://docs.semaphore.pse.dev/guides/identities) identity whose private key is a passkey PRF secret. The private key never leaves w3pk, isn't stored and isn't in backups.

```typescript
const { commitment, credentialId } = await w3pk.getSemaphoreIdentity('voting')
group.addMember(commitment)
```

- Needs the optional dependency `@semaphore-protocol/identity`, imported only when the method is called
- The commitment equals `new Identity(privateKey).commitment` from `@semaphore-protocol/identity`: Poseidon of the EdDSA-Poseidon public key on Baby Jubjub
- The private key is derived under its own PRF label (`w3pk-semaphore-v1`), so `derivePrfSecret(tag)` can't return it for any tag, and building an `Identity` from `derivePrfSecret()` gives a different commitment
- A new passkey gives a new commitment: keep `credentialId` with the commitment and update the group member when it changes

See the [API reference](./API_REFERENCE.md#getsemaphoreidentitytag-string-promisesemaphoreidentity).

---

### NFT Ownership Proofs

`w3pk.zk.proveNFTOwnership()` proves that a holder identity is in a holders tree with at least `minBalance` tokens, without revealing which holder. The identity is a Semaphore v4 identity derived from the wallet in the session, one per origin and contract, so there is no extra passkey prompt.

1. **Holder:** `w3pk.zk.getNFTHolderCommitment(contract)`, then register the commitment with the address that holds the tokens, e.g. by signing it with `signMessage()`
2. **Registrar:** check each registration's signature and the address's balance, then publish `[{ commitment, balance }]`. The proof trusts this list: anyone in it can prove, with the balance it records
3. **Holder:** `generateNFTOwnershipProofInputs(commitment, contract, holders, scope, minBalance)`, then `w3pk.zk.proveNFTOwnership(input)`
4. **Verifier:** `w3pk.zk.verifyNFTOwnership(proof, contract, root, minBalance, scope)`, and refuse a nullifier already seen in that scope

`nft.circom`:

- Leaf: `Poseidon(commitment, contract, balance)`, with `commitment = Poseidon(BabyPbk(secret))` as in Semaphore v4 and `secret` range-checked to 251 bits and below the subgroup order `l`. Empty leaves are 0; the tree has 20 levels
- `balance >= minBalance`, both range-checked to 64 bits
- Nullifier: `Poseidon(scope, secret)`. The public signals are `[nullifier, root, contractAddress, minBalance, scope]`; none depends on which holder proved except the nullifier, which only links proofs in the same scope

The holders list is public, so a commitment tied to an address at registration is known to be a holder; the proof hides which one. A unique balance narrows the anonymity set to the holders with at least `minBalance`.

---

### Membership, Threshold and Range Circuits

- `membership.circom`: the nullifier is `Poseidon(scope, leaf)`, with a public `scope` as in Semaphore. `proveMembership(input)` takes an optional `input.scope` (default 0) and `verifyMembership(proof, root, scope?)` checks it; public signals are `[nullifier, root, scope]`. Give each app or action its own scope, so that its nullifiers can't be matched with another's. The leaf itself is hashed, so anyone who knows the leaves, such as a public allowlist of addresses, can compute every member's nullifier and tell who proved. For anonymity, the leaves must be values derived from a secret, like the commitments of `nft.circom`
- `threshold.circom` and `range.circom`: every comparator input (`value`, `threshold`, `min`, `max`) is range-checked to 128 bits with `Num2Bits(128)`, and the comparators are 128-bit. Without the check, circomlib's comparators wrap around the field: a 252-bit `GreaterEqThan` accepted `0 >= p - 2^252 + 1`. Public signals are `[threshold, commitment]` and `[min, max, commitment]`

Recompile the circuits and redo their setup after upgrading.

---

### Trusted Setup

A Groth16 key with no phase-2 contribution has known toxic waste: anyone can redo `groth16 setup` and forge proofs for that circuit. `scripts/compile-circuits.js` has two modes:

- `pnpm compile:circuits [--ptau <file>]` compiles the circuits and writes `src/zk/templates/zkeys/<name>_test_only.zkey` straight from `groth16 setup`, with `testOnly: true` in `artifacts.json`. These keys are for tests only; never ship them
- `pnpm compile:circuits:release [--ptau <file>]` creates no key. It takes `<name>_final.zkey` from a phase-2 ceremony and fails unless the key has at least one contribution that isn't a beacon and passes `snarkjs zkey verify` against the circuit and the ptau

The ptau defaults to `scripts/powersOfTau28_hez_final_15.ptau`, from the [Hermez ceremony](https://github.com/iden3/snarkjs#7-prepare-phase-2) (`https://circom.info/powersOfTau28_hez_final_15.ptau`). Run phase 2 as in the [snarkjs README](https://github.com/iden3/snarkjs#groth16): `snarkjs groth16 setup` for `<name>_0000.zkey`, one `snarkjs zkey contribute` per participant, then `snarkjs zkey beacon` for `<name>_final.zkey`. A beacon alone doesn't count: its randomness is public.

---

### Circuit Artifact Verification

A proof is only as trustworthy as the circuit it was made with: whoever serves the `.wasm` and `.zkey` (host, CDN) can swap them for a circuit the app didn't choose. `verifyZkArtifacts` computes the IPFS CIDs of both files and checks them against CIDs pinned onchain before you prove. A list of hashes shipped with the app doesn't help, since whoever can swap the artifacts can swap the list.

```typescript
import { ethers } from 'ethers'
import { readZkArtifactPins, verifyZkArtifacts, ZkArtifactMismatchError } from 'w3pk/zk'

const registry = new ethers.Contract(
  REGISTRY_ADDRESS,
  ['function getCidByVersion(string version) view returns (string)'],
  new ethers.JsonRpcProvider('https://mainnet.optimism.io')
)

const pins = await readZkArtifactPins(registry, {
  wasm: 'vote-v1.wasm',
  zkey: 'vote-v1.zkey',
})

try {
  const { wasm, zkey } = await verifyZkArtifacts(
    { wasm: '/circuits/vote.wasm', zkey: '/circuits/vote_final.zkey' },
    pins
  )
  // Prove with these bytes, not by fetching the URLs again
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey)
} catch (error) {
  if (error instanceof ZkArtifactMismatchError) {
    console.error(error.artifact, error.expectedCid, error.actualCid)
  }
  throw error
}
```

- Artifacts are bytes (any `ArrayBuffer` or view) or URLs; URLs are fetched once and the verified bytes are returned, so the checked files are the ones you prove with
- CIDs are computed as `ipfs add --cid-version 1` does (UnixFS, raw leaves, 256 KiB chunks, balanced layout), with the same helper as [build verification](./BUILD_VERIFICATION.md#zk-circuit-artifacts). Get the CID to pin with `ipfs add --cid-version 1 -n circuit_final.zkey`
- Pins are compared as exact strings, so pin the base32 CIDv1 (`bafy…`, or `bafk…` for files up to 256 KiB) that command prints
- `pins` can also be plain CIDs, e.g. from your own contract: `verifyZkArtifacts(artifacts, { wasm: 'bafy…', zkey: 'bafy…' })`
- `readZkArtifactPins` works with any object that has the build registry's `getCidByVersion(string)`, such as an ethers `Contract` for the [build registry](./BUILD_VERIFICATION.md#onchain-registry) or your own deployment of it

| Error | When |
|-------|------|
| `ZkArtifactMismatchError` (`ZK_ARTIFACT_MISMATCH`) | an artifact's CID differs from its pin |
| `Web3PasskeyError` `ZK_ARTIFACT_FETCH_ERROR` | an artifact URL can't be fetched |
| `Web3PasskeyError` `ZK_ARTIFACT_NOT_PINNED` | the registry has no CID under a key |

---

### Proving with a Passkey-Bound Secret

`w3pk.zkProve(tag, artifacts, publicInputs, extraWitness?, options?)` makes a Groth16 proof with a secret bound to the passkey that the app never sees. w3pk derives the secret, places it in the witness with any inputs it derives or randomizes for you, checks the artifacts against their pins, runs snarkjs in a Web Worker, and returns only `{ proof, publicSignals }`.

```typescript
const pins = await readZkArtifactPins(registry, { wasm: 'vote-v1.wasm', zkey: 'vote-v1.zkey' })

const { proof, publicSignals } = await w3pk.zkProve(
  'voting',
  { wasm: '/circuits/vote.wasm', zkey: '/circuits/vote_final.zkey', pins },
  { proposalId, root },                 // public inputs
  { vote: 1, pathElements, pathIndices }, // other private inputs
  {
    secret: 'semaphore',                // the identity from getSemaphoreIdentity('voting')
    derive: { voteSecret: ['secret', 'proposalId', 0x564f5445n] }, // Poseidon(secret, proposalId, "VOTE")
    random: ['r'],                      // e.g. ElGamal randomness
  }
)
```

**Options**

| Option | Default | Meaning |
|--------|---------|---------|
| `secret` | `'zk'` | `'zk'`: a Baby Jubjub private key derived from a PRF secret under its own label, `w3pk-zk-v1`. `'semaphore'`: the `secretScalar` of the identity `getSemaphoreIdentity(tag)` commits to (label `w3pk-semaphore-v1`) |
| `secretInput` | `'secret'` | circuit input that receives the secret |
| `derive` | none | `{ name: terms }`: inputs w3pk computes as `Poseidon(terms)`, in order. A string term names another input (the secret, a public or extra input, a random input or an earlier derivation); a bigint is a constant. 1 to 16 terms |
| `random` | none | inputs w3pk fills with fresh scalars in `[1, l)` (`randomBabyJubScalar()`), used for this proof and discarded |

Both secrets are scalars in `[1, l)`, so a circuit can use either as a Baby Jubjub private key. Neither is reachable from `derivePrfSecret(tag)`, whose label is `w3pk-prf-v1`.

**Guarantees**

- The secret, derived values and random values are not returned, stored, logged or put in backups. A proof whose public signals contain the secret or a random input is refused with `CryptoError`. Derived values may be public, such as a nullifier: they are one-way, and the circuit decides what it exposes
- The caller can't set an input w3pk sets itself (the secret, a derived or a random input)
- Everything that can fail without the passkey (options, tag, missing dependencies, [artifact pins](#circuit-artifact-verification), the worker) fails before the prompt. Proving uses the bytes `verifyZkArtifacts` checked
- Requires `snarkjs`, plus `poseidon-lite` for `derive` and `@semaphore-protocol/identity` for `secret: 'semaphore'`, all optional dependencies imported on use

**Worker**

snarkjs runs in a module worker, `dist/zk/prove-worker.mjs`, started with `new Worker(new URL('./zk/prove-worker.mjs', import.meta.url), { type: 'module' })`, which webpack 5 and Vite bundle with snarkjs. Proving runs in-thread where `Worker` doesn't exist (Node) or the worker can't start: the CommonJS build (no `import.meta.url`), a bundler that didn't emit the worker, or a CSP that blocks it. In Vite dev, if the worker isn't found, add `w3pk` to `optimizeDeps.exclude`. The worker keeps the UI responsive; it is not a security boundary.

**Circuit trust**

w3pk refuses a proof only when a public signal equals the secret or a random input. The circuit chooses its public signals and can output any function of the secret, such as its bits, `secret + 1` or a weak hash, and with `secret: 'semaphore'` that secret is the Semaphore identity's `secretScalar`. The artifact pins guarantee which circuit runs, not what it reveals, so only prove with circuits you have reviewed or trust.

**Isolation limit**

w3pk runs in the host app's JavaScript context. `zkProve` keeps the secret out of the API, so an honest app can't leak it or keep a receipt of its randomness, but it doesn't put the secret out of reach of malicious code on the same page (XSS, a compromised dependency): that code can evaluate the PRF with the same input after a user-approved prompt, or read the witness in memory. The [cross-origin wallet](https://github.com/w3hc/w3pk/issues/156) is what isolates it fully.

See the [API reference](./API_REFERENCE.md#zkprovetag-artifacts-publicinputs-extrawitness-options-promisezkproveresult).

---

## Use Cases

### 1. Password Hashing System

```typescript
import { stretchKey } from 'w3pk/zk/utils'

class UserAuth {
  async hashPassword(password: string, userId: string): Promise<string> {
    const salt = `user-${userId}-salt-2024`
    const iterations = 100000  // Adjust based on security needs
    return await stretchKey(password, salt, iterations)
  }

  async verifyPassword(
    password: string,
    userId: string,
    storedHash: string
  ): Promise<boolean> {
    const hash = await this.hashPassword(password, userId)
    return hash === storedHash
  }
}

// Usage
const auth = new UserAuth()
const passwordHash = await auth.hashPassword("SecurePass123!", "user-42")
// Store passwordHash in database

// Later: verify login
const isValid = await auth.verifyPassword("SecurePass123!", "user-42", passwordHash)
console.log(isValid)  // true
```

---

### 2. Privacy-Preserving User IDs

```typescript
import { hashWithSalt } from 'w3pk/zk/utils'

class PrivacyPreservingAuth {
  private appSecret = process.env.APP_SECRET!

  async createUserId(email: string): Promise<string> {
    // Creates deterministic but privacy-preserving ID
    return await hashWithSalt(email, this.appSecret)
  }

  async verifyUserIdentity(email: string, userId: string): Promise<boolean> {
    const computedId = await this.createUserId(email)
    return computedId === userId
  }
}

// Usage
const privacy = new PrivacyPreservingAuth()
const userId = await privacy.createUserId("alice@example.com")
// userId can be stored publicly without revealing email

// Verify identity later
const isValid = await privacy.verifyUserIdentity("alice@example.com", userId)
```

---

### 3. Commitment Scheme for Voting

```typescript
import { iterativeHash, hashWithSalt } from 'w3pk/zk/utils'

class AnonymousVoting {
  async createVoteCommitment(
    vote: string,
    voterSecret: string
  ): Promise<string> {
    // Create commitment that hides vote until reveal phase
    const nonce = voterSecret + Date.now()
    return await iterativeHash(vote, nonce, 10000)
  }

  async revealVote(
    vote: string,
    voterSecret: string,
    commitment: string
  ): Promise<boolean> {
    const nonce = voterSecret + Date.now()
    const revealed = await iterativeHash(vote, nonce, 10000)
    return revealed === commitment
  }
}

// Usage
const voting = new AnonymousVoting()

// Commit phase: voter submits commitment
const myVote = "candidate-A"
const mySecret = "voter-secret-12345"
const commitment = await voting.createVoteCommitment(myVote, mySecret)

// Reveal phase: voter reveals their vote
const isValid = await voting.revealVote(myVote, mySecret, commitment)
```

---

### 4. Deterministic Wallet Key Derivation

```typescript
import { stretchKey } from 'w3pk/zk/utils'

class DeterministicWallet {
  async deriveKey(
    masterPassword: string,
    accountIndex: number,
    purpose: string
  ): Promise<string> {
    // Derive deterministic key for specific purpose
    const salt = `account-${accountIndex}-${purpose}`
    return await stretchKey(masterPassword, salt, 50000, 32)
  }
}

// Usage
const wallet = new DeterministicWallet()

// Derive different keys for different purposes from same password
const signingKey = await wallet.deriveKey("MyMasterPassword", 0, "signing")
const encryptionKey = await wallet.deriveKey("MyMasterPassword", 0, "encryption")
const accountKey = await wallet.deriveKey("MyMasterPassword", 1, "signing")

// Each key is different but deterministically derived
console.log(signingKey !== encryptionKey)  // true
console.log(signingKey !== accountKey)     // true
```

---

### 5. Zero-Knowledge Membership Proof

```typescript
import {
  buildMerkleTree,
  generateMerkleProof,
  stretchKey
} from 'w3pk/zk/utils'

class MembershipProof {
  async proveAllowlistMembership(
    allowlist: string[],
    myAddress: string
  ): Promise<{
    root: string
    proof: { pathIndices: number[], pathElements: string[] }
  }> {
    // Build merkle tree
    const leaves = allowlist.map(addr => BigInt(addr).toString())
    const { root, tree } = await buildMerkleTree(leaves)

    // Find my position
    const myIndex = allowlist.findIndex(
      addr => addr.toLowerCase() === myAddress.toLowerCase()
    )

    if (myIndex === -1) {
      throw new Error("Address not in allowlist")
    }

    // Generate proof
    const proof = generateMerkleProof(tree, myIndex)

    return { root, proof }
  }
}

// Usage
const membership = new MembershipProof()

const allowlist = [
  '0x1111111111111111111111111111111111111111',
  '0x2222222222222222222222222222222222222222',
  '0x3333333333333333333333333333333333333333'
]

const myAddress = '0x2222222222222222222222222222222222222222'
const { root, proof } = await membership.proveAllowlistMembership(
  allowlist,
  myAddress
)

// Can now prove membership without revealing which address
console.log(`Merkle Root: ${root}`)
console.log(`Proof Length: ${proof.pathIndices.length}`)
```

---

## Security Considerations

### 1. Salt Management

**Best Practices:**
- ✅ Use unique salt per user/entity
- ✅ Store salt separately from hash
- ✅ Use cryptographically random salts
- ❌ Never reuse salts across different contexts
- ❌ Don't use predictable salts (timestamps, sequential IDs)

```typescript
// Good: unique per user
const salt = `user-${userId}-${crypto.randomUUID()}`

// Bad: predictable
const salt = `user-${userId}`
```

---

### 2. Iteration Count Selection

**Guidelines:**

| Security Level | PBKDF2 Iterations | Use Case |
|---------------|-------------------|----------|
| Low           | 10,000            | Development/testing |
| Medium        | 100,000           | Standard applications |
| High          | 500,000+          | High-security systems |

```typescript
// Adjust based on threat model
const devIterations = 10_000
const prodIterations = 100_000
const highSecIterations = 500_000

const iterations = process.env.NODE_ENV === 'production'
  ? prodIterations
  : devIterations
```

---

### 3. Key Length Requirements

**Recommendations:**

| Key Length | Security Level | Use Case |
|-----------|----------------|----------|
| 16 bytes  | 128-bit        | Short-term secrets |
| 32 bytes  | 256-bit        | Standard (recommended) |
| 64 bytes  | 512-bit        | Maximum security |

```typescript
// Standard: 32 bytes (256 bits)
const key = await stretchKey(password, salt, 100000, 32)

// High security: 64 bytes (512 bits)
const strongKey = await stretchKey(password, salt, 100000, 64)
```

---

### 4. Timing Attack Prevention

All functions in this library are designed to be resistant to timing attacks through:

- ✅ Constant-time comparison should be used externally
- ✅ Deterministic execution time for same parameters
- ✅ No early returns based on secret values

```typescript
// Use constant-time comparison for hashes
function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false

  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return result === 0
}
```

---

### 5. Commitment Security

**Requirements for Secure Commitments:**

- ✅ Use cryptographically secure random blinding factors
- ✅ Never reuse blinding factors
- ✅ Keep blinding factors secret until reveal phase
- ✅ Sufficient iteration count to prevent brute-force

```typescript
import { generateBlinding, iterativeHash } from 'w3pk/zk/utils'

// Good: fresh random blinding
const blinding = generateBlinding()
const commitment = await iterativeHash(
  secretValue,
  blinding.toString(),
  10000
)

// Bad: predictable blinding
const badBlinding = Date.now().toString()  // Don't do this!
```

---

## API Reference

### Key Stretching

#### `stretchKey(input, salt, iterations?, keyLength?)`

Derives a key using PBKDF2-SHA256.

**Parameters:**
- `input` (string): Input data to stretch (e.g., password)
- `salt` (string): Salt value for uniqueness
- `iterations` (number, optional): Iteration count (default: 10000)
- `keyLength` (number, optional): Output length in bytes (default: 32)

**Returns:** `Promise<string>` - Hex-encoded stretched key

**Throws:** `CryptoError` if derivation fails

---

### Salted Hashing

#### `hashWithSalt(data, salt)`

Hashes data with salt using SHA-256.

**Parameters:**
- `data` (string): Data to hash
- `salt` (string): Salt value

**Returns:** `Promise<string>` - Hex-encoded hash (64 characters)

**Throws:** `CryptoError` if hashing fails

---

### Iterative Hashing

#### `iterativeHash(data, salt, iterations)`

Applies SHA-256 multiple times.

**Parameters:**
- `data` (string): Data to hash
- `salt` (string): Salt value
- `iterations` (number): Number of hash rounds (must be ≥ 1)

**Returns:** `Promise<string>` - Hex-encoded hash (64 characters)

**Throws:**
- `Error` if iterations < 1
- `CryptoError` if hashing fails

---

### Merkle Trees

#### `buildMerkleTree(leaves)`

Builds a Merkle tree using Poseidon hash.

**Parameters:**
- `leaves` (string[]): Leaf values (as strings)

**Returns:** `Promise<{ root: string, tree: string[][] }>`
- `root`: Merkle root hash
- `tree`: All levels of the tree

**Throws:** `CryptoError` if circomlibjs not installed or build fails

---

#### `generateMerkleProof(tree, leafIndex)`

Generates a Merkle proof for a specific leaf.

**Parameters:**
- `tree` (string[][]): Tree from `buildMerkleTree()`
- `leafIndex` (number): Index of leaf to prove

**Returns:** `{ pathIndices: number[], pathElements: string[] }`
- `pathIndices`: Binary path (0=left, 1=right)
- `pathElements`: Sibling hashes along path

`membership.circom` and `nft.circom` take exactly 20 levels and constrain every `pathIndices[i]` to 0 or 1, so a path index outside `{0, 1}` fails the proof.

---

### Other Utilities

#### `generateBlinding()`

Generates a cryptographically secure random 256-bit number.

**Returns:** `bigint` - Random blinding factor

---

#### `sha256Hash(data)`

Computes SHA-256 hash of data.

**Parameters:**
- `data` (string | Uint8Array): Data to hash

**Returns:** `Promise<string>` - Hex-encoded hash

**Throws:** `CryptoError` if hashing fails

---

#### `bufferToBigInt(buffer)`

Converts a Uint8Array buffer to a BigInt.

**Parameters:**
- `buffer` (Uint8Array): Buffer to convert

**Returns:** `bigint` - Converted BigInt value

---

#### `bigIntToBuffer(value, byteLength?)`

Converts a BigInt to a Uint8Array buffer.

**Parameters:**
- `value` (bigint): BigInt to convert
- `byteLength` (number, optional): Output buffer length (default: 32)

**Returns:** `Uint8Array` - Converted buffer

---

#### `hexToBigInt(hex)`

Converts a hex string to a BigInt.

**Parameters:**
- `hex` (string): Hex string (with or without '0x' prefix)

**Returns:** `bigint` - Converted BigInt value

---

#### `bigIntToHex(value, padToBytes?)`

Converts a BigInt to a hex string.

**Parameters:**
- `value` (bigint): BigInt to convert
- `padToBytes` (number, optional): Pad output to this many bytes

**Returns:** `string` - Hex string with '0x' prefix

---

#### `generateNonce()`

Generates a random nonce for challenges.

**Returns:** `bigint` - Random 256-bit nonce

---

#### `isValidAddress(address)`

Validates Ethereum address format.

**Parameters:**
- `address` (string): Address to validate

**Returns:** `boolean` - True if valid Ethereum address format

---

#### `serializeProof(proof)`

Serializes a ZK proof for storage or transmission.

**Parameters:**
- `proof` (any): ZK proof object

**Returns:** `string` - JSON-serialized proof

---

#### `deserializeProof(serialized)`

Deserializes a ZK proof from storage or transmission.

**Parameters:**
- `serialized` (string): JSON-serialized proof

**Returns:** `any` - Deserialized proof object

**Throws:** `CryptoError` if deserialization fails

---

#### `validateProofInputs(inputs)`

Validates that all required proof inputs are present.

**Parameters:**
- `inputs` (Record<string, any>): Proof inputs to validate

**Throws:** `CryptoError` if any required input is missing

---

### NFT Ownership Utilities

All exported from `w3pk/zk/utils`; they need `poseidon-lite`. `NFT_TREE_DEPTH` is 20, the depth `nft.circom` takes.

#### `buildNFTHoldersMerkleTree(holders, contractAddress)`

Builds the holders tree `nft.circom` proves against.

**Parameters:**
- `holders` (`NFTHolder[]`): `{ commitment: string | bigint, balance: bigint }` per holder, commitments unique, balances below 2^64
- `contractAddress` (string): NFT contract address

**Returns:** `Promise<{ root: string, tree: string[][], holderLeaves: string[] }>`
- `holderLeaves`: `Poseidon(commitment, contract, balance)` per holder
- `tree`: the non-empty nodes of each of the 21 levels, empty slots being the zero subtree hashes; `tree[20]` is `[root]`

**Throws:** `CryptoError` on an invalid address, an empty or oversized list, a duplicate commitment or a balance out of range

---

#### `generateNFTOwnershipProofInputs(holderCommitment, contractAddress, holders, scope, minBalance?)`

Builds `proveNFTOwnership()`'s input for the holder with `holderCommitment`: its balance and its 20-level path.

**Parameters:**
- `holderCommitment` (string | bigint): from `getNFTHolderCommitment()`
- `contractAddress` (string): NFT contract address
- `holders` (`NFTHolder[]`): the published holders list
- `scope` (bigint | string): the verifier's scope
- `minBalance` (bigint, optional): default 1n

**Returns:** `Promise<{ nftProofInput: NFTOwnershipProofInput, holderLeaves: string[] }>`

**Throws:** `CryptoError` if the commitment isn't in the list or its balance is below `minBalance`

---

#### `validateNFTOwnershipProofInputs(inputs)`

Checks an `NFTOwnershipProofInput`: contract address, 20 path levels with indices 0 or 1, field elements, balances below 2^64, `minBalance >= 1` and `balance >= minBalance`. `proveNFTOwnership()` runs it before deriving the secret.

**Throws:** `CryptoError` if any input is invalid

---

### Baby Jubjub

All exported from `w3pk/zk`. Functions throw `CryptoError` on invalid input.

**Constants:** `BABYJUB_FIELD` (`p`, the BN254 scalar field), `BABYJUB_A`, `BABYJUB_D`, `BABYJUB_ORDER`, `BABYJUB_SUBORDER` (`l`), `BABYJUB_GENERATOR`, `BABYJUB_BASE8`, `BABYJUB_IDENTITY`

**Types:** `BabyJubPoint = readonly [bigint, bigint]`, `BabyJubKeyPair = { privateKey: bigint, publicKey: BabyJubPoint }`

| Function | Returns |
|----------|---------|
| `babyJubAdd(p, q)` | `p + q` |
| `babyJubNeg(p)` | `-p` |
| `babyJubMul(p, e)` | `e · p`, `e ≥ 0`, not reduced mod `l` |
| `babyJubEquals(p, q)` | `boolean` |
| `isOnBabyJub(p)` | `true` when `p` has canonical coordinates and is on the curve |
| `isInBabyJubSubgroup(p)` | `true` when `p` is on the curve and `l · p = (0, 1)` |
| `isValidBabyJubPublicKey(p)` | `true` when `p` is in the subgroup and not the identity |
| `assertBabyJubPublicKey(p)` / `assertBabyJubPrivateKey(sk)` | throws unless valid |
| `packBabyJubPoint(p)` / `unpackBabyJubPoint(bytes)` | 32 bytes, as circomlibjs's `packPoint` / on-curve point, no subgroup check |
| `packBabyJubPublicKey(pk)` / `unpackBabyJubPublicKey(bytes)` | same, with the public key checks |
| `randomBabyJubScalar()` | uniform scalar in `[1, l)` |
| `babyJubPublicKey(sk)` | `sk · BABYJUB_BASE8`, `sk` in `[1, l)` |
| `generateBabyJubKeyPair()` | random `BabyJubKeyPair` |
| `deriveBabyJubKeyPair(secret)` | `BabyJubKeyPair` from a secret of at least 16 bytes |
| `babyJubDiscreteLog(point, maxValue)` | smallest `m` in `[0, maxValue]` with `m · BABYJUB_BASE8 = point`, or `null`; `maxValue ≤ 2^32` |

### ElGamal

**Type:** `ElGamalCiphertext = { c1: BabyJubPoint, c2: BabyJubPoint }`

| Function | Returns |
|----------|---------|
| `elgamalEncrypt(publicKey, message, r?)` | `(r · B, m · B + r · PK)`, `m` in `[0, l)`, `r` in `[1, l)` |
| `elgamalAdd(a, b)` | ciphertext of `m1 + m2` |
| `elgamalRerandomize(publicKey, ciphertext, r?)` | same plaintext, randomness increased by `r` |
| `elgamalDecryptToPoint(privateKey, ciphertext)` | `m · B` |
| `elgamalDecrypt(privateKey, ciphertext, maxValue)` | `m`, or throws when `m > maxValue` |

### Artifact Verification

**Types:** `ZkArtifactName = 'wasm' | 'zkey'`, `ZkArtifactSource = ArrayBufferView | ArrayBuffer | string` (URL), `ZkArtifactSources`, `ZkArtifactPins` and `ZkArtifactBytes` (records keyed by `ZkArtifactName`), `ZkArtifactRegistry = { getCidByVersion(key: string): Promise<string> }`

| Function | Returns |
|----------|---------|
| `verifyZkArtifacts({ wasm, zkey }, pins)` | `Promise<{ wasm: Uint8Array, zkey: Uint8Array }>`, the verified bytes; throws `ZkArtifactMismatchError` on a CID mismatch |
| `readZkArtifactPins(registry, { wasm, zkey })` | `Promise<ZkArtifactPins>` read with `registry.getCidByVersion(key)`; throws `ZK_ARTIFACT_NOT_PINNED` on an empty CID |

`ZkArtifactMismatchError` has `code: 'ZK_ARTIFACT_MISMATCH'`, `artifact`, `expectedCid` and `actualCid`.

---

## Examples

### Complete Password Authentication System

```typescript
import { stretchKey } from 'w3pk/zk/utils'
import { randomBytes } from 'crypto'

interface UserCredentials {
  userId: string
  passwordHash: string
  salt: string
  iterations: number
}

class AuthSystem {
  private readonly iterations = 100000

  async register(userId: string, password: string): Promise<UserCredentials> {
    // Generate unique salt for user
    const salt = randomBytes(32).toString('hex')

    // Hash password with PBKDF2
    const passwordHash = await stretchKey(
      password,
      salt,
      this.iterations
    )

    return {
      userId,
      passwordHash,
      salt,
      iterations: this.iterations
    }
  }

  async login(
    password: string,
    credentials: UserCredentials
  ): Promise<boolean> {
    // Recompute hash with provided password
    const attemptHash = await stretchKey(
      password,
      credentials.salt,
      credentials.iterations
    )

    // Constant-time comparison
    return this.constantTimeCompare(attemptHash, credentials.passwordHash)
  }

  private constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false
    let result = 0
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i)
    }
    return result === 0
  }
}

// Usage
const auth = new AuthSystem()

// Registration
const credentials = await auth.register("alice", "SecurePass123!")
// Store credentials in database

// Login
const isValid = await auth.login("SecurePass123!", credentials)
console.log(`Login ${isValid ? 'successful' : 'failed'}`)
```

---

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
npm test

# Run key stretching tests specifically
npm test -- test/zk/key-stretching.test.ts

# Run with coverage
npm test -- --coverage
```

### Test Coverage

The test suite covers:

- ✅ PBKDF2 key derivation (17 tests)
- ✅ Salted hashing (8 tests)
- ✅ Iterative hashing (9 tests)
- ✅ Merkle tree operations (6 tests)
- ✅ Use case scenarios (5 tests)
- ✅ Error handling (4 tests)
- ✅ Performance benchmarks (3 tests)

**Total: 52 tests, 100% passing**

---

## Performance Benchmarks

Typical performance on modern hardware:

| Operation | Iterations/Params | Time |
|-----------|------------------|------|
| `sha256Hash()` | - | <1ms |
| `hashWithSalt()` | - | <1ms |
| `iterativeHash()` | 100 | ~10ms |
| `iterativeHash()` | 1000 | ~100ms |
| `stretchKey()` | 10,000 | ~50ms |
| `stretchKey()` | 100,000 | ~500ms |
| `buildMerkleTree()` | 100 leaves | ~100ms |
| `generateMerkleProof()` | depth 10 | <1ms |

**Note:** Higher iteration counts are intentionally slower for security.

---

## Resources

### Documentation
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [PBKDF2 Specification](https://tools.ietf.org/html/rfc2898)
- [Merkle Trees Explained](https://en.wikipedia.org/wiki/Merkle_tree)
- [EIP-2494: Baby Jubjub Elliptic Curve](https://eips.ethereum.org/EIPS/eip-2494)
- [circomlib `babyjub.circom`](https://github.com/iden3/circomlib/blob/master/circuits/babyjub.circom)

### Security
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Key Derivation Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-132.pdf)