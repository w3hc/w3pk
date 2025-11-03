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
- [Use Cases](#use-cases)
- [Security Considerations](#security-considerations)
- [API Reference](#api-reference)
  - [Key Stretching](#key-stretching)
  - [Salted Hashing](#salted-hashing-1)
  - [Iterative Hashing](#iterative-hashing-1)
  - [Merkle Trees](#merkle-trees-1)
  - [Other Utilities](#other-utilities)
  - [NFT Ownership Utilities](#nft-ownership-utilities)
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
- NFT holder verification
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

#### `buildNFTHoldersMerkleTree(holderAddresses, contractAddress)`

Builds a Merkle tree from NFT holder addresses for a specific contract.

**Parameters:**
- `holderAddresses` (string[]): Array of NFT holder addresses
- `contractAddress` (string): NFT contract address

**Returns:** `Promise<{ root: string, tree: string[][], holderLeaves: string[] }>`
- `root`: Merkle root hash
- `tree`: All levels of the tree
- `holderLeaves`: Computed leaf hashes

**Throws:** `CryptoError` if circomlibjs not installed or build fails

---

#### `generateNFTOwnershipProofInputs(ownerAddress, contractAddress, allHolderAddresses, minBalance?)`

Generates all inputs needed for NFT ownership proof.

**Parameters:**
- `ownerAddress` (string): Owner's Ethereum address
- `contractAddress` (string): NFT contract address
- `allHolderAddresses` (string[]): All holder addresses
- `minBalance` (bigint, optional): Minimum balance required (default: 1n)

**Returns:** `Promise<{ nftProofInput: {...}, holderLeaves: string[] }>`

**Throws:** `CryptoError` if owner not found in holders list

---

#### `validateNFTOwnershipProofInputs(inputs)`

Validates NFT ownership proof inputs.

**Parameters:**
- `inputs` (object): Proof inputs containing ownerAddress, contractAddress, etc.

**Throws:** `CryptoError` if any input is invalid

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

### Security
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Key Derivation Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-132.pdf)