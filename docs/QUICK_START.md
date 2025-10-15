# w3pk Quick Start Guide

## Installation

### Basic Installation (Core Features Only)

```bash
npm install w3pk ethers
```

This gives you:
- ✅ WebAuthn passwordless authentication
- ✅ Encrypted wallet management
- ✅ BIP39 HD wallet generation
- ✅ Message signing
- ✅ Stealth addresses (privacy-preserving transactions)

### With Stealth Addresses

Stealth addresses are included by default, just enable them:

```typescript
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  stealthAddresses: {}  // Enable stealth addresses
})
```

### With Zero-Knowledge Proofs (Optional)

ZK proofs require additional dependencies. Install only if you need ZK features:

```bash
npm install w3pk ethers
npm install snarkjs circomlibjs  # Optional: Only needed for ZK proofs
```

**Bundle size impact:**
- Core only: ~5MB (WebAuthn, wallets, stealth addresses)  
- With ZK: ~75MB (includes cryptographic libraries)

**Without ZK dependencies installed:**
- ✅ Core SDK works perfectly
- ❌ ZK features will throw helpful error messages with install instructions

Then enable in your code:

```typescript
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  zkProofs: {
    enabledProofs: ['membership', 'threshold', 'range']
  }
})
```

## Usage Examples

### 1. Basic Authentication

```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org'
})

// Register new user
await w3pk.register({
  username: 'alice',
  ethereumAddress: '0x...'  // Generated automatically
})

// Login
await w3pk.login()

// Sign message
const signature = await w3pk.signMessage('Hello World')
```

### 2. Wallet Management

```typescript
// Generate new wallet
const wallet = await w3pk.generateWallet()
console.log(wallet.address)   // 0x...
console.log(wallet.mnemonic)  // 12-word phrase

// Export wallet after login
const mnemonic = await w3pk.exportMnemonic()

// Derive HD wallet at index
const derived = await w3pk.deriveWallet(1)
console.log(derived.address)
console.log(derived.privateKey)
```

### 3. Stealth Addresses

```typescript
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  stealthAddresses: {}
})

await w3pk.login()

// Generate stealth address
const stealth = await w3pk.stealth?.generateStealthAddress()
console.log(stealth.stealthAddress)      // Fresh address
console.log(stealth.stealthPrivateKey)   // Private key
console.log(stealth.ephemeralPublicKey)  // For publishing

// Get stealth keys
const keys = await w3pk.stealth?.getKeys()
console.log(keys.metaAddress)
console.log(keys.viewingKey)
console.log(keys.spendingKey)
```

### 4. Zero-Knowledge Proofs

**Prerequisites:** Ensure ZK dependencies are installed:
```bash
npm install snarkjs circomlibjs
```

```typescript
import { generateBlinding, buildMerkleTree, generateMerkleProof } from 'w3pk'

const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  zkProofs: {
    enabledProofs: ['membership', 'threshold', 'range']
  }
})

try {
  // Membership Proof - Prove you're in a set
  const users = ['0x111...', '0x222...', '0x333...']
  const myIndex = 1
  const proof = await w3pk.proveVerifiedMembership(users, myIndex)
  // ✅ Proved membership without revealing which user!

  // Threshold Proof - Prove balance > $1000
  const balance = 5000n
  const threshold = 1000n
  const proof2 = await w3pk.proveBalanceThreshold(balance, threshold)
  // ✅ Proved balance > $1000 without revealing $5000!

  // Range Proof - Prove age 18-65
  const age = 25n
  const proof3 = await w3pk.proveAgeRange(age, 18n, 65n)
  // ✅ Proved age in range without revealing 25!

} catch (error) {
  if (error.message.includes('snarkjs') || error.message.includes('circomlibjs')) {
    console.log('ZK dependencies not installed. Run: npm install snarkjs circomlibjs')
  }
}
```

### 5. Advanced ZK Proofs

```typescript
const zk = w3pk.zk

// Build merkle tree
const { root, tree } = await buildMerkleTree(leaves)

// Generate merkle proof
const { pathIndices, pathElements } = generateMerkleProof(tree, index)

// Create membership proof
const membershipProof = await zk.proveMembership({
  value: leaves[index],
  pathIndices,
  pathElements,
  root
})

// Verify proof
const isValid = await zk.verifyMembership(membershipProof, root)

// Create commitment
const blinding = generateBlinding()
const commitment = await zk.createCommitment(value, blinding)

// Threshold proof
const thresholdProof = await zk.proveThreshold({
  value: balance,
  blinding,
  threshold: 1000n,
  commitment
})

// Verify threshold proof
const meetsThreshold = await zk.verifyThreshold(
  thresholdProof,
  commitment,
  1000n
)
```

## Development Setup

### For Contributors

```bash
# Clone repository
git clone https://github.com/w3hc/w3pk.git
cd w3pk

# Install dependencies
pnpm install

# Install ZK dependencies
pnpm add snarkjs circomlibjs

# Build
pnpm build

# Run tests
pnpm test

# Build with ZK circuits (requires circom)
npm install -g circom
pnpm build:zk
```

### Compiling ZK Circuits

If you want to generate actual ZK proofs (not just test the setup):

```bash
# Install circom (one-time)
npm install -g circom

# Install snarkjs (one-time)
npm install -g snarkjs

# Compile circuits and generate keys
pnpm build:zk
```

This will:
1. Compile all Circom circuits to WASM
2. Download Powers of Tau (one-time, ~50MB)
3. Generate proving keys for each circuit
4. Export verification keys

## Project Structure

```
w3pk/
├── src/
│   ├── auth/              # WebAuthn authentication
│   ├── wallet/            # Wallet generation & encryption
│   ├── stealth/           # Stealth address module
│   ├── zk/                # Zero-knowledge proofs
│   │   ├── circuits/      # Circom circuits
│   │   └── templates/     # Compiled artifacts
│   └── core/              # SDK core
├── test/                  # Test suites
├── examples/              # Usage examples
└── scripts/               # Build scripts
```

## Environment Variables

None required! w3pk works out of the box.

## Browser Support

- ✅ Chrome/Edge 67+
- ✅ Firefox 60+
- ✅ Safari 13+
- ✅ Opera 54+

Requires:
- WebAuthn API support
- Web Crypto API support
- IndexedDB support

## Common Issues

### "indexedDB is not defined"
This is expected in Node.js tests. IndexedDB only works in browsers. For testing in Node, mock IndexedDB or use browser test environments.

### "ZK proofs require snarkjs. Install with: npm install snarkjs"
ZK dependencies are optional. Install only if you need ZK features:
```bash
npm install snarkjs circomlibjs
```

### "ZK merkle tree requires circomlibjs"
Some ZK utility functions require circomlibjs:
```bash
npm install circomlibjs
```

### "Circuit not registered"
You need to compile circuits first:
```bash
npm install -g circom snarkjs
pnpm build:zk
```

### Bundle too large?
Use core features only (without ZK dependencies):
- Core bundle: ~5MB
- With ZK: ~75MB
- ZK dependencies are completely optional

## Next Steps

- 📖 Read the [ZK Integration Guide](./ZK_INTEGRATION_GUIDE.md)
- 🔍 Check out [examples](./examples/)
- 🛠️ See [API documentation](./README.md)
- 🌐 Visit [Vitalik's privacy post](https://vitalik.eth.limo/general/2025/04/14/privacy.html)

## Support

- GitHub Issues: https://github.com/w3hc/w3pk/issues
- Documentation: https://github.com/w3hc/w3pk

## License

GPL-3.0-or-later