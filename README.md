# w3pk

WebAuthn SDK for passwordless authentication, encrypted Ethereum wallets, privacy-preserving stealth addresses, and zero-knowledge proofs.

Live demo: **https://d2u.w3hc.org/voting**

## Install

```bash
npm install w3pk
```

### Optional Zero-Knowledge Proofs

ZK proofs require additional dependencies. Install only if you need ZK features:

```bash
# Install ZK dependencies (optional)
npm install snarkjs circomlibjs
```

## Features

- **🔐 Passwordless Authentication**: WebAuthn/FIDO2 biometric authentication
- **💰 Encrypted Wallet Management**: Client-side AES-GCM-256 encrypted wallets  
- **🌱 HD Wallet Generation**: BIP39/BIP44 compliant wallet derivation with multi-address support
- **🥷 Stealth Addresses**: Privacy-preserving stealth address generation with unlinkable transactions
- **🔬 Zero-Knowledge Proofs**: Privacy-preserving proofs (membership, threshold, range, ownership)
- **🛡️ Network Agnostic**: Works with any blockchain - you handle the transactions
- **⚡ React Optimized**: Streamlined for modern React applications

## Quick Start

```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org'
})

// Register new user (wallet generated automatically)
const result = await w3pk.register({ username: 'alice' })
console.log('⚠️ BACKUP THIS MNEMONIC:', result.mnemonic)
console.log('Ethereum address:', result.ethereumAddress)

// Login (usernameless)
const loginResult = await w3pk.login()
console.log('Logged in:', loginResult.user?.username)
console.log('Address:', loginResult.user?.ethereumAddress)

// Sign message (handles fresh auth automatically)
const signature = await w3pk.signMessage('Hello, Web3!')
console.log('Signature:', signature)

// Logout
w3pk.logout()
```

## API

### Configuration

```typescript
createWeb3Passkey({
  apiBaseUrl: string,              // Required: Backend URL
  timeout?: number,                // Optional: Request timeout (default: 30000ms)
  debug?: boolean,                 // Optional: Enable logs (default: false)
  onError?: (error) => void,       // Optional: Error handler
  onAuthStateChanged?: (isAuth, user?) => void,  // Optional: Auth callback
  stealthAddresses?: {},           // Optional: Enable stealth address generation
  zkProofs?: {                     // Optional: Enable zero-knowledge proofs
    enabledProofs: ['membership', 'threshold', 'range', 'ownership']
  }
})
```

### Methods

#### Wallet Management

```typescript
// Generate BIP39 wallet (12-word mnemonic)
await w3pk.generateWallet()
// Returns: { address: string, mnemonic: string }

// Check if wallet exists for current user
await w3pk.hasWallet()
// Returns: boolean

// Derive HD wallet at specific index (requires authentication)
await w3pk.deriveWallet(0)  // First address (default)
await w3pk.deriveWallet(1)  // Second address
await w3pk.deriveWallet(5)  // Sixth address
// Returns: { address: string, privateKey: string }
```

#### Authentication

```typescript
// Register new user (auto-generates wallet)
await w3pk.register({ username: string })
// Returns: { ethereumAddress: string, mnemonic?: string }

// Register with existing wallet
await w3pk.register({ 
  username: string,
  ethereumAddress: string,
  mnemonic: string 
})

// Login (usernameless)
await w3pk.login()
// Returns: { verified: boolean, user?: UserInfo }

// Logout
w3pk.logout()
```

#### Message Signing

```typescript
// Sign message (handles WebAuthn authentication internally)
await w3pk.signMessage(message: string)
// Returns: string (signature)
```

### Properties

```typescript
w3pk.isAuthenticated        // boolean - Current authentication state
w3pk.user                   // UserInfo | null - Current user data
w3pk.version                // string - SDK version
w3pk.isBrowserEnvironment   // boolean - Browser environment detection
w3pk.stealth                // StealthAddressModule | null - Stealth address module
w3pk.zk                     // ZKProofModule | null - Zero-knowledge proof module
```

### Error Handling

The SDK provides specific error types for better error handling:

```typescript
import { 
  Web3PasskeyError, 
  AuthenticationError, 
  RegistrationError,
  WalletError,
  CryptoError,
  StorageError,
  ApiError 
} from 'w3pk'

try {
  await w3pk.register({ username: 'alice' })
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.error('WebAuthn authentication failed:', error.message)
  } else if (error instanceof WalletError) {
    console.error('Wallet operation failed:', error.message)  
  } else if (error instanceof ApiError) {
    console.error('Backend API error:', error.message)
  }
}
```

### Stealth Address API

When configured with `stealthAddresses` option, the SDK provides privacy-preserving stealth address generation:

```typescript
// Generate a fresh stealth address for privacy-preserving transactions
await w3pk.stealth.generateStealthAddress()
// Returns: { stealthAddress, stealthPrivateKey, ephemeralPublicKey }

// Get stealth keys for advanced operations
await w3pk.stealth.getKeys()
// Returns: { metaAddress, viewingKey, spendingKey }

// Check if a stealth address belongs to you (from crypto utils)
import { canControlStealthAddress } from 'w3pk'
canControlStealthAddress(viewingKey, ephemeralPublicKey, targetAddress)
// Returns: boolean
```

### Utility Functions

For direct wallet operations without SDK authentication:

```typescript
import { generateBIP39Wallet, createWalletFromMnemonic, deriveWalletFromMnemonic } from 'w3pk'

// Generate new BIP39 wallet
const wallet = generateBIP39Wallet()
// Returns: { address: string, mnemonic: string }

// Create ethers wallet from mnemonic
const ethersWallet = createWalletFromMnemonic(mnemonic)
// Returns: ethers.HDNodeWallet

// Derive HD wallet at specific index
const derived = deriveWalletFromMnemonic(mnemonic, 2)
// Returns: { address: string, privateKey: string }
```

### Types

```typescript
interface UserInfo {
  id: string
  username: string
  displayName: string
  ethereumAddress: string
}

interface WalletInfo {
  address: string
  mnemonic: string
}

interface AuthResult {
  verified: boolean
  user?: UserInfo
}

interface StealthKeys {
  metaAddress: string
  viewingKey: string
  spendingKey: string
}

interface StealthAddressResult {
  stealthAddress: string
  stealthPrivateKey: string
  ephemeralPublicKey: string
}
```

## HD Wallet Example

Access multiple addresses from a single mnemonic for advanced wallet management:

```typescript
import { createWeb3Passkey } from 'w3pk'
import { ethers } from 'ethers'

// Initialize and authenticate
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org'
})
await w3pk.login()

// Generate multiple wallet addresses from the same mnemonic
const mainWallet = await w3pk.deriveWallet(0)      // Main wallet
const savingsWallet = await w3pk.deriveWallet(1)   // Savings wallet  
const tradingWallet = await w3pk.deriveWallet(2)   // Trading wallet

console.log('Main address:', mainWallet.address)
console.log('Savings address:', savingsWallet.address)
console.log('Trading address:', tradingWallet.address)

// Use private keys directly with ethers.js
const provider = new ethers.JsonRpcProvider('https://ethereum-sepolia-rpc.publicnode.com')
const mainSigner = new ethers.Wallet(mainWallet.privateKey, provider)
const savingsSigner = new ethers.Wallet(savingsWallet.privateKey, provider)

// Send transactions from different derived addresses
const tx1 = await mainSigner.sendTransaction({
  to: savingsWallet.address,
  value: ethers.parseEther('0.1')
})

const tx2 = await savingsSigner.sendTransaction({
  to: tradingWallet.address,
  value: ethers.parseEther('0.05')
})

console.log('Transfer to savings:', tx1.hash)
console.log('Transfer to trading:', tx2.hash)
```

## Stealth Address Example

```typescript
import { createWeb3Passkey } from 'w3pk'
import { ethers } from 'ethers'

// Initialize SDK with stealth addresses enabled
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  stealthAddresses: {}
})

// 1. Login with w3pk
await w3pk.login()

// 2. Generate a fresh stealth address
const stealthResult = await w3pk.stealth.generateStealthAddress()
console.log('Stealth address:', stealthResult.stealthAddress)
console.log('Private key:', stealthResult.stealthPrivateKey)
console.log('Ephemeral public key:', stealthResult.ephemeralPublicKey)

// 3. Use the private key with any blockchain library
const stealthWallet = new ethers.Wallet(stealthResult.stealthPrivateKey)

// 4. Sign transactions with any provider
const provider = new ethers.JsonRpcProvider('https://ethereum-sepolia-rpc.publicnode.com')
const connectedWallet = stealthWallet.connect(provider)

// 5. Send transactions normally - now unlinkable!
const tx = await connectedWallet.sendTransaction({
  to: '0x742d35Cc6139FE1C2f1234567890123456789014',
  value: ethers.parseEther('0.001')
})
console.log('Transaction sent from stealth address:', tx.hash)

// 6. Get stealth keys for advanced operations
const keys = await w3pk.stealth.getKeys()
console.log('Your stealth meta address:', keys.metaAddress)
console.log('Your viewing key (keep private):', keys.viewingKey)
```

### Zero-Knowledge Proofs API

**Prerequisites**: Install ZK dependencies first:
```bash
npm install snarkjs circomlibjs
```

When configured with `zkProofs` option, the SDK provides privacy-preserving zero-knowledge proof generation:

```typescript
// Initialize SDK with ZK proofs enabled
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  zkProofs: {
    enabledProofs: ['membership', 'threshold', 'range', 'ownership', 'nft']
  }
})

// Login first
await w3pk.login()

// 1. Membership Proof - Prove you're in a set without revealing identity
const members = ['user1', 'user2', 'user3']
const membershipProof = await w3pk.zk.proveMembership({
  value: 'user2',
  pathIndices: [1, 0], 
  pathElements: ['hash1', 'hash2'],
  root: 'merkle_root'
})

// 2. Threshold Proof - Prove balance > threshold without revealing balance
const thresholdProof = await w3pk.zk.proveThreshold({
  value: 5000n,
  blinding: 123456n,
  threshold: 1000n,
  commitment: 'commitment_hash'
})

// 3. Range Proof - Prove age is 18-65 without revealing exact age
const rangeProof = await w3pk.zk.proveRange({
  value: 25n,
  blinding: 789012n, 
  min: 18n,
  max: 65n,
  commitment: 'age_commitment'
})

// 4. Ownership Proof - Prove you own an address without revealing private key
const ownershipProof = await w3pk.zk.proveOwnership({
  privateKey: 'your_private_key',
  nonce: 345678n,
  address: '0x...',
  challenge: 'challenge_string'
})

// 5. NFT Ownership Proof - Prove you own an NFT from a collection
import { generateNFTOwnershipProofInputs } from 'w3pk'

const holderAddresses = [
  '0x742d35Cc6139FE1C2f1234567890123456789014',
  '0x1234567890123456789012345678901234567890',  // Your address
  '0x9876543210987654321098765432109876543210'
]
const contractAddress = '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D'  // Human Passport SBT contract

const { nftProofInput } = await generateNFTOwnershipProofInputs(
  '0x1234567890123456789012345678901234567890',  // Your address
  contractAddress,
  holderAddresses
)

const nftProof = await w3pk.zk.proveNFTOwnership(nftProofInput)

// Verify any proof
const isValid = await w3pk.zk.verify(membershipProof)
const nftIsValid = await w3pk.zk.verifyNFTOwnership(nftProof, contractAddress, nftProofInput.holdersRoot)
console.log('Proof valid:', isValid)
console.log('NFT proof valid:', nftIsValid)
```

### ZK Proof Utilities

**Note**: These functions require `snarkjs` and `circomlibjs` to be installed.

```typescript
// Create commitments for hiding values (requires circomlibjs)
const commitment = await w3pk.zk.createCommitment(value, blinding)

// Compute merkle roots for membership proofs (requires circomlibjs)  
const root = await w3pk.zk.computeMerkleRoot(leaf, pathIndices, pathElements)

// Direct utility functions
import { 
  generateBlinding, 
  buildMerkleTree, 
  generateMerkleProof,
  buildNFTHoldersMerkleTree,
  generateNFTOwnershipProofInputs,
  validateNFTOwnershipProofInputs 
} from 'w3pk'

const blinding = generateBlinding()
const { root, tree } = await buildMerkleTree(['leaf1', 'leaf2', 'leaf3'])
const { pathIndices, pathElements } = generateMerkleProof(tree, 1)

// NFT-specific utilities
const holderAddresses = ['0x...', '0x...', '0x...']
const contractAddress = '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D'
const { root: nftRoot, tree: nftTree } = await buildNFTHoldersMerkleTree(holderAddresses, contractAddress)
const { nftProofInput } = await generateNFTOwnershipProofInputs('0x...', contractAddress, holderAddresses)
```

**Note:** ZK proofs require circuit compilation:
```bash
# Compile circuits (required for proof generation)
pnpm build:zk

# Run comprehensive ZK demo (optional)
tsx examples/zk-proof-demo.ts
```

## NFT Ownership Proof Example

Prove you own an NFT from a collection without revealing which specific NFT or your exact wallet address:

```typescript
import { createWeb3Passkey, generateNFTOwnershipProofInputs } from 'w3pk'

// Initialize SDK with NFT proofs enabled
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  zkProofs: {
    enabledProofs: ['nft']
  }
})

// Login first
await w3pk.login()

// Example: Human Passport SBT contract
const HumanPassportSBTContract = '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D'
const SBTHolders = [
  '0x742d35Cc6139FE1C2f1234567890123456789014',
  '0x1234567890123456789012345678901234567890',  // Your address
  '0x9876543210987654321098765432109876543210',
  '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'
]

// 1. Generate proof inputs for your address
const yourAddress = '0x1234567890123456789012345678901234567890'
const { nftProofInput, holderLeaves } = await generateNFTOwnershipProofInputs(
  yourAddress,
  HumanPassportSBTContract,
  SBTHolders,
  1n  // Minimum balance requirement
)

// 2. Generate NFT ownership proof
const nftOwnershipProof = await w3pk.zk.proveNFTOwnership(nftProofInput)

console.log('NFT Ownership Proof Generated!')
console.log('Holder index:', nftProofInput.holderIndex)  // Your position in holder list (private)
console.log('Proof type:', nftOwnershipProof.type)      // "nft"
console.log('Public signals:', nftOwnershipProof.publicSignals)  // Only merkle root visible

// 3. Verify the proof
const isValid = await w3pk.zk.verifyNFTOwnership(
  nftOwnershipProof,
  HumanPassportSBTContract,
  nftProofInput.holdersRoot,
  1n  // Expected minimum balance
)

console.log('NFT proof is valid:', isValid)

// 4. Use case: Gated content access
if (isValid) {
  console.log('✅ Access granted to Human Passport SBT holders-only content!')
  console.log('✅ Your exact NFT and wallet address remain private')
} else {
  console.log('❌ Access denied - proof verification failed')
}

// Example: SBT (Soulbound Token) Proof
const sbtContract = '0x1234567890123456789012345678901234567890'
const sbtHolders = [
  '0xuser1...',
  '0xuser2...',
  yourAddress,  // You have this SBT
  '0xuser3...'
]

const { nftProofInput: sbtProofInput } = await generateNFTOwnershipProofInputs(
  yourAddress,
  sbtContract, 
  sbtHolders
)

const sbtProof = await w3pk.zk.proveNFTOwnership(sbtProofInput)
const sbtValid = await w3pk.zk.verifyNFTOwnership(sbtProof, sbtContract, sbtProofInput.holdersRoot)

if (sbtValid) {
  console.log('✅ SBT ownership verified - access granted to exclusive community!')
}
```

### NFT Proof Privacy Features

- **🔒 Private NFT ID**: Nobody knows which specific NFT you own from the collection
- **🔒 Private Wallet**: Your exact wallet address is not revealed
- **🔒 Private Balance**: Only proves you meet minimum balance requirement
- **✅ Public Verification**: Anyone can verify you own an NFT from the specified collection
- **⚡ Efficient Proofs**: Uses merkle trees for scalable verification (supports thousands of holders)

### Supported Use Cases

- **🎨 NFT-Gated Content**: Prove ownership for exclusive access without linking to specific wallet
- **🏅 SBT Credentials**: Verify soulbound token ownership for reputation systems  
- **🎪 Community Access**: Join exclusive groups based on NFT ownership
- **🗳️ DAO Voting**: Anonymous voting rights based on NFT collection membership
- **🎮 Gaming**: Unlock features based on NFT ownership across multiple games
- **📚 Education**: Access courses/content based on credential NFTs/SBTs

## Complete Example

```typescript
import { createWeb3Passkey } from 'w3pk'

// Initialize SDK
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  debug: true,
  onError: (error) => {
    console.error('SDK Error:', error.message)
  },
  onAuthStateChanged: (isAuth, user) => {
    console.log('Auth changed:', isAuth, user?.username)
  }
})

// 1. Register new user
try {
  const result = await w3pk.register({ username: 'alice' })
  
  // User MUST backup this mnemonic!
  if (result.mnemonic) {
    alert(`⚠️ SAVE THIS: ${result.mnemonic}`)
  }
} catch (error) {
  console.error('Registration failed:', error)
}

// 2. Login existing user
try {
  const result = await w3pk.login()
  
  if (result.verified) {
    console.log('Welcome back,', result.user?.username)
    
    // Check if wallet is available on this device
    const hasWallet = await w3pk.hasWallet()
    console.log('Wallet available:', hasWallet)
  }
} catch (error) {
  console.error('Login failed:', error)
}

// 3. Sign a message
if (w3pk.isAuthenticated) {
  try {
    // This will prompt for WebAuthn authentication
    const signature = await w3pk.signMessage('Hello, Web3!')
    console.log('Signature:', signature)
    
    // Verify on Etherscan: https://etherscan.io/verifiedSignatures
  } catch (error) {
    console.error('Signing failed:', error)
  }
}

// 4. Logout
w3pk.logout()
```

## Backend

### Using Hosted Backend (Recommended)

The easiest way to get started is to use the hosted WebAuthn backend:

```typescript
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org'
})
```

This hosted service handles WebAuthn registration and authentication flows.

### Self-Hosted Backend

For production use, you may want to self-host your WebAuthn backend. The backend should implement:

- `POST /webauthn/register/begin` - Start WebAuthn registration
- `POST /webauthn/register/complete` - Complete WebAuthn registration  
- `POST /webauthn/authenticate/usernameless/begin` - Start usernameless authentication
- `POST /webauthn/authenticate/usernameless/complete` - Complete usernameless authentication

See the [WebAuthn specification](https://w3c.github.io/webauthn/) for implementation details.

## Security

### Encryption & Storage
- ✅ **Client-side AES-GCM-256 encryption** - All sensitive data encrypted in browser
- ✅ **PBKDF2 key derivation** (100,000 iterations) from WebAuthn credentials
- ✅ **Private keys never leave device** - Zero server-side key storage
- ✅ **IndexedDB encrypted storage** - Separate encrypted storage per device
- ✅ **WebAuthn/FIDO2 authentication** - Hardware-backed biometric security

### Wallet Standards
- ✅ **BIP39 standard mnemonic** - Industry-standard 12-word recovery phrase
- ✅ **BIP44 HD derivation** - Standard path `m/44'/60'/0'/0/{index}` for Ethereum
- ✅ **Deterministic addresses** - Same mnemonic always produces same addresses
- ✅ **Multiple address support** - Derive unlimited addresses from one mnemonic

### Privacy Features
- ✅ **Stealth addresses** - Unlinkable transaction privacy (optional)
- ✅ **Zero-knowledge proofs** - Privacy-preserving stealth address generation
- ✅ **Ephemeral keys** - Fresh keys for each stealth transaction
- ✅ **Unlinkable transactions** - No on-chain connection between stealth addresses

### Security Notes & Best Practices

#### ⚠️ Critical Security Requirements
- **MUST backup mnemonic** - The 12-word phrase is shown only once during registration
- **MUST secure mnemonic** - Store it offline, never share or store digitally
- **Cannot recover without mnemonic** - Lost device + lost mnemonic = lost wallet forever

#### 🔒 Device Security
- Your wallet is protected by device biometrics (fingerprint, Face ID, Windows Hello)
- Each device stores its own encrypted copy of the wallet
- WebAuthn credentials are bound to your specific device hardware
- Fresh authentication required for sensitive operations (signing, key derivation)

#### 🌐 Network Security
- SDK works entirely client-side - no private keys sent to servers
- Backend only stores WebAuthn public key credentials (no wallet data)
- All wallet encryption/decryption happens in your browser
- Compatible with any Ethereum-compatible network

#### 💡 Operational Security Tips
- Test wallet functionality with small amounts first
- Verify signatures on Etherscan before sending large transactions
- Use different derived addresses for different purposes (privacy by design)
- Consider using stealth addresses for maximum transaction privacy

## React Integration

View live example: **https://d2u.w3hc.org/web3** 

```typescript
import { createWeb3Passkey } from 'w3pk'
import { useState, useEffect } from 'react'

function App() {
  const [w3pk, setW3pk] = useState(null)
  const [user, setUser] = useState(null)

  useEffect(() => {
    const sdk = createWeb3Passkey({
      apiBaseUrl: 'https://webauthn.w3hc.org',
      onAuthStateChanged: (isAuth, user) => {
        setUser(isAuth ? user : null)
      }
    })
    setW3pk(sdk)
  }, [])

  const handleRegister = async () => {
    const result = await w3pk.register({ username: 'alice' })
    alert(`Save this mnemonic: ${result.mnemonic}`)
  }

  const handleLogin = async () => {
    await w3pk.login()
  }

  const handleSign = async () => {
    const sig = await w3pk.signMessage('Hello!')
    console.log('Signature:', sig)
  }

  return (
    <div>
      {!user ? (
        <>
          <button onClick={handleRegister}>Register</button>
          <button onClick={handleLogin}>Login</button>
        </>
      ) : (
        <>
          <p>Welcome {user.username}!</p>
          <button onClick={handleSign}>Sign Message</button>
          <button onClick={() => w3pk.logout()}>Logout</button>
        </>
      )}
    </div>
  )
}
```

## Development

```bash
# Install dependencies
pnpm install

# Build for production
pnpm build

# Development mode with watch
pnpm dev

# Run tests
pnpm test                    # Run basic + comprehensive + ZK test suites
pnpm test:basic             # Run basic functionality tests only
pnpm test:comprehensive     # Run full 23-test comprehensive suite  
pnpm test:zk                # Run ZK proof module tests
pnpm test:nft               # Run NFT ownership proof tests (6 tests)

# ZK circuit compilation (optional)
pnpm build:zk               # Compile circom circuits for proof generation

# Publish to npm
pnpm prepublishOnly         # Builds before publishing
```

Watch [Asciinema video](https://asciinema.org/a/s9EAGyxNpBH2UZilZvEUHcGSO) (running the tests)

### Test Coverage

The SDK includes a comprehensive test suite with **37 test cases** covering:

- ✅ **Core SDK functionality** - Constructor, configuration, environment detection
- ✅ **Wallet generation** - BIP39/BIP44 compliance, HD derivation, consistency
- ✅ **Encryption/decryption** - AES-GCM-256, key derivation, data roundtrips
- ✅ **Storage operations** - IndexedDB CRUD, multiple wallets, cleanup
- ✅ **Message signing** - Signature generation, address verification
- ✅ **HD wallet derivation** - Multi-index support, validation, consistency
- ✅ **ZK proof operations** - Commitment creation, merkle trees, proof setup
- ✅ **NFT ownership proofs** - NFT merkle trees, proof generation, SBT support
- ✅ **Circuit compilation** - Circom circuit status, dependency detection
- ✅ **Error handling** - Graceful failure scenarios, mock mode fallbacks
- ✅ **Integration testing** - End-to-end workflows

### Architecture

```
w3pk/
├── src/
│   ├── core/           # Main SDK class and configuration
│   ├── wallet/         # Wallet generation, signing, storage
│   ├── auth/           # WebAuthn authentication flows  
│   ├── stealth/        # Privacy-preserving stealth addresses
│   ├── zk/             # Zero-knowledge proof module
│   │   ├── circuits/   # Circom circuit definitions (membership, threshold, range, ownership, nft)
│   │   ├── templates/  # Compiled circuit artifacts (.r1cs, .sym, .wasm)
│   │   └── wasm/       # WebAssembly circuit files
│   ├── utils/          # API client, validation utilities
│   └── types/          # TypeScript type definitions
├── test/               # Comprehensive test suite (37 test cases)
├── scripts/            # Circuit compilation and build scripts
└── dist/               # Built output (CJS + ESM + types)
```

## Browser Compatibility

Requires browsers with WebAuthn support:
- Chrome/Edge 67+
- Firefox 60+
- Safari 13+
- All modern mobile browsers

## Support

Contact [Julien Béranger](https://github.com/julienbrg):
- Element: [@julienbrg:matrix.org](https://matrix.to/#/@julienbrg:matrix.org)
- Farcaster: [julien-](https://warpcast.com/julien-)
- Telegram: [@julienbrg](https://t.me/julienbrg)
- Twitter: [@julienbrg](https://twitter.com/julienbrg)

## License

GPL-3.0

<img src="https://bafkreid5xwxz4bed67bxb2wjmwsec4uhlcjviwy7pkzwoyu5oesjd3sp64.ipfs.w3s.link" alt="built-with-ethereum-w3hc" width="100"/>