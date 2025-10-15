# w3pk

WebAuthn SDK for passwordless authentication, encrypted Ethereum wallets, and privacy-preserving stealth addresses.

Live demo: **https://d2u.w3hc.org/voting**

## Install

```bash
npm install w3pk
```

## Features

- **🔐 Passwordless Authentication**: WebAuthn/FIDO2 biometric authentication
- **💰 Encrypted Wallet Management**: Client-side AES-GCM-256 encrypted wallets  
- **🌱 HD Wallet Generation**: BIP39/BIP44 compliant wallet derivation
- **🥷 Stealth Addresses**: Privacy-preserving stealth address generation with unlinkable transactions
- **🛡️ Network Agnostic**: Works with any blockchain - you handle the transactions

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
  stealthAddresses?: {}            // Optional: Enable stealth address generation
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

Requires [nestjs-webauthn](https://github.com/w3hc/nestjs-webauthn):

```bash
git clone https://github.com/w3hc/nestjs-webauthn
cd nestjs-webauthn
pnpm install
pnpm start:dev
```

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
pnpm test                    # Run basic + comprehensive test suite
pnpm test:basic             # Run basic functionality tests only
pnpm test:comprehensive     # Run full 23-test comprehensive suite

# Publish to npm
pnpm prepublishOnly         # Builds before publishing
```

### Test Coverage

The SDK includes a comprehensive test suite with **23 test cases** covering:

- ✅ **Core SDK functionality** - Constructor, configuration, environment detection
- ✅ **Wallet generation** - BIP39/BIP44 compliance, HD derivation, consistency
- ✅ **Encryption/decryption** - AES-GCM-256, key derivation, data roundtrips
- ✅ **Storage operations** - IndexedDB CRUD, multiple wallets, cleanup
- ✅ **Message signing** - Signature generation, address verification
- ✅ **HD wallet derivation** - Multi-index support, validation, consistency
- ✅ **Error handling** - Graceful failure scenarios
- ✅ **Integration testing** - End-to-end workflows

### Architecture

```
w3pk/
├── src/
│   ├── core/           # Main SDK class and configuration
│   ├── wallet/         # Wallet generation, signing, storage
│   ├── auth/           # WebAuthn authentication flows  
│   ├── stealth/        # Privacy-preserving stealth addresses
│   ├── utils/          # API client, validation utilities
│   └── types/          # TypeScript type definitions
├── test/               # Comprehensive test suite
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

GPL-3.0-or-later

<img src="https://bafkreid5xwxz4bed67bxb2wjmwsec4uhlcjviwy7pkzwoyu5oesjd3sp64.ipfs.w3s.link" alt="built-with-ethereum-w3hc" width="100"/>