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
w3pk.isAuthenticated        // boolean
w3pk.user                   // UserInfo | null
w3pk.version                // string
w3pk.isBrowserEnvironment   // boolean
w3pk.stealth                // StealthAddressModule | null
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

- ✅ Client-side AES-GCM-256 encryption
- ✅ PBKDF2 key derivation (100,000 iterations) from WebAuthn credentials
- ✅ Private keys never leave the browser
- ✅ IndexedDB encrypted storage per device
- ✅ BIP39 standard 12-word mnemonic
- ✅ BIP44 HD wallet derivation (m/44'/60'/0'/0/0)
- ⚠️ Users MUST backup their 12-word mnemonic

### Security Notes

- Your wallet is protected by device biometrics (fingerprint, Face ID, etc.)
- If you lose your device or passkey, your wallet **cannot be recovered** without the mnemonic
- The mnemonic is only shown once during registration
- Each device stores its own encrypted copy of the wallet

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

# Build
pnpm build

# Watch mode
pnpm dev

# Test (Node.js environment - wallet generation)
pnpm test
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