# w3pk

WebAuthn SDK for passwordless authentication with client-side encrypted Ethereum wallets.

---

## Install

```bash
npm install w3pk
# or
pnpm add w3pk
# or
yarn add w3pk
```

---

## Integration

### Basic Setup

```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org'
})
```

### Configuration Options

```typescript
const w3pk = createWeb3Passkey({
  apiBaseUrl: string,                                      // Required: Backend API URL
  timeout?: number,                                        // Optional: Request timeout (default: 30000ms)
  debug?: boolean,                                         // Optional: Enable debug logs (default: false)
  onError?: (error) => void,                              // Optional: Global error handler
  onAuthStateChanged?: (isAuth, user?) => void            // Optional: Auth state callback
})
```

### Complete Integration Example

```typescript
import { createWeb3Passkey } from 'w3pk'
import { startRegistration, startAuthentication } from '@simplewebauthn/browser'

// Initialize SDK
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  debug: true,
  onAuthStateChanged: (isAuthenticated, user) => {
    console.log('Auth state:', isAuthenticated, user?.username)
  },
  onError: (error) => {
    console.error('SDK Error:', error.message)
  }
})

// 1. Registration Flow
async function registerUser(username: string) {
  try {
    // Generate BIP39 wallet
    const wallet = await w3pk.generateWallet()
    
    // IMPORTANT: Show mnemonic to user for backup
    alert(`⚠️ BACKUP THIS MNEMONIC:\n\n${wallet.mnemonic}\n\nYou will need it to recover your wallet!`)
    
    // Get registration options from backend
    const beginResponse = await fetch('https://webauthn.w3hc.org/webauthn/register/begin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        ethereumAddress: wallet.address
      })
    })
    const { data } = await beginResponse.json()
    
    // Create WebAuthn credential (triggers biometric prompt)
    const credential = await startRegistration(data.options)
    
    // Register with w3pk SDK
    await w3pk.register({
      username,
      ethereumAddress: wallet.address,
      mnemonic: wallet.mnemonic,
      credentialId: credential.id,
      challenge: data.options.challenge
    })
    
    console.log('✅ Registration successful!')
    console.log('Address:', wallet.address)
  } catch (error) {
    console.error('Registration failed:', error)
  }
}

// 2. Login Flow (Usernameless)
async function login() {
  try {
    const result = await w3pk.authenticateUsernameless()
    
    if (result.verified && result.user) {
      console.log('✅ Logged in as:', result.user.username)
      console.log('Address:', result.user.ethereumAddress)
    }
  } catch (error) {
    console.error('Login failed:', error)
  }
}

// 3. Message Signing Flow
async function signMessage(message: string) {
  try {
    // Get fresh authentication challenge
    const beginResponse = await fetch('https://webauthn.w3hc.org/webauthn/authenticate/usernameless/begin', {
      method: 'POST'
    })
    const { data } = await beginResponse.json()
    
    // Authenticate user (triggers biometric prompt)
    const credential = await startAuthentication(data.options)
    
    // Sign message with encrypted wallet
    const signature = await w3pk.signMessage(
      message,
      credential.id,
      data.options.challenge
    )
    
    console.log('✅ Message signed!')
    console.log('Signature:', signature)
    
    return signature
  } catch (error) {
    console.error('Signing failed:', error)
  }
}

// 4. Logout
function logout() {
  w3pk.logout()
  console.log('✅ Logged out')
}

// Usage
await registerUser('alice')
await login()
await signMessage('Hello, Web3!')
logout()
```

### API Reference

#### Wallet Methods

```typescript
// Generate new BIP39 wallet (12-word mnemonic)
const wallet = await w3pk.generateWallet()
// Returns: { address: string, mnemonic: string }

// Check if wallet exists for current user (browser only)
const hasWallet = await w3pk.hasWallet()
// Returns: boolean
```

#### Authentication Methods

```typescript
// Register new user (browser only)
await w3pk.register({
  username: string,
  ethereumAddress: string,
  mnemonic: string,
  credentialId: string,
  challenge: string
})

// Login without username (browser only)
const result = await w3pk.authenticateUsernameless()
// Returns: { verified: boolean, user?: { id, username, ethereumAddress } }

// Login with specific address (browser only)
const result = await w3pk.authenticate(ethereumAddress: string)
// Returns: { verified: boolean, user?: { id, username, ethereumAddress } }

// Logout current user
w3pk.logout()
```

#### Message Signing

```typescript
// Sign message with encrypted wallet (browser only, requires fresh auth)
const signature = await w3pk.signMessage(
  message: string,
  credentialId: string,
  challenge: string
)
// Returns: string (Ethereum signature)
```

#### Properties

```typescript
w3pk.isAuthenticated        // boolean - Current auth state
w3pk.user                   // UserInfo | null - Current user info
w3pk.version                // string - SDK version
w3pk.isBrowserEnvironment   // boolean - Check if running in browser
```

### Backend Integration

This SDK requires a WebAuthn backend API. Use [nestjs-webauthn](https://github.com/w3hc/nestjs-webauthn):

```bash
git clone https://github.com/w3hc/nestjs-webauthn
cd nestjs-webauthn
pnpm install
pnpm start:dev
```

Configure your backend URL in the SDK:

```typescript
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'http://localhost:3000'  // Your backend URL
})
```

### Environment Support

| Feature | Node.js | Browser |
|---------|---------|---------|
| Wallet Generation | ✅ | ✅ |
| WebAuthn Registration | ❌ | ✅ |
| WebAuthn Authentication | ❌ | ✅ |
| Message Signing | ❌ | ✅ |
| Encrypted Storage | ❌ | ✅ |

The SDK gracefully handles non-browser environments and will show appropriate warnings.

### Security Notes

⚠️ **Critical Security Information:**

- **Mnemonics are encrypted client-side** using keys derived from WebAuthn credentials
- **Private keys never leave the browser** - all cryptographic operations happen locally
- **Users MUST backup their 12-word mnemonic** during registration
- **No mnemonic backup = no wallet recovery** - if the device is lost, the wallet is lost
- **Each device stores its own encrypted wallet** in IndexedDB
- **Message signing requires fresh WebAuthn authentication** for security

### Browser Support

- Chrome 67+ (all platforms)
- Firefox 60+ (all platforms)
- Safari 14+ (macOS, iOS)
- Edge 18+ (Windows)

WebAuthn/FIDO2 compatible authenticators required (biometrics, security keys, etc.)

---

## Contribute

### Prerequisites

```bash
pnpm install
```

### Development

```bash
# Watch mode (rebuilds on changes)
pnpm dev

# Build for production
pnpm build
```

### Testing

#### Node.js Tests (Wallet Generation)

Run the Node.js test to verify wallet generation works:

```bash
pnpm test
```

**Expected output:**
```
w3pk: Running in non-browser environment, some features disabled
SDK initialized successfully
Is authenticated: false
Current user: null
SDK version: 0.1.0
Wallet generated: 0x304d39f46FbD7464Fa799034629bD93091ACe0EA
Wallet generated:
  Address: 0x304d39f46FbD7464Fa799034629bD93091ACe0EA
  Mnemonic: tortoise barrel margin object loyal cart mechanic suffer scorpion athlete tide city
```

#### Browser Tests (Full Features)

Test all features including WebAuthn authentication and message signing:

1. **Start your backend:**
   ```bash
   cd nestjs-webauthn
   pnpm start:dev
   ```

2. **Serve the test files:**
   ```bash
   pnpm test:browser
   ```

3. **Open in browser:**
   ```
   http://localhost:3000/test/browser-test.html
   ```

4. **Test the features:**
   - Click "Generate Wallet" - Creates a new BIP39 wallet
   - Click "Register" - Creates WebAuthn credential and encrypts mnemonic
   - Click "Login (Usernameless)" - Authenticates with biometric/passkey
   - Click "Logout" - Clears authentication state

**Browser test features:**
- ✅ Real WebAuthn credential creation
- ✅ Biometric authentication prompts
- ✅ Wallet encryption/decryption
- ✅ IndexedDB storage
- ✅ Message signing with encrypted keys

### Project Structure

```
w3pk/
├── src/
│   ├── auth/              # WebAuthn authentication flows
│   │   ├── authenticate.ts
│   │   ├── register.ts
│   │   ├── types.ts
│   │   └── usernameless.ts
│   ├── core/              # SDK core
│   │   ├── config.ts
│   │   ├── errors.ts
│   │   └── sdk.ts
│   ├── wallet/            # Wallet & crypto
│   │   ├── crypto.ts      # AES-GCM encryption
│   │   ├── generate.ts    # BIP39 generation
│   │   ├── signing.ts     # Message signing
│   │   ├── storage.ts     # IndexedDB
│   │   └── types.ts
│   ├── utils/             # Utilities
│   │   ├── api.ts         # API client
│   │   └── validation.ts  # Input validation
│   ├── types/             # Shared types
│   │   └── index.ts
│   └── index.ts           # Main export
├── test/
│   ├── test.ts            # Node.js tests
│   └── browser-test.html  # Browser tests
├── dist/                  # Built files
├── package.json
├── tsconfig.json
└── tsup.config.ts
```

### Making Changes

1. **Fork the repository**
2. **Create a feature branch:**
   ```bash
   git checkout -b feature/my-feature
   ```

3. **Make your changes in `src/`**

4. **Test your changes:**
   ```bash
   pnpm build
   pnpm test
   pnpm test:browser
   ```

5. **Commit and push:**
   ```bash
   git add .
   git commit -m "feat: add my feature"
   git push origin feature/my-feature
   ```

6. **Open a Pull Request**

### Publishing

```bash
# Bump version
npm version patch|minor|major

# Build and publish
pnpm build
npm publish
```

### Code Style

- **TypeScript** with strict mode
- **ESM + CommonJS** dual package
- **Functional** where possible
- **Clear error messages** for debugging
- **JSDoc comments** for public APIs

---

## Features

- 🔐 **Passwordless Authentication** - WebAuthn/FIDO2 biometric login
- 💼 **BIP39 HD Wallets** - Standard 12-word mnemonics, BIP44 derivation (m/44'/60'/0'/0/0)
- 🔒 **Client-Side Encryption** - AES-GCM-256 with PBKDF2 key derivation
- 💾 **IndexedDB Storage** - Encrypted wallets stored locally per device
- ✍️ **Message Signing** - Ethereum message signing with encrypted keys
- 🌐 **Zero Server Trust** - Private keys never leave the client
- 🔄 **Usernameless Auth** - Streamlined authentication flow

---

## License

GPL-3.0-or-later

---

## Links

- **GitHub:** https://github.com/w3hc/w3pk
- **Backend API:** https://github.com/w3hc/nestjs-webauthn
- **Issues:** https://github.com/w3hc/w3pk/issues
- **NPM:** https://www.npmjs.com/package/w3pk

---

## Support

Reach out to [Julien Béranger](https://github.com/julienbrg):

- Element: [@julienbrg:matrix.org](https://matrix.to/#/@julienbrg:matrix.org)
- Farcaster: [julien-](https://warpcast.com/julien-)
- Telegram: [@julienbrg](https://t.me/julienbrg)
- Twitter: [@julienbrg](https://twitter.com/julienbrg)
- Discord: [julienbrg](https://discordapp.com/users/julienbrg)
- LinkedIn: [julienberanger](https://www.linkedin.com/in/julienberanger/)

<img src="https://bafkreid5xwxz4bed67bxb2wjmwsec4uhlcjviwy7pkzwoyu5oesjd3sp64.ipfs.w3s.link" alt="built-with-ethereum-w3hc" width="100"/>