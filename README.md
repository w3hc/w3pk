# w3pk

WebAuthn SDK for passwordless authentication with client-side encrypted Ethereum wallets.

## Install

```bash
npm install w3pk
```

## Quick Start

```typescript
import { createWeb3Passkey } from 'w3pk'
import { startRegistration, startAuthentication } from '@simplewebauthn/browser'

const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org'
})

// Generate wallet
const wallet = await w3pk.generateWallet()
console.log('Backup this mnemonic:', wallet.mnemonic)

// Register
const beginRes = await fetch('https://webauthn.w3hc.org/webauthn/register/begin', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'alice', ethereumAddress: wallet.address })
})
const { data } = await beginRes.json()
const credential = await startRegistration(data.options)

await w3pk.register({
  username: 'alice',
  ethereumAddress: wallet.address,
  mnemonic: wallet.mnemonic,
  credentialId: credential.id,
  challenge: data.options.challenge
})

// Login
const result = await w3pk.login()
console.log('Logged in:', result.user?.username)

// Sign message
const authBeginRes = await fetch('https://webauthn.w3hc.org/webauthn/authenticate/usernameless/begin', {
  method: 'POST'
})
const authData = await authBeginRes.json()
const authCredential = await startAuthentication(authData.data.options)

const signature = await w3pk.signMessage(
  'Hello, Web3!',
  authCredential.id,
  authData.data.options.challenge
)
```

## API

### Configuration

```typescript
createWeb3Passkey({
  apiBaseUrl: string,              // Required: Backend URL
  timeout?: number,                // Optional: Request timeout (default: 30000ms)
  debug?: boolean,                 // Optional: Enable logs (default: false)
  onError?: (error) => void,       // Optional: Error handler
  onAuthStateChanged?: (isAuth, user?) => void  // Optional: Auth callback
})
```

### Methods

```typescript
// Generate BIP39 wallet (12-word mnemonic)
await w3pk.generateWallet()
// Returns: { address: string, mnemonic: string }

// Register new user
await w3pk.register({
  username: string,
  ethereumAddress: string,
  mnemonic: string,
  credentialId: string,
  challenge: string
})

// Login (usernameless)
await w3pk.login()
// Returns: { verified: boolean, user?: { id, username, ethereumAddress } }

// Authenticate with address
await w3pk.authenticate(ethereumAddress: string)

// Sign message (requires fresh auth)
await w3pk.signMessage(message: string, credentialId: string, challenge: string)
// Returns: string (signature)

// Logout
w3pk.logout()

// Check wallet exists
await w3pk.hasWallet()
// Returns: boolean
```

### Properties

```typescript
w3pk.isAuthenticated        // boolean
w3pk.user                   // UserInfo | null
w3pk.version                // string
w3pk.isBrowserEnvironment   // boolean
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
- ✅ PBKDF2 key derivation from WebAuthn credentials
- ✅ Private keys never leave the browser
- ✅ IndexedDB encrypted storage per device
- ⚠️ Users MUST backup their 12-word mnemonic

## Testing

```bash
# Node.js test (wallet generation)
pnpm test

# Build
pnpm build

# Watch mode
pnpm dev
```

## Support

Contact [Julien Béranger](https://github.com/julienbrg):
- Element: [@julienbrg:matrix.org](https://matrix.to/#/@julienbrg:matrix.org)
- Farcaster: [julien-](https://warpcast.com/julien-)
- Telegram: [@julienbrg](https://t.me/julienbrg)
- Twitter: [@julienbrg](https://twitter.com/julienbrg)

<img src="https://bafkreid5xwxz4bed67bxb2wjmwsec4uhlcjviwy7pkzwoyu5oesjd3sp64.ipfs.w3s.link" alt="built-with-ethereum-w3hc" width="100"/>
