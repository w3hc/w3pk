# Quick Start

A simple step-by-step guide to get started with w3pk.

Example integration in a Next.js app: [w3pk.w3hc.org](https://w3pk.w3hc.org)

## Installation

```bash
npm install w3pk ethers
```

## 1. Import

```typescript
import { createWeb3Passkey } from 'w3pk'
```

*Loads the w3pk SDK into your application.*

## 2. Instantiate

Create a new w3pk instance:

```typescript
const w3pk = createWeb3Passkey()
```

When you instantiate w3pk, the SDK initializes a connection to your browser's IndexedDB for secure local storage and sets up the WebAuthn configuration tailored to your device. 

It also prepares the session management system with a default duration of 1 hour, meaning you won't be repeatedly prompted for biometric authentication during that time. Everything happens client-side—no server connection is needed, keeping your wallet truly under your control.

## 3. Register

Register a new user (this auto-generates a wallet and stores it securely):

```typescript
const { address, username } = await w3pk.register({
  username: 'alice'
})

console.log('Registered:', username)
console.log('Address:', address)
```

Registration is where the magic happens. First, w3pk generates a fresh BIP39 mnemonic—a 12-word recovery phrase that serves as the master key to your wallet. Then your device's biometric prompt appears (Face ID, Touch ID, Windows Hello, or similar), creating a WebAuthn credential tied to your hardware. The SDK derives your Ethereum wallet from the mnemonic using the standard BIP44 path (m/44'/60'/0'/0/0), giving you a proper Ethereum address.

Here's the security layer: the mnemonic gets encrypted using AES-GCM-256 with the WebAuthn credential as the encryption key, meaning only your biometric authentication can decrypt it. The encrypted wallet is stored safely in your browser's IndexedDB. To make your experience smooth, w3pk immediately starts a session by caching the decrypted mnemonic in memory for 1 hour, so you won't need to authenticate again right away. Finally, it returns your Ethereum address and username: you're ready to go!

### 4. Sign a Message

```typescript
const message = 'Hello world!'
const signature = await w3pk.signMessage(message)

console.log('Signature:', signature)
```

When you sign a message, w3pk first checks if you have an active session. If your session is still valid (within the 1-hour window), it uses the cached mnemonic from memory, making the process seamless and instant. If your session has expired, you'll see the biometric prompt again to decrypt your wallet.

Once the mnemonic is accessible, the SDK derives the private key from it and signs your message using ECDSA (Elliptic Curve Digital Signature Algorithm), following the EIP-191 standard for Ethereum message signatures. The result is a hex signature string that proves you control the wallet without exposing your private key.

### 5. Logout

```typescript
await w3pk.logout()
console.log('Logged out')
```

Logout is all about security housekeeping. The SDK immediately clears the active session by removing the cached mnemonic from memory. But it doesn't just delete it—it overwrites the memory locations with zeros to prevent any possibility of the sensitive data being recovered. The authentication state change is triggered, notifying any listeners in your application that the user is no longer authenticated. From this point forward, any wallet operation will require fresh biometric authentication, ensuring your wallet stays protected when you're done using it.

### 6. Login

For subsequent sessions, just login:

```typescript
await w3pk.login()
console.log('Logged in')
```

Login is a beautifully streamlined process. The SDK retrieves your credential ID from IndexedDB and triggers WebAuthn authentication—this is when your biometric prompt appears. Notice there's no username or password to remember; your device recognizes you through your biometric data.

Once authenticated, w3pk retrieves your encrypted wallet from IndexedDB and uses the WebAuthn signature as the decryption key to unlock your mnemonic. A fresh session starts immediately, caching the decrypted mnemonic in memory for 1 hour (this is configurable and balances security with user experience—long enough to avoid annoying prompts, short enough to stay secure). The method returns your user info (address and username), and you're good to go. For the next hour, all wallet operations will use this cached session without bothering you with repeated biometric prompts—smooth, secure, and user-friendly.

## Complete Example

```typescript
// 1. Import
import { createWeb3Passkey } from 'w3pk'

async function main() {
  // 2. Instantiate
  const w3pk = createWeb3Passkey()

  // 3. Register
  const { address, username } = await w3pk.register({
    username: 'alice'
  })
  console.log('Registered:', username, 'with address:', address)

  // 4. Sign a message
  const signature = await w3pk.signMessage('Hello World')
  console.log('Signature:', signature)

  // 5. Logout
  await w3pk.logout()
  console.log('Logged out')

  // 6. Login (for next session)
  await w3pk.login()
  console.log('Logged in successfully')
}

main()
```

And that's it! Users can now enjoy passwordless Web3 authentication with secure, biometric-gated wallets - no passwords, no seed phrase management headaches, just simple and secure authentication.