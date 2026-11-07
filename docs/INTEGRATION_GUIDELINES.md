# Integration Guidelines

This guide covers essential best practices for integrating w3pk into your application.

## Table of Contents

- [Public API vs Internal Implementation](#public-api-vs-internal-implementation)
- [Wallet Derivation Strategy](#wallet-derivation-strategy)
- [Sending Transactions](#sending-transactions)
- [EIP-1193 Provider](#eip-1193-provider)
- [Registration Flow](#registration-flow)
- [User Verification](#user-verification)
- [Backup & Recovery](#backup--recovery)
- [Security Considerations](#security-considerations)

---

## Public API vs Internal Implementation

### Always Use the SDK Methods

w3pk provides a clean public API through the `Web3Passkey` class. **Always use these SDK methods** in your application:

```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey()
await w3pk.login()

// ✅ Use these SDK methods
await w3pk.signMessage('Hello World')
await w3pk.signAuthorization({ contractAddress: '0x...', chainId: 1 })
await w3pk.deriveWallet()
await w3pk.getAddress()
```

### Don't Import Internal Classes

Internal implementation classes like `SessionManager`, `LocalStorageWalletStorage`, etc. are **not part of the public API** and may change without notice:

```typescript
// ❌ Don't do this - internal APIs
import { SessionManager } from 'w3pk/core/session'
import { LocalStorageWalletStorage } from 'w3pk/wallet/storage'

// ✅ Do this instead - public SDK API
import { createWeb3Passkey } from 'w3pk'
const w3pk = createWeb3Passkey()
```

### Why This Matters

The SDK methods (e.g. `w3pk.signAuthorization()`) handle:
- Session management automatically
- Authentication prompts when needed
- Support for derived/stealth addresses
- Signature verification before returning
- Error handling and callbacks

**Example:**

```typescript
const w3pk = createWeb3Passkey()
await w3pk.login()

// ✅ Correct - uses SDK method with session management
const auth = await w3pk.signAuthorization({
  contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
  chainId: 1,
  nonce: 0n
})

// ✅ Works with other modes and tags too (prompts for the passkey each time)
const auth2 = await w3pk.signAuthorization({
  contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
  chainId: 1
}, { mode: 'YOLO', tag: 'GAMING' })
```

### Public API Surface

**Core Methods:**
- `register()` - Create new wallet
- `login()` - Authenticate with passkey
- `logout()` - Clear session
- `deriveWallet()` - Get origin-specific wallet
- `getAddress()` - Get address for mode/tag

**Signing Methods:**
- `signMessage()` - Sign with EIP-191, SIWE, EIP-712, or rawHash; in PRIMARY mode, as the P-256 smart account (EIP-1271)
- `signAuthorization()` - Sign EIP-7702 authorization

**Backup & Recovery:**
- `createBackupFile()` - Create encrypted backup
- `confirmRecoveryPhraseBackup()` - Record that the user wrote down the recovery phrase
- `restoreFromBackupFile()` - Restore from backup
- `setupSocialRecovery()` - Split backup among guardians
- `recoverFromGuardians()` - Recover from guardian shares

**Utility Methods:**
- `listExistingCredentials()` - List all wallets on device
- `getBackupStatus()` - Check backup coverage
- `hasActiveSession()` - Check session status

**Complete list:** See [API Reference](./API_REFERENCE.md)

---

## Wallet Derivation Strategy

### Default: Use STANDARD Mode

**Best Practice:** For most applications, use the default STANDARD mode wallet derivation.

```typescript
// ✅ Recommended for most use cases
const wallet = await w3pk.deriveWallet()
// Returns: { address, path, origin, mode: 'STANDARD', tag: 'MAIN' }
// No private key exposed
// Persistent sessions allowed
```

**Why STANDARD mode?**
- **Security:** Private keys are never exposed to your application
- **User Control:** Users retain full custody of their wallet
- **Signing:** You can still sign messages and transactions via `w3pk.signMessage()`
- **Trust:** Users don't need to trust your application with key material
- **Convenience:** Supports persistent sessions for "Remember Me" functionality

### STRICT Mode: Maximum Security

**Use STRICT mode for high-security applications that need extra protection.**

```typescript
// ✅ For banking, high-value DeFi, or sensitive operations
const strictWallet = await w3pk.deriveWallet('STRICT')
// Returns: { address, path, origin, mode: 'STRICT', tag: 'MAIN' }
// No private key exposed
// Requires biometric/PIN authentication every time (no persistent sessions)
```

**When to use STRICT mode:**
- Banking and financial applications
- High-value DeFi protocols
- Enterprise/corporate wallets
- Compliance-focused applications
- Applications handling sensitive assets

### YOLO Mode: When You Need Private Keys

**Use YOLO mode ONLY when your application requires direct access to private keys.**

```typescript
// ⚠️ Use only when necessary (non-financial apps, games, etc.)
const yoloWallet = await w3pk.deriveWallet('YOLO')
// Returns: { address, privateKey, path, origin, mode: 'YOLO', tag: 'MAIN' }
// Private key exposed
// Persistent sessions allowed

// With custom tag for specific features
const gamingWallet = await w3pk.deriveWallet('YOLO', 'GAMING')
```

**Valid Use Cases:**
- Gaming applications (low-value in-game assets)
- Social applications (non-financial operations)
- Throwaway wallets for testing/development
- Apps where users explicitly want your app to manage keys

**Important Security Implications:**

When you use YOLO mode, **you control the user's private key** for that specific derived wallet. This means:

1. **Custody Risk:** Your application has full access to the private key
2. **User Trust:** Users must trust your application not to misuse their keys
3. **Liability:** Your application is responsible for securing these keys
4. **Regulatory:** May have compliance implications depending on jurisdiction

```typescript
// Different modes create different addresses
const standard = await w3pk.deriveWallet()                    // STANDARD - no private key
const strict = await w3pk.deriveWallet('STRICT')              // STRICT - no private key, no sessions
const yolo = await w3pk.deriveWallet('YOLO')                  // YOLO - has private key
const gaming = await w3pk.deriveWallet('YOLO', 'GAMING')      // YOLO + custom tag

console.log(standard.address !== strict.address)    // true (different modes)
console.log(standard.address !== yolo.address)      // true (different modes)
console.log(yolo.address !== gaming.address)        // true (different tags)
```

**Decision Matrix:**

| Use Case | Recommended Mode |
|----------|------------------|
| Financial transactions | STANDARD mode |
| DeFi applications | STANDARD mode |
| NFT purchases | STANDARD mode |
| Banking/high-value | STRICT mode |
| Enterprise wallets | STRICT mode |
| Gaming (low value) | YOLO mode |
| Social features | YOLO mode |
| Testing/development | YOLO mode |

---

## Signing Methods

w3pk supports multiple signing methods for different use cases. Choose the appropriate method based on your application's requirements.

### EIP-191 (Default): Standard Message Signing

```typescript
// Standard Ethereum signed message
const result = await w3pk.signMessage('Hello World')
// Uses EIP-191 prefix: "\x19Ethereum Signed Message:\n<length>"
```

**Use for:**
- General message signing
- Wallet authentication
- Proof of ownership
- Simple signatures

### SIWE: Sign-In with Ethereum (EIP-4361)

```typescript
import { createSiweMessage, generateSiweNonce } from 'w3pk'

// Create properly formatted SIWE message
const message = createSiweMessage({
  domain: 'app.example.com',
  address: await w3pk.getAddress(),
  uri: 'https://app.example.com/login',
  version: '1',
  chainId: 1,
  nonce: generateSiweNonce(),
  issuedAt: new Date().toISOString(),
  statement: 'Sign in to Example App'
})

// Sign with SIWE method
const result = await w3pk.signMessage(message, {
  signingMethod: 'SIWE'
})
```

SIWE works in every mode. In PRIMARY mode the signature comes from the smart account, so verify it with viem rather than `verifySiweSignature()`, as shown below. Get the address with the same mode and tag you sign with. In production, have the server issue the nonce and tie it to the address, as EIP-4361 recommends; see [examples/siwe-login.ts](../examples/siwe-login.ts).

**Verifying on a backend:** PRIMARY signatures come from a contract, so `ethers.verifyMessage()` and `verifySiweSignature()` can't recover them. viem's [`verifyMessage`](https://viem.sh/docs/actions/public/verifyMessage) and [`verifyTypedData`](https://viem.sh/docs/actions/public/verifyTypedData) on a public client verify EOA, ERC-1271 and ERC-6492 signatures alike, so one call covers every mode:

```typescript
import { createPublicClient, http } from 'viem'
import { mainnet } from 'viem/chains'

const client = createPublicClient({ chain: mainnet, transport: http() })

const valid = await client.verifyMessage({ address, message, signature })
const validTyped = await client.verifyTypedData({ address, domain, types, primaryType, message, signature })
```

Use a client for the chain the message was signed for: the signature doesn't verify on another chain.

**Use for:**
- Web3 authentication flows
- App login
- Decentralized identity
- Session management

### EIP-712: Structured Typed Data

```typescript
// Define EIP-712 structure
const domain = {
  name: 'MyDApp',
  version: '1',
  chainId: 1,
  verifyingContract: '0x...'
}

const types = {
  Transfer: [
    { name: 'to', type: 'address' },
    { name: 'amount', type: 'uint256' }
  ]
}

const message = {
  to: '0x...',
  amount: '1000000000000000000'
}

// Sign typed data
const result = await w3pk.signMessage(JSON.stringify(message), {
  signingMethod: 'EIP712',
  eip712Domain: domain,
  eip712Types: types,
  eip712PrimaryType: 'Transfer'
})
```

**Use for:**
- Token permits (gasless approvals)
- DAO voting
- NFT minting signatures
- Meta-transactions
- Any structured data requiring user approval

### rawHash: Pre-computed Hashes

```typescript
import { TypedDataEncoder } from 'ethers'

// Compute hash manually (if needed for custom schemes)
const hash = TypedDataEncoder.hash(domain, types, message)

// Sign the raw hash (always prompts for the passkey)
const result = await w3pk.signMessage(hash, {
  signingMethod: 'rawHash'
})
```

A bare hash could be an EIP-7702 authorization digest, so rawHash never signs from the session cache.

**Use for:**
- Safe multisig transactions
- Custom signature schemes
- Pre-computed EIP-712 hashes
- Advanced use cases

### Choosing the Right Method

| Use Case | Method | Reason |
|----------|--------|---------|
| User authentication | SIWE | Standardized Web3 login |
| General signatures | EIP-191 | Simple and universal |
| Token permits | EIP-712 | Gasless approvals |
| DAO voting | EIP-712 | Structured proposals |
| Safe multisig | rawHash | Pre-computed transaction hashes |
| NFT allowlist | EIP-712 | Structured whitelist data |
| Gasless meta-tx | EIP-712 | Relayer signatures |

---

## Sending Transactions

`sendTransaction()` broadcasts on-chain transactions using the wallet derived for the current security mode. It handles session management and STRICT-mode re-authentication automatically; it sends through the RPC endpoints you set for each chain.

### Basic Usage

```typescript
const w3pk = createWeb3Passkey({
  rpcUrls: { 1: ['https://eth.example.com'] }  // endpoints you trust, per chain
})

const result = await w3pk.sendTransaction({
  to: '0xRecipient...',
  value: 1n * 10n**18n,  // 1 ETH in wei (bigint)
  chainId: 1             // required — no implicit default
})

console.log(result.hash)   // transaction hash
console.log(result.from)   // derived sender address
console.log(result.mode)   // 'STANDARD'
```

`sendTransaction()` uses `options.rpcUrl`, then the first `rpcUrls` endpoint for the chain. With neither, it throws a `WalletError` naming `rpcUrls` before any passkey prompt. It never falls back to the public chainlist endpoints, since the RPC supplies the nonce, gas and fees.

### Using with ethers.js

If you want to **wait for confirmation** or read a receipt after sending through w3pk:

```typescript
import { JsonRpcProvider } from 'ethers'

// 1. Send via w3pk (handles auth + key derivation)
const result = await w3pk.sendTransaction({
  to: '0xRecipient...',
  value: 5n * 10n**17n,  // 0.5 ETH
  chainId: 1
})

// 2. Wait for confirmation using ethers
const endpoints = await w3pk.getEndpoints(1)
const provider = new JsonRpcProvider(endpoints[0])
const receipt = await provider.waitForTransaction(result.hash)
console.log('Confirmed in block:', receipt?.blockNumber)
```

For **contract calls** with ethers (recommended pattern — keep key derivation in w3pk, use ethers only for ABI encoding):

```typescript
import { Interface } from 'ethers'

// Encode the calldata with ethers ABI encoder
const iface = new Interface(['function transfer(address to, uint256 amount)'])
const data = iface.encodeFunctionData('transfer', [
  '0xRecipient...',
  1000n * 10n**18n   // 1000 tokens
])

// Send via w3pk — no private key exposure
const result = await w3pk.sendTransaction({
  to: '0xTokenContract...',
  data,
  chainId: 1
})
```

### Using with viem

viem's `encodeFunctionData` works the same way — use it to build calldata, then hand the transaction to w3pk:

```typescript
import { encodeFunctionData, parseEther, parseAbi } from 'viem'

// Encode calldata with viem
const data = encodeFunctionData({
  abi: parseAbi(['function transfer(address to, uint256 amount) returns (bool)']),
  functionName: 'transfer',
  args: ['0xRecipient...', parseEther('100')]
})

// Send via w3pk
const result = await w3pk.sendTransaction({
  to: '0xTokenContract...',
  data,
  chainId: 1
})
console.log('tx hash:', result.hash)
```

To **wait for a receipt** using viem's `publicClient`:

```typescript
import { createPublicClient, http } from 'viem'
import { mainnet } from 'viem/chains'

const publicClient = createPublicClient({
  chain: mainnet,
  transport: http()   // or http(rpcUrl) for a specific endpoint
})

// Send via w3pk
const { hash } = await w3pk.sendTransaction({
  to: '0x...',
  value: parseEther('0.1'),
  chainId: 1
})

// Wait for confirmation with viem
const receipt = await publicClient.waitForTransactionReceipt({ hash: hash as `0x${string}` })
console.log('Confirmed in block:', receipt.blockNumber)
```

### Choosing the Right Mode

```typescript
// STANDARD — session-based, re-authenticates only when session expires
const tx = await w3pk.sendTransaction(
  { to: '0x...', chainId: 1 },
  { mode: 'STANDARD' }
)

// STRICT — always prompts for biometric before sending (high-value transactions)
const safeTx = await w3pk.sendTransaction(
  { to: '0x...', value: parseEther('10'), chainId: 1 },
  { mode: 'STRICT' }
)

// YOLO — session-based, sends from the app-specific isolated address
const gamingTx = await w3pk.sendTransaction(
  { to: '0xGameContract...', data: '0x...', chainId: 8453 },
  { mode: 'YOLO', tag: 'GAMING' }
)
```

### PRIMARY Mode: Passkey Smart Account

In PRIMARY mode no secp256k1 key exists: the passkey's `W3pkAccount` sends an [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) UserOperation through a bundler that supports EntryPoint v0.9. Set a bundler per chain, and optionally an [ERC-7677](https://eips.ethereum.org/EIPS/eip-7677) paymaster service; without one, the account pays its own gas, so fund `await w3pk.getAddress('PRIMARY')` first. For now the account's factory is deployed only on Sepolia (11155111), so `PRIMARY` accounts work only there; the other chains will follow at the same addresses ([deploying the contracts](../contracts/README.md#deploying-to-a-network)).

```typescript
const w3pk = createWeb3Passkey({
  rpcUrls: { 11155111: ['https://sepolia.example.com'] },              // nonce, code and fees
  bundlerUrls: { 11155111: 'https://bundler.example.com/sepolia' },    // eth_sendUserOperation
  paymasterUrl: 'https://paymaster.example.com',                // optional
})

// One passkey prompt; the account deploys itself with its first transaction on the chain
const { hash, userOpHash } = await w3pk.sendTransaction(
  { to: '0xRecipient...', value: parseEther('0.01'), chainId: 11155111 },
  { mode: 'PRIMARY' }
)

// An array runs as one ERC-7579 batch: every call succeeds or none does
await w3pk.sendTransaction(
  [
    { to: token, data: approveCalldata, chainId: 11155111 },
    { to: router, data: swapCalldata, chainId: 11155111 },
  ],
  { mode: 'PRIMARY', paymasterContext: { policyId: 'my-policy' } }
)
```

- `hash` is the transaction that included the UserOperation, so `waitForTransactionReceipt({ hash })` works; `userOpHash` identifies the UserOperation at the bundler
- `sendTransaction()` waits for inclusion, up to `options.timeout` (60 s by default), and throws with the revert reason if the UserOperation reverted
- `options.bundlerUrl` and `options.paymasterUrl` override the config per call; `nonce` is ignored, since the EntryPoint sets it, and `gasLimit` only raises the bundler's `callGasLimit` estimate
- Only PRIMARY mode takes an array: STANDARD, STRICT and YOLO send one EOA transaction

### EIP-1559 Fee Control

```typescript
import { parseUnits } from 'viem'  // or ethers

const tx = await w3pk.sendTransaction({
  to: '0x...',
  chainId: 1,
  maxFeePerGas: parseUnits('30', 'gwei'),           // 30 gwei
  maxPriorityFeePerGas: parseUnits('2', 'gwei'),    // 2 gwei tip
  gasLimit: 50000n
})
```

If you omit fee fields, ethers automatically queries the network and selects appropriate values.

### Patterns to Avoid

```typescript
// ❌ Don't import ethers/viem wallets separately and sign raw transactions —
//    this bypasses w3pk's session management, mode isolation, and security model.
import { Wallet } from 'ethers'
const wallet = new Wallet(somePrivateKey)  // Never do this with w3pk keys

// ✅ Always use w3pk.sendTransaction() so auth and key derivation stay inside the SDK
const result = await w3pk.sendTransaction({ to: '0x...', chainId: 1 })
```

---

## EIP-1193 Provider

`getEIP1193Provider()` returns a standard [EIP-1193](https://eips.ethereum.org/EIPS/eip-1193) provider that wraps the SDK. Plug it directly into ethers, viem, wagmi, or RainbowKit — no extra wrappers required.

```typescript
const eip1193 = w3pk.getEIP1193Provider({ chainId: 1 })
```

### ethers v6

```typescript
import { BrowserProvider, parseEther } from 'ethers'

const provider = new BrowserProvider(w3pk.getEIP1193Provider({ chainId: 1 }))
const signer = await provider.getSigner()

// Send 1 ETH
const tx = await signer.sendTransaction({ to: '0xRecipient...', value: parseEther('1') })
console.log('hash:', tx.hash)

// Sign (EIP-191)
const sig = await signer.signMessage('Hello World')

// Sign typed data (EIP-712)
const permit = await signer.signTypedData(domain, types, value)
```

### viem

```typescript
import { createWalletClient, createPublicClient, custom, http, parseEther } from 'viem'
import { mainnet } from 'viem/chains'

const walletClient = createWalletClient({
  chain: mainnet,
  transport: custom(w3pk.getEIP1193Provider({ chainId: 1 }))
})

const [address] = await walletClient.getAddresses()

// Send ETH
const hash = await walletClient.sendTransaction({
  account: address,
  to: '0xRecipient...',
  value: parseEther('1')
})

// Sign (EIP-191)
const sig = await walletClient.signMessage({ account: address, message: 'Hello' })

// Sign typed data (EIP-712)
const permitSig = await walletClient.signTypedData({ account: address, domain, types, primaryType, message })

// Wait for receipt (use a publicClient)
const publicClient = createPublicClient({ chain: mainnet, transport: http() })
const receipt = await publicClient.waitForTransactionReceipt({ hash })
```

### wagmi

```typescript
import { injected } from 'wagmi/connectors'
import { createConfig, http } from 'wagmi'
import { mainnet } from 'wagmi/chains'

const w3pkConnector = injected({
  target() {
    return {
      id: 'w3pk',
      name: 'w3pk Passkey Wallet',
      provider: w3pk.getEIP1193Provider({ chainId: 1 })
    }
  }
})

const config = createConfig({
  chains: [mainnet],
  connectors: [w3pkConnector],
  transports: { [mainnet.id]: http() }
})
```

### Chain switching

The provider maintains its own `chainId` state. Call `wallet_switchEthereumChain` and listen for `chainChanged`:

```typescript
const provider = w3pk.getEIP1193Provider({ chainId: 1 })

provider.on('chainChanged', (chainId) => {
  console.log('Chain switched to:', parseInt(chainId, 16))
})

// Switch to Optimism
await provider.request({
  method: 'wallet_switchEthereumChain',
  params: [{ chainId: '0xa' }]
})
```

### PRIMARY mode

`getEIP1193Provider({ mode: 'PRIMARY' })` serves the passkey's P-256 smart account: transactions go through the bundler as ERC-4337 UserOperations, and signatures verify through EIP-1271.

```typescript
const w3pk = createWeb3Passkey({
  rpcUrls: { 11155111: ['https://sepolia.example.com'] },
  bundlerUrls: { 11155111: 'https://bundler.example.com/sepolia' },
})
const provider = w3pk.getEIP1193Provider({ mode: 'PRIMARY', chainId: 11155111 })
// or per provider: getEIP1193Provider({ mode: 'PRIMARY', chainId: 11155111, bundlerUrl: '...' })
```

| Method | STANDARD, STRICT, YOLO | PRIMARY |
|--------|------------------------|---------|
| `eth_accounts`, `eth_requestAccounts` | EOA address | Smart account address |
| `eth_sendTransaction` | EOA transaction | UserOperation; `nonce` ignored, `gas` raises `callGasLimit` |
| `personal_sign`, `eth_signTypedData_v4` | ECDSA signature | ERC-7739 signature for the active chain |
| `eth_sign` | ECDSA signature | Rejects with code `4200` |
| `eth_signTransaction` | Unsupported | Unsupported |

Verify `PRIMARY` signatures with viem's `verifyMessage` or `verifyTypedData` on a public client, which handle EIP-1271 and ERC-6492. Read receipts through a public client too: the provider only answers the methods above.

### Patterns to avoid

```typescript
// ❌ Don't re-use the same provider instance for different chains.
//    Each getEIP1193Provider() call returns an independent instance.
const provider = w3pk.getEIP1193Provider({ chainId: 1 })

// ✅ Create separate providers for different chains/contexts
const mainnetProvider  = w3pk.getEIP1193Provider({ chainId: 1 })
const optimismProvider = w3pk.getEIP1193Provider({ chainId: 10, rpcUrl: 'https://mainnet.optimism.io' })
```

---

## Registration Flow

### Check for Existing Wallet First

**Critical:** Before registering a new wallet, always check if one exists on the device.

#### Available Method

**`listExistingCredentials(): Promise<Array<{username, ethereumAddress, createdAt, lastUsed}>>`**
- Returns full list of wallets with metadata
- `.length > 0` checks whether a wallet exists on the device
- `.length` gives the count for warning messages

```typescript
// ✅ Correct registration flow
async function handleUserOnboarding() {
  try {
    // Check if user already has a wallet on this device
    const wallets = await w3pk.listExistingCredentials()

    if (wallets.length > 0) {
      // User already has a wallet - use login instead
      console.log('Found existing wallet, logging in...')
      await w3pk.login()
      return
    }

    // No existing wallet - proceed with registration
    const { address, username } = await w3pk.register({
      username: 'user@example.com'
    })

    console.log('New wallet created:', address)

    // Prompt for backup immediately after registration
    promptUserForBackup()

  } catch (error) {
    console.error('Onboarding failed:', error)
  }
}
```

**Why This Matters:**

1. **Apple Platform Limitation:** iOS/macOS have a unique Relying Party ID (RP ID) per domain
   - Creating multiple passkeys on the same device can cause conflicts
   - Better UX to have one wallet per device, synced via iCloud/Google

2. **User Experience:**
   - Prevents confusion from multiple wallets
   - Leverages platform passkey sync (iCloud Keychain, Google Password Manager)
   - Simplifies backup and recovery

3. **Security:**
   - Reduces attack surface (fewer credentials to manage)
   - Clearer security model for users

**Example 1: Simple Flow (Auto-Login if Wallet Exists)**

```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey({
  sessionDuration: 2 // 2 hour sessions
})

async function onboardUser(email: string) {
  // 1. Check for existing credential
  const wallets = await w3pk.listExistingCredentials()

  if (wallets.length > 0) {
    // Show "Welcome back" UI
    await w3pk.login()
    return { isNewUser: false }
  }

  // 2. Register new user
  const { address, username } = await w3pk.register({
    username: email
  })

  // 3. Show success message
  console.log(`✅ Wallet created: ${address}`)

  // 4. Immediately prompt for backup
  await promptBackupOptions()

  return { isNewUser: true, address }
}
```

**Example 2: Advanced Flow with Warning (Allows Multiple Wallets)**

For applications that want to support multiple wallets but warn users:

```typescript
async function onboardUserWithWarning(email: string) {
  // 1. Check for existing credentials
  const existingWallets = await w3pk.listExistingCredentials()
  const count = existingWallets.length

  if (count > 0) {
    // 2. Show warning dialog to user
    const userChoice = await showWarningDialog({
      title: 'Wallet Already Exists',
      message: `You have ${count} wallet(s) on this device:

${existingWallets.map((w, i) => `${i + 1}. ${w.username} (${w.ethereumAddress.slice(0, 10)}...)`).join('\n')}

⚠️ Creating a NEW wallet will generate a DIFFERENT address.
Funds sent to different addresses won't appear in the same wallet.

What would you like to do?`,
      options: [
        { label: 'Login to Existing Wallet', value: 'login' },
        { label: 'Create New Wallet', value: 'create', warning: true },
        { label: 'Cancel', value: 'cancel' }
      ]
    })

    if (userChoice === 'login') {
      // Let user select which wallet to login to
      await w3pk.login()
      return { isNewUser: false }
    } else if (userChoice === 'cancel') {
      throw new Error('User cancelled registration')
    }
    // else: userChoice === 'create', continue with registration
  }

  // 3. Proceed with registration (user explicitly confirmed or no existing wallet)
  const { address, username } = await w3pk.register({
    username: email
  })

  console.log(`✅ New wallet created: ${address}`)
  await promptBackupOptions()

  return { isNewUser: true, address }
}

async function promptBackupOptions() {
  // Show modal/screen with backup options
  const userChoice = await showBackupModal()

  if (userChoice === 'download') {
    const { blob, filename } = await w3pk.createBackupFile('User-Chosen-Backup-1!')
    downloadFile(blob, filename)
  } else if (userChoice === 'social-recovery') {
    await setupSocialRecoveryFlow()
  }
}
```

---

## User Verification

Registration accepts any authenticator: a built-in one (Touch ID, Windows Hello, Android), a phone through a QR code, a USB or NFC security key, or a password manager. Computers without a built-in authenticator, such as older Windows and Linux machines, can register through a phone or a security key.

By default every prompt asks for a biometric or PIN. To let authenticators that can skip the check sign in with one click, set `userVerification: 'preferred'`:

```typescript
const w3pk = createWeb3Passkey({
  userVerification: 'preferred'
})
```

The authenticator decides whether to prompt. Built-in authenticators usually still ask; security keys without a PIN and unlocked password managers usually don't.

What changes with `'preferred'`:

- `register()` and `login()` ask for `'preferred'`; PRIMARY `signMessage()` still requires verification, since the account checks it
- `derivePrfSecret()` and PRF device sync still require verification, so their secrets don't change
- A login that isn't user-verified gets an in-memory session only: no persistent session is stored or restored from it

Don't promise users a fingerprint check in your copy when you opt in: "biometric or PIN, when your device asks for it" stays accurate.

---

## Backup & Recovery

### Allow Users Multiple Backup Options

**Critical:** Users should set up at least one backup method immediately after registration. Browser storage can be wiped (eviction, Safari's 7-day cap, clearing site data), and a wallet without a backup is then lost for good.

`evictionRisk` tells you whether this browser is likely to wipe the wallet: it is `true` on WebKit (every iOS browser, Safari and other WebKit browsers on desktop) in a tab whose storage is not persisted, and `false` in a home-screen app, once storage is persisted, and on Chromium and Firefox. Use it to choose how hard to push:

- `!hasBackup && evictionRisk`: block the app until the user backs up
- `!hasBackup` otherwise: show a dismissible banner
- On iOS, also suggest "Add to Home Screen": home-screen apps are exempt from Safari's 7-day cap

```typescript
// ✅ Ask for a backup right after registration
const { hasBackup, evictionRisk } = await w3pk.register({ username })

if (!hasBackup) {
  // Blocking where the browser may wipe the wallet, dismissible otherwise
  // "Back up now": a backup file, or the recovery phrase written down
  const choice = await showBackupNowPrompt({ blocking: evictionRisk })

  if (choice === 'file') {
    const { blob, filename } = await w3pk.createBackupFile(password)
    downloadFile(blob, filename)
  } else if (choice === 'phrase') {
    await showRecoveryPhrase()
    await w3pk.confirmRecoveryPhraseBackup()
  }
}

// ✅ Keep warning while no backup exists
async function checkBackup() {
  const status = await w3pk.getBackupStatus()

  if (!status.hasBackup && status.evictionRisk) {
    showBackupGate() // blocking; on iOS, suggest "Add to Home Screen"
  } else if (!status.hasBackup) {
    showBackupWarning() // the score is capped at 20 ('vulnerable')
  }

  console.log('Security Score:', status.securityScore.total)
  console.log('Backup methods:', status.methods) // 'file' | 'qr' | 'phrase'
  console.log('Last backup:', status.lastBackupAt)
}
```

### Three-Layer Backup Strategy

Encourage users to enable multiple backup methods:

#### 1. Passkey Auto-Sync (Automatic)

```typescript
// Already enabled by default via platform
// - iCloud Keychain (Apple devices)
// - Google Password Manager (Android/Chrome)
// - Microsoft Account (Windows/Edge)

const status = await w3pk.getBackupStatus()
if (status.passkeySync.enabled) {
  console.log('✅ Passkey synced to cloud')
}
```

#### 2. Encrypted Backups (Manual)

```typescript
import { isStrongPassword } from 'w3pk'

async function createEncryptedBackup() {
  // Get password from user
  const password = await promptUserForPassword()

  // Validate strength
  if (!isStrongPassword(password)) {
    throw new Error('Password too weak. Need 15+ characters, not a common password')
  }

  // Create backup file and optionally generate QR code
  const { blob, filename } = await w3pk.createBackupFile(password)

  // You can display the JSON as QR code for scanning
  const backupJson = await blob.text()
  const qrCodeDataURL = await generateQRCode(backupJson)
  displayQRForPrinting(qrCodeDataURL)
}
```

#### 3. Social Recovery (Best UX)

```typescript
async function setupSocialRecovery(password: string) {
  const guardians = [
    { name: 'Alice', email: 'alice@example.com' },
    { name: 'Bob', email: 'bob@example.com' },
    { name: 'Charlie', email: 'charlie@example.com' },
    { name: 'Diana', email: 'diana@example.com' },
    { name: 'Eve', email: 'eve@example.com' }
  ]

  // Setup 3-of-5 guardians
  const { guardianShares } = await w3pk.setupSocialRecovery(
    guardians,
    3, // threshold - need 3 out of 5 to recover
    password // encrypts the backup the shares rebuild
  )

  // Generate and send guardian invites
  for (let i = 0; i < guardianShares.length; i++) {
    const share = guardianShares[i]
    const guardian = guardians[i]
    const invite = await w3pk.generateGuardianInvite(share, 'Custom message for guardian')
    await sendInviteToGuardian(guardian, invite)
  }
}
```

### Backup Reminder Strategy

```typescript
// Check backup status regularly
async function checkBackupReminder() {
  const status = await w3pk.getBackupStatus()
  const daysSinceRegistration = calculateDaysSince(registeredAt) // tracked by your app

  // Remind users who haven't set up backup
  if (!status.hasBackup) {

    if (daysSinceRegistration === 1) {
      showBackupReminder('urgent')
    } else if (daysSinceRegistration === 7) {
      showBackupReminder('critical')
    } else if (daysSinceRegistration % 30 === 0) {
      showBackupReminder('periodic')
    }
  }
}
```

### Recovery Flow

```typescript
async function recoverWallet() {
  // Let user choose recovery method
  const method = await showRecoveryOptions()

  if (method === 'encrypted-backup') {
    const file = await getBackupFile()
    const password = await getPasswordFromUser()
    const { ethereumAddress } = await w3pk.restoreFromBackupFile(file, password)
    console.log('✅ Wallet recovered:', ethereumAddress)

  } else if (method === 'social-recovery') {
    const shares = await collectGuardianShares()
    const password = await getPasswordFromUser() // if password-protected backup was used
    const { ethereumAddress } = await w3pk.recoverFromGuardians(shares, password)
    console.log('✅ Wallet recovered:', ethereumAddress)

  }
}
```

---

## Security Considerations

### Session Management

w3pk supports both **in-memory** (default) and **persistent** sessions:

```typescript
// ✅ In-memory sessions (default, cleared on page refresh)
const w3pk = createWeb3Passkey({
  sessionDuration: 1 // 1 hour (cleared on refresh)
})

// ✅ Persistent sessions ("Remember Me" functionality)
const w3pkPersistent = createWeb3Passkey({
  sessionDuration: 1,        // In-memory session duration
  persistentSession: {
    enabled: true,           // Enable persistent sessions
    duration: 168,           // 7 days (survives page refresh)
    requireReauth: true      // Prompt on page refresh (more secure)
  }
})

// ✅ Auto-restore (convenience mode)
const w3pkAutoRestore = createWeb3Passkey({
  persistentSession: {
    enabled: true,
    duration: 30 * 24,       // 30 days
    requireReauth: false     // Silent restore (no prompt)
  }
})

// For high-security apps, require auth for sensitive operations
async function sendHighValueTransaction(amount: number) {
  const requireAuth = amount > 1000 // Force auth for >$1000

  const signature = await w3pk.signMessage(
    `Transfer ${amount} USDC`,
    { requireAuth }
  )

  // Submit transaction...
}

// Or use STRICT mode to disable persistent sessions entirely
const strictWallet = await w3pk.deriveWallet('STRICT')
// STRICT mode ALWAYS requires fresh authentication (no persistent sessions)
```

**Persistent Session Security:**
- STANDARD / YOLO: persistent sessions allowed. STRICT: ❌ NEVER allowed.
- Time-limited expiration; origin-isolated via localStorage.
- ⚠️ The at-rest key is derived from **public** credential metadata in the same browser profile, not an authenticator secret — a persistent session is **decryptable by anyone who can read this origin's storage**, for the whole duration it's enabled. "Remember Me" is a UX-for-security trade-off that widens the exposure window; it does not add a new trust dependency beyond the origin-code integrity you already rely on. Keep the duration short for higher-value wallets and don't enable on shared devices.
- Decide this deliberately against your threat model: **[SECURITY.md → At-Rest Encryption](./SECURITY.md#at-rest-encryption-what-it-protects-and-what-it-doesnt)**.

### Build Verification

```typescript
// ✅ Verify package integrity on app initialization
import { verifyBuildHash } from 'w3pk'

const TRUSTED_HASH = 'bafybeicce26ztznqcdn6n6j6hhnoye37nb7nt7gtubelwk2ku4txbp7acy'

async function initializeApp() {
  const isValid = await verifyBuildHash(TRUSTED_HASH)

  if (!isValid) {
    throw new Error('w3pk package integrity check failed!')
  }

  // Continue with app initialization
}
```

### Origin Isolation

w3pk automatically provides origin isolation:

- Different domains derive different wallets
- `app.example.com` gets different addresses than `gaming.example.com`
- Prevents cross-origin wallet access

```typescript
// On app.example.com
const wallet1 = await w3pk.deriveWallet()
// address: 0xaaa...

// On gaming.example.com
const wallet2 = await w3pk.deriveWallet()
// address: 0xbbb... (different!)
```

### Never Expose Master Mnemonic

```typescript
// ❌ No method returns the master mnemonic
console.log('exportMnemonic' in w3pk) // false

// ✅ Use derived wallets instead
const wallet = await w3pk.deriveWallet('STANDARD', 'GAMING') // Safe, tagged wallet
```

---

## Complete Integration Example

```typescript
import { createWeb3Passkey, isStrongPassword } from 'w3pk'

class WalletManager {
  private w3pk = createWeb3Passkey({
    sessionDuration: 2,
    stealthAddresses: {} // Optional stealth support
  })

  async initialize() {
    // Verify package integrity
    const TRUSTED_HASH = 'bafybeicce26ztznqcdn6n6j6hhnoye37nb7nt7gtubelwk2ku4txbp7acy'
    const isValid = await verifyBuildHash(TRUSTED_HASH)
    if (!isValid) throw new Error('Package integrity check failed')
  }

  async onboard(username: string) {
    // Check for existing wallet
    const wallets = await this.w3pk.listExistingCredentials()

    if (wallets.length > 0) {
      await this.w3pk.login()
      return { isNewUser: false }
    }

    // Register new wallet
    const { address } = await this.w3pk.register({ username })

    // Immediate backup prompt
    await this.promptBackup()

    return { isNewUser: true, address }
  }

  async promptBackup() {
    const status = await this.w3pk.getBackupStatus()

    if (status.securityScore.total <= 40) {
      // Show backup modal to user
      const choice = await this.showBackupOptions()

      if (choice === 'encrypted') {
        const password = await this.getStrongPassword()
        const { blob, filename } = await this.w3pk.createBackupFile(password)
        this.downloadBackup(blob, filename)
      } else if (choice === 'social') {
        await this.setupSocialRecovery()
      }
    }
  }

  async getWallet() {
    // ✅ Use STANDARD mode by default (no private key exposure)
    return await this.w3pk.deriveWallet()
  }

  async signTransaction(message: string, amount?: number) {
    // Force auth for high-value transactions
    const requireAuth = amount && amount > 1000

    // Sign with STANDARD mode by default
    const result = await this.w3pk.signMessage(message, { requireAuth })
    return result.signature
  }

  private async getStrongPassword(): Promise<string> {
    let password = await this.promptUserForPassword()
    while (!isStrongPassword(password)) {
      password = await this.promptUserForPassword(
        'Password too weak. Need 15+ characters, not a common password'
      )
    }
    return password
  }
}

// Usage
const wallet = new WalletManager()
await wallet.initialize()
await wallet.onboard('user@example.com')
```

---

## Checklist

Use this checklist to ensure proper integration:

- [ ] Check for existing credentials before registration using `listExistingCredentials()`
- [ ] Consider showing warning with `listExistingCredentials()` if allowing multiple wallets
- [ ] Use STANDARD mode by default (no private key exposure)
- [ ] Only use YOLO mode when you need private keys (and understand the implications)
- [ ] Use STRICT mode for high-security or compliance-focused applications
- [ ] Prompt users to set up backup immediately after registration
- [ ] Verify package integrity on app initialization
- [ ] Configure appropriate session duration for your use case
- [ ] Require fresh authentication for high-value operations
- [ ] Show backup reminders to users without sufficient backup coverage
- [ ] Test recovery flows (encrypted backup, social recovery)
- [ ] Review [Security Architecture](./SECURITY.md) documentation

---

## Further Reading

- [Quick Start Guide](./QUICK_START.md)
- [API Reference](./API_REFERENCE.md)
- [Security Architecture](./SECURITY.md)
- [Recovery & Backup System](./RECOVERY.md)
- [Build Verification](./BUILD_VERIFICATION.md)
