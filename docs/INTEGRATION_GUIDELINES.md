# Integration Guidelines

This guide covers essential best practices for integrating w3pk into your application.

## Table of Contents

- [Public API vs Internal Implementation](#public-api-vs-internal-implementation)
- [Wallet Derivation Strategy](#wallet-derivation-strategy)
- [External Wallet Integration](#external-wallet-integration)
- [Sending Transactions](#sending-transactions)
- [EIP-1193 Provider](#eip-1193-provider)
- [Registration Flow](#registration-flow)
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

Internal implementation classes like `WalletSigner`, `SessionManager`, `IndexedDBWalletStorage`, etc. are **not part of the public API** and may change without notice:

```typescript
// ❌ Don't do this - internal APIs
import { WalletSigner } from 'w3pk/wallet/signing'
import { SessionManager } from 'w3pk/core/session'
import { IndexedDBWalletStorage } from 'w3pk/wallet/storage'

// ✅ Do this instead - public SDK API
import { createWeb3Passkey } from 'w3pk'
const w3pk = createWeb3Passkey()
```

### Why This Matters

**For `signAuthorization` specifically:**
- There are **two implementations** in the codebase:
  - `WalletSigner.signAuthorization()` - Internal low-level utility
  - `Web3Passkey.signAuthorization()` - Public SDK method
- **Always use the SDK version** (`w3pk.signAuthorization()`)
- The SDK version handles:
  - Session management automatically
  - Authentication prompts when needed
  - Support for derived/stealth addresses
  - Signature verification before returning
  - Error handling and callbacks

**Example - Correct Usage:**

```typescript
const w3pk = createWeb3Passkey()
await w3pk.login()

// ✅ Correct - uses SDK method with session management
const auth = await w3pk.signAuthorization({
  contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
  chainId: 1,
  nonce: 0n
})

// ✅ Works with derived addresses too
const derived = await w3pk.deriveWallet('YOLO', 'GAMING')
const auth2 = await w3pk.signAuthorization({
  contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
  chainId: 1,
  privateKey: derived.privateKey  // Sign from derived address
})
```

**Example - Incorrect Usage:**

```typescript
// ❌ Don't use internal WalletSigner class directly
import { WalletSigner } from 'w3pk/wallet/signing'
import { IndexedDBWalletStorage } from 'w3pk/wallet/storage'

const storage = new IndexedDBWalletStorage()
const signer = new WalletSigner(storage)

// This bypasses session management and requires manual credential handling
await signer.signAuthorization(
  ethereumAddress,
  { contractAddress: '0x...', chainId: 1 },
  credentialId,    // You have to manage this yourself
  challenge        // You have to generate this yourself
)
```

### Public API Surface

**Core Methods:**
- `register()` - Create new wallet
- `login()` - Authenticate with passkey
- `logout()` - Clear session
- `deriveWallet()` - Get origin-specific wallet
- `getAddress()` - Get address for mode/tag

**Signing Methods:**
- `signMessage()` - Sign with EIP-191, SIWE, EIP-712, or rawHash
- `signMessageWithPasskey()` - Sign with WebAuthn P-256 (PRIMARY mode)
- `signAuthorization()` - Sign EIP-7702 authorization

**Backup & Recovery:**
- `createBackupFile()` - Create encrypted backup
- `restoreFromBackupFile()` - Restore from backup
- `setupSocialRecovery()` - Split backup among guardians
- `recoverFromGuardians()` - Recover from guardian shares

**Utility Methods:**
- `hasExistingCredential()` - Check if wallet exists
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
// Returns: { address, index, origin, mode: 'STANDARD', tag: 'MAIN' }
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
// Returns: { address, index, origin, mode: 'STRICT', tag: 'MAIN' }
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
// Returns: { address, privateKey, index, origin, mode: 'YOLO', tag: 'MAIN' }
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

## External Wallet Integration

### Why Allow External Wallet Signing?

Users often have existing wallets (MetaMask, Rabby, Rainbow, etc.) that hold valuable assets (NFTs, tokens). W3PK allows users to link these external wallets using EIP-7702 delegation, enabling them to use those assets within your app **without transferring them**.

**Key Benefits:**
- **No asset transfers**: NFTs/tokens stay in user's external wallet
- **Maintained custody**: Users keep full control of their assets
- **Reversible**: Users can revoke delegation at any time
- **Better UX**: No need to move assets between wallets

### Integration Pattern

To integrate external wallet linking, you need to:
1. Setup the delegation authorization using w3pk SDK
2. Have the user sign it with their external wallet (MetaMask, Rabby, etc.)
3. Execute the delegation on-chain

### Step 1: Setup Delegation Authorization

```typescript
import { W3PK } from 'w3pk-sdk'

// Initialize w3pk SDK
const sdk = new W3PK({
  credentialName: 'MyApp',
  rpcUrl: 'https://your-rpc-url',
  walletType: 'STANDARD+MAIN'
})

// User's external wallet address (e.g., their MetaMask address)
const externalWalletAddress = '0x1234...' // Address that holds the NFT

// Setup the delegation - this creates the EIP-7702 authorization data
const authorizationData = await sdk.setupExternalWalletDelegation(externalWalletAddress)

// authorizationData contains the typed data structure to be signed
console.log(authorizationData)
// {
//   chainId: 1,
//   address: '0x1234...',
//   nonce: 0n,
//   authorizationList: [...]
// }
```

### Step 2: Connect External Wallet and Get Signature

Now you need to integrate with external wallet providers to get the user's signature. Here are examples for common providers:

#### Option A: Using ethers.js with MetaMask/injected wallet

```typescript
import { BrowserProvider } from 'ethers'

async function signWithExternalWallet(authorizationData: any) {
  // Connect to MetaMask/Rabby/any injected wallet
  if (!window.ethereum) {
    throw new Error('No wallet extension found. Please install MetaMask or Rabby.')
  }

  const provider = new BrowserProvider(window.ethereum)

  // Request account access
  await provider.send('eth_requestAccounts', [])
  const signer = await provider.getSigner()

  // Verify the address matches
  const address = await signer.getAddress()
  if (address.toLowerCase() !== externalWalletAddress.toLowerCase()) {
    throw new Error('Connected wallet address does not match the target address')
  }

  // Sign the EIP-7702 authorization
  // Note: The authorization data from setupExternalWalletDelegation is already formatted
  const signature = await signer.signTypedData(
    authorizationData.domain,
    authorizationData.types,
    authorizationData.message
  )

  return {
    ...authorizationData,
    signature
  }
}
```

#### Option B: Using wagmi (recommended for React apps)

```typescript
import { useSignTypedData, useAccount } from 'wagmi'

function ExternalWalletLinker() {
  const { address: connectedAddress } = useAccount()
  const { signTypedDataAsync } = useSignTypedData()

  async function linkExternalWallet(externalAddress: string) {
    // 1. Setup authorization with w3pk
    const authData = await sdk.setupExternalWalletDelegation(externalAddress)

    // 2. Verify connected wallet matches
    if (connectedAddress?.toLowerCase() !== externalAddress.toLowerCase()) {
      throw new Error('Please connect the wallet you want to link')
    }

    // 3. Sign with external wallet
    const signature = await signTypedDataAsync({
      domain: authData.domain,
      types: authData.types,
      primaryType: authData.primaryType,
      message: authData.message
    })

    // 4. Execute delegation
    const txHash = await sdk.executeExternalWalletDelegation({
      ...authData,
      signature
    })

    return txHash
  }

  return (
    <button onClick={() => linkExternalWallet('0x1234...')}>
      Link External Wallet
    </button>
  )
}
```

#### Option C: Using RainbowKit (best UX for multiple wallets)

```typescript
import { useWalletClient, useAccount } from 'wagmi'
import { signTypedData } from '@wagmi/core'

async function linkWithRainbowKit(externalAddress: string) {
  const { address } = useAccount()

  // Setup authorization
  const authData = await sdk.setupExternalWalletDelegation(externalAddress)

  // Verify address
  if (address?.toLowerCase() !== externalAddress.toLowerCase()) {
    throw new Error('Connected wallet does not match')
  }

  // Sign with RainbowKit's connected wallet
  const signature = await signTypedData({
    domain: authData.domain,
    types: authData.types,
    primaryType: authData.primaryType,
    message: authData.message
  })

  // Execute delegation
  return await sdk.executeExternalWalletDelegation({
    ...authData,
    signature
  })
}
```

### Step 3: Execute the Delegation

Once you have the signed authorization, execute it on-chain:

```typescript
// The executeExternalWalletDelegation method submits the signed authorization
const txHash = await sdk.executeExternalWalletDelegation(signedAuthorization)

console.log('Delegation transaction:', txHash)

// Wait for confirmation
await provider.waitForTransaction(txHash)

// Verify delegation is active
const isDelegated = await sdk.verifyExternalWalletDelegation(externalWalletAddress)
console.log('Is delegated:', isDelegated) // true
```

### Complete Example: Full Integration Flow

```typescript
import { W3PK } from 'w3pk-sdk'
import { BrowserProvider } from 'ethers'

class ExternalWalletManager {
  private sdk: W3PK

  constructor() {
    this.sdk = new W3PK({
      credentialName: 'MyApp',
      rpcUrl: 'https://mainnet.infura.io/v3/YOUR_KEY',
      walletType: 'STANDARD+MAIN'
    })
  }

  /**
   * Link an external wallet (MetaMask, Rabby, etc.) to the user's w3pk wallet
   */
  async linkExternalWallet(externalAddress: string): Promise<string> {
    try {
      // Step 1: Setup the delegation authorization
      const authData = await this.sdk.setupExternalWalletDelegation(externalAddress)

      // Step 2: Connect to external wallet
      if (!window.ethereum) {
        throw new Error('Please install MetaMask or another Web3 wallet')
      }

      const provider = new BrowserProvider(window.ethereum)
      await provider.send('eth_requestAccounts', [])
      const signer = await provider.getSigner()

      // Verify address matches
      const connectedAddress = await signer.getAddress()
      if (connectedAddress.toLowerCase() !== externalAddress.toLowerCase()) {
        throw new Error(
          `Please switch to the wallet you want to link: ${externalAddress}`
        )
      }

      // Step 3: Sign the authorization with external wallet
      const signature = await signer.signTypedData(
        authData.domain,
        authData.types,
        authData.message
      )

      // Step 4: Execute the delegation on-chain
      const txHash = await this.sdk.executeExternalWalletDelegation({
        ...authData,
        signature
      })

      console.log('✅ External wallet linked! Transaction:', txHash)
      return txHash

    } catch (error) {
      console.error('Failed to link external wallet:', error)
      throw error
    }
  }

  /**
   * Verify if an external wallet is currently delegated
   */
  async checkDelegationStatus(address: string): Promise<boolean> {
    return await this.sdk.verifyExternalWalletDelegation(address)
  }

  /**
   * Revoke delegation for an external wallet
   */
  async unlinkExternalWallet(address: string): Promise<string> {
    const txHash = await this.sdk.revokeExternalWalletDelegation(address)
    console.log('✅ Delegation revoked! Transaction:', txHash)
    return txHash
  }
}

// Usage in your app
const walletManager = new ExternalWalletManager()

// Link user's MetaMask wallet
const txHash = await walletManager.linkExternalWallet('0x742d35Cc...')

// Check if it's delegated
const isDelegated = await walletManager.checkDelegationStatus('0x742d35Cc...')

// Revoke when done
await walletManager.unlinkExternalWallet('0x742d35Cc...')
```

### UI/UX Best Practices

#### 1. Clear Communication

Explain to users what delegation means:

```typescript
function LinkWalletModal({ onLink }: { onLink: () => void }) {
  return (
    <div className="modal">
      <h2>Link Your MetaMask Wallet</h2>
      <p>
        This allows your w3pk wallet to use NFTs and tokens from your MetaMask wallet
        without transferring them.
      </p>
      <ul>
        <li>✅ Your assets stay in your MetaMask wallet</li>
        <li>✅ You maintain full control</li>
        <li>✅ You can revoke access at any time</li>
        <li>✅ No transaction fees to link</li>
      </ul>
      <button onClick={onLink}>Link Wallet</button>
    </div>
  )
}
```

#### 2. Address Verification

Show users which address they're linking:

```tsx
function AddressConfirmation({ address }: { address: string }) {
  const { address: connectedAddress } = useAccount()
  const isCorrect = connectedAddress?.toLowerCase() === address.toLowerCase()

  return (
    <div>
      <p>Linking wallet: <code>{address}</code></p>
      {!isCorrect && (
        <div className="warning">
          ⚠️ Connected wallet ({connectedAddress}) doesn't match.
          Please switch wallets in MetaMask.
        </div>
      )}
    </div>
  )
}
```

#### 3. Show Delegation Status

```typescript
function WalletStatus({ address }: { address: string }) {
  const [isDelegated, setIsDelegated] = useState(false)

  useEffect(() => {
    sdk.verifyExternalWalletDelegation(address)
      .then(setIsDelegated)
  }, [address])

  return (
    <div>
      {isDelegated ? (
        <span className="badge-success">✅ Linked</span>
      ) : (
        <span className="badge-neutral">Not Linked</span>
      )}
    </div>
  )
}
```

#### 4. Handle Signature Rejection

```typescript
try {
  const signature = await signer.signTypedData(...)
} catch (error) {
  if (error.code === 'ACTION_REJECTED') {
    // User rejected the signature
    showNotification('You cancelled the linking. Please try again when ready.')
  } else {
    // Other error
    showError('Failed to link wallet: ' + error.message)
  }
}
```

### Security Considerations

1. **Always verify addresses**: Ensure connected wallet matches the target address
2. **Explain delegation clearly**: Users should understand what they're authorizing
3. **Show active delegations**: Let users see which wallets are currently linked
4. **Easy revocation**: Make it simple to revoke delegation
5. **Chain-specific**: Delegation is per-chain; linking on mainnet doesn't affect other chains

### Testing Your Integration

```typescript
// Test with a local testnet
const sdk = new W3PK({
  rpcUrl: 'http://localhost:8545', // Local Anvil/Hardhat
  walletType: 'STANDARD+MAIN'
})

// Test flow:
// 1. Link a test wallet
const txHash = await linkExternalWallet(testAddress)

// 2. Verify delegation
const isDelegated = await sdk.verifyExternalWalletDelegation(testAddress)
console.assert(isDelegated === true)

// 3. Use the delegated wallet (transfer NFT, etc.)
// ... your app logic ...

// 4. Revoke
await sdk.revokeExternalWalletDelegation(testAddress)

// 5. Verify revocation
const isStillDelegated = await sdk.verifyExternalWalletDelegation(testAddress)
console.assert(isStillDelegated === false)
```

### Common Issues and Solutions

**Issue: "User rejected the request"**
- Solution: User cancelled the signature in their wallet. Allow them to retry.

**Issue: "Wrong address connected"**
- Solution: Check connected address matches target address before requesting signature.

**Issue: "Transaction failed"**
- Solution: Ensure the w3pk wallet has enough ETH to pay for gas.

**Issue: "Network mismatch"**
- Solution: Verify both wallets are on the same network (e.g., both on mainnet).

For more details on EIP-7702 and external wallet integration, see [EIP_7702.md](./EIP_7702.md) and [PORTABILITY.md](./PORTABILITY.md).

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

**Use for:**
- Web3 authentication flows
- dApp login
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

// Sign the raw hash
const result = await w3pk.signMessage(hash, {
  signingMethod: 'rawHash'
})
```

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

`sendTransaction()` broadcasts on-chain transactions using the wallet derived for the current security mode. It handles RPC resolution, session management, and STRICT-mode re-authentication automatically — you only need to provide the transaction details.

### Basic Usage

```typescript
const result = await w3pk.sendTransaction({
  to: '0xRecipient...',
  value: 1n * 10n**18n,  // 1 ETH in wei (bigint)
  chainId: 1             // required — no implicit default
})

console.log(result.hash)   // transaction hash
console.log(result.from)   // derived sender address
console.log(result.mode)   // 'STANDARD'
```

The RPC endpoint is resolved automatically from the built-in chainlist (2390+ networks). Pass `options.rpcUrl` to override.

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

#### Available Methods

w3pk provides three methods for checking existing credentials:

1. **`hasExistingCredential(): Promise<boolean>`**
   - Returns `true` if at least one wallet exists on the device
   - Use for simple yes/no checks

2. **`getExistingCredentialCount(): Promise<number>`**
   - Returns the number of existing wallets
   - Useful for showing counts in warning messages

3. **`listExistingCredentials(): Promise<Array<{username, ethereumAddress, createdAt, lastUsed}>>`**
   - Returns full list of wallets with metadata
   - Use for showing users which wallets they have

```typescript
// ✅ Correct registration flow
async function handleUserOnboarding() {
  try {
    // Check if user already has a wallet on this device
    const hasExisting = await w3pk.hasExistingCredential()

    if (hasExisting) {
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
  const existing = await w3pk.hasExistingCredential()

  if (existing) {
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
  const count = await w3pk.getExistingCredentialCount()

  if (count > 0) {
    // 2. List existing wallets
    const existingWallets = await w3pk.listExistingCredentials()

    // 3. Show warning dialog to user
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

  // 4. Proceed with registration (user explicitly confirmed or no existing wallet)
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

  if (userChoice === 'qr-code') {
    const { qrCodeDataURL } = await w3pk.createQRBackup()
    displayQRCode(qrCodeDataURL)
  } else if (userChoice === 'social-recovery') {
    await setupSocialRecoveryFlow()
  }
}
```

---

## Backup & Recovery

### Allow Users Multiple Backup Options

**Critical:** Users should set up at least one backup method immediately after registration.

```typescript
// ✅ Provide multiple backup options
async function setupBackups() {
  const status = await w3pk.getBackupStatus()

  console.log('Security Score:', status.securityScore.score)
  console.log('Has passkey sync:', status.securityScore.hasPasskeyBackup)
  console.log('Has encrypted backup:', status.securityScore.hasEncryptedBackup)
  console.log('Has social recovery:', status.securityScore.hasSocialRecovery)

  // Warn if security score is low
  if (status.securityScore.score < 60) {
    showBackupWarning()
  }
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
if (status.securityScore.hasPasskeyBackup) {
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
    throw new Error('Password too weak. Need 12+ chars with mixed case, numbers, symbols')
  }

  // Create QR backup
  const { qrCodeDataURL } = await w3pk.createQRBackup(password)
  displayQRForPrinting(qrCodeDataURL)
}
```

#### 3. Social Recovery (Best UX)

```typescript
async function setupSocialRecovery() {
  // Setup 3-of-5 guardians
  await w3pk.setupSocialRecovery(
    [
      { name: 'Alice', email: 'alice@example.com' },
      { name: 'Bob', email: 'bob@example.com' },
      { name: 'Charlie', phone: '+1234567890' },
      { name: 'Diana', email: 'diana@example.com' },
      { name: 'Eve', email: 'eve@example.com' }
    ],
    3 // threshold - need 3 out of 5 to recover
  )

  // Generate and send guardian invites
  const guardians = await w3pk.getGuardians()
  for (const guardian of guardians) {
    const invite = await w3pk.generateGuardianInvite(guardian.id)
    await sendInviteToGuardian(guardian, invite)
  }
}
```

### Backup Reminder Strategy

```typescript
// Check backup status regularly
async function checkBackupReminder() {
  const status = await w3pk.getBackupStatus()
  const daysSinceRegistration = calculateDaysSince(status.createdAt)

  // Remind users who haven't set up backup
  if (!status.securityScore.hasEncryptedBackup &&
      !status.securityScore.hasSocialRecovery) {

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
    await w3pk.restoreFromBackup(file, password)

  } else if (method === 'social-recovery') {
    const shares = await collectGuardianShares()
    const { mnemonic } = await w3pk.recoverFromGuardians(shares)
    console.log('✅ Wallet recovered!')

  } else if (method === 'qr-backup') {
    const qrData = await scanQRCode()
    const password = await getPasswordFromUser()
    await w3pk.restoreFromBackup(qrData, password)
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
- STANDARD mode: Persistent sessions ✅ allowed
- YOLO mode: Persistent sessions ✅ allowed
- STRICT mode: Persistent sessions ❌ NEVER allowed
- Sessions encrypted with WebAuthn-derived keys
- Requires valid credential to decrypt
- Time-limited expiration
- Origin-isolated via IndexedDB

### Build Verification

```typescript
// ✅ Verify package integrity on app initialization
import { verifyBuildHash } from 'w3pk'

const TRUSTED_HASH = 'bafybeig2xoiu2hfcjexz6cwtjcjf4u4vwxzcm66zhnqivhh6jvi7nx2qa4'

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
// ❌ This will throw an error - master mnemonic is never exposed
try {
  await w3pk.exportMnemonic()
} catch (error) {
  console.error('Cannot export master mnemonic') // Expected
}

// ✅ Use derived wallets instead
const wallet = await w3pk.deriveWallet('GAMING') // Safe, tagged wallet
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
    const TRUSTED_HASH = 'bafybeig2xoiu2hfcjexz6cwtjcjf4u4vwxzcm66zhnqivhh6jvi7nx2qa4'
    const isValid = await verifyBuildHash(TRUSTED_HASH)
    if (!isValid) throw new Error('Package integrity check failed')
  }

  async onboard(username: string) {
    // Check for existing wallet
    const hasExisting = await this.w3pk.hasExistingCredential()

    if (hasExisting) {
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

    if (status.securityScore.score < 60) {
      // Show backup modal to user
      const choice = await this.showBackupOptions()

      if (choice === 'encrypted') {
        const password = await this.getStrongPassword()
        const blob = await this.w3pk.createZipBackup(password)
        this.downloadBackup(blob)
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
        'Password too weak. Need 12+ chars with mixed case, numbers, symbols'
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

- [ ] Check for existing credentials before registration using `hasExistingCredential()`
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
