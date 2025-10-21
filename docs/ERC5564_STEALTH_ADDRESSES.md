# ERC-5564 Stealth Addresses

Complete guide to using ERC-5564 compliant stealth addresses in w3pk.

## Table of Contents

- [Overview](#overview)
- [What are Stealth Addresses?](#what-are-stealth-addresses)
- [ERC-5564 Standard](#erc-5564-standard)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [How It Works](#how-it-works)
- [View Tags](#view-tags)
- [Use Cases](#use-cases)
- [Security Considerations](#security-considerations)
- [Complete Integration Example](#complete-integration-example)
- [Troubleshooting](#troubleshooting)
- [FAQ](#frequently-asked-questions)

**Visual Learner?** See [ERC-5564 Flow Diagrams](./ERC5564_FLOW_DIAGRAM.md) for detailed visual explanations.

## Overview

w3pk implements ERC-5564 compliant stealth addresses, enabling privacy-preserving transactions on Ethereum and EVM chains. This implementation follows the official standard and includes view tag optimization for efficient scanning.

**Standard Compliance:**
- ✅ ERC-5564 compliant
- ✅ SECP256k1 scheme with ECDH
- ✅ Compressed public keys (33 bytes)
- ✅ View tags for ~99% scan efficiency
- ✅ Non-interactive generation

## What are Stealth Addresses?

Stealth addresses allow you to receive funds at unlinkable, one-time addresses that only you can identify and spend from. Unlike regular addresses, each stealth address is unique and cannot be linked to your identity or other stealth addresses you control.

**Benefits:**
- **Privacy**: Transactions cannot be linked to your identity
- **Unlinkable**: Each payment uses a unique address
- **Non-interactive**: No communication needed between sender and recipient
- **Efficient**: View tags enable fast scanning (~99% skip rate)

## ERC-5564 Standard

ERC-5564 is the Ethereum standard for stealth addresses. It defines:

1. **Stealth Meta-Address**: 66 bytes containing spending and viewing public keys
2. **SECP256k1 Scheme**: Uses ECDH for shared secret computation
3. **View Tags**: 1-byte optimization for efficient scanning
4. **Announcement Format**: Standard for publishing stealth payments on-chain

**Specification:** https://eips.ethereum.org/EIPS/eip-5564

## Quick Start

### Setup

```typescript
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  stealthAddresses: {} // Enable stealth addresses
})
```

### Recipient: Get Stealth Meta-Address

```typescript
// Get your stealth meta-address to share publicly
const metaAddress = await w3pk.stealth?.getStealthMetaAddress()
console.log(metaAddress)
// 0x03f2e32f9a060b8fe18736f5c4da328265d9d29ac13d5fed45649700a9c5f2cdca03037f40766fbc839e1b69a19685ce42f967a74a87d597a52ef525810484908b33

// Or get full keys
const keys = await w3pk.stealth?.getKeys()
console.log(keys.stealthMetaAddress)  // 66 bytes
console.log(keys.spendingPubKey)      // 33 bytes (compressed)
console.log(keys.viewingPubKey)       // 33 bytes (compressed)
```

### Sender: Generate Stealth Address

```typescript
// Generate a stealth address for recipient
const announcement = await w3pk.stealth?.generateStealthAddress()

console.log(announcement.stealthAddress)     // 0x1234...
console.log(announcement.ephemeralPublicKey) // 33 bytes
console.log(announcement.viewTag)            // 1 byte (0x00-0xff)

// 1. Send funds to announcement.stealthAddress
// 2. Publish announcement on-chain (event/transaction data)
```

### Recipient: Parse Announcements

```typescript
// Check if an announcement is for you
const result = await w3pk.stealth?.parseAnnouncement({
  stealthAddress: '0x1234...',
  ephemeralPublicKey: '0x02abcd...',
  viewTag: '0xa4'
})

if (result.isForUser) {
  console.log('Payment found!')
  console.log('Address:', result.stealthAddress)
  console.log('Private key:', result.stealthPrivateKey)

  // Use private key to spend funds
  const wallet = new ethers.Wallet(result.stealthPrivateKey)
}
```

### Scan Multiple Announcements

```typescript
// Efficiently scan many announcements
const announcements = [
  { stealthAddress: '0x...', ephemeralPublicKey: '0x...', viewTag: '0x...' },
  // ... more announcements
]

const myPayments = await w3pk.stealth?.scanAnnouncements(announcements)

console.log(`Found ${myPayments.length} payments`)
myPayments.forEach(payment => {
  console.log('Stealth address:', payment.stealthAddress)
  console.log('Private key:', payment.stealthPrivateKey)
})
```

## API Reference

### `getStealthMetaAddress()`

Get your stealth meta-address to share publicly with senders.

**Returns:** `Promise<string>` - 66-byte stealth meta-address (0x-prefixed hex)

**Example:**
```typescript
const metaAddress = await w3pk.stealth?.getStealthMetaAddress()
```

### `getKeys()`

Get full stealth keys including meta-address and private keys.

**Returns:** `Promise<StealthKeys>`

```typescript
interface StealthKeys {
  stealthMetaAddress: string    // 66 bytes
  spendingPubKey: string         // 33 bytes (compressed)
  viewingPubKey: string          // 33 bytes (compressed)
  viewingKey: string             // 32 bytes (private)
  spendingKey: string            // 32 bytes (private)
}
```

### `generateStealthAddress()`

Generate a stealth address for the recipient (sender's operation).

**Returns:** `Promise<StealthAddressResult>`

```typescript
interface StealthAddressResult {
  stealthAddress: string         // Address to send funds to
  ephemeralPublicKey: string     // 33 bytes (publish on-chain)
  viewTag: string                // 1 byte (publish on-chain)
}
```

### `parseAnnouncement(announcement)`

Check if an announcement is for you and get the private key if it is.

**Parameters:**
- `announcement: Announcement` - The announcement to parse

**Returns:** `Promise<ParseAnnouncementResult>`

```typescript
interface Announcement {
  stealthAddress: string
  ephemeralPublicKey: string
  viewTag: string
}

interface ParseAnnouncementResult {
  isForUser: boolean
  stealthAddress?: string        // Only if isForUser is true
  stealthPrivateKey?: string     // Only if isForUser is true
}
```

### `scanAnnouncements(announcements)`

Efficiently scan multiple announcements using view tags.

**Parameters:**
- `announcements: Announcement[]` - Array of announcements

**Returns:** `Promise<ParseAnnouncementResult[]>` - Only announcements that belong to you

## How It Works

### 1. Key Generation (Recipient)

The recipient generates two key pairs:
- **Spending Key**: For spending funds
- **Viewing Key**: For identifying payments

These are combined into a 66-byte **stealth meta-address**:
```
stealthMetaAddress = spending_pubkey (33 bytes) + viewing_pubkey (33 bytes)
```

### 2. Stealth Address Generation (Sender)

The sender has only the recipient's stealth meta-address. They:

1. Generate random **ephemeral private key**
2. Compute **shared secret** using ECDH:
   ```
   shared_secret = ephemeral_privkey × viewing_pubkey
   ```
3. Hash the shared secret:
   ```
   s_h = keccak256(shared_secret)
   ```
4. Extract **view tag** (first byte):
   ```
   viewTag = s_h[0]
   ```
5. Compute **stealth public key**:
   ```
   stealth_pubkey = spending_pubkey + (s_h × G)
   ```
6. Derive **stealth address** from stealth_pubkey

### 3. Announcement (Sender)

The sender publishes on-chain:
- Stealth address (where funds were sent)
- Ephemeral public key
- View tag
- Optional metadata

### 4. Scanning (Recipient)

For each announcement, the recipient:

1. Compute shared secret:
   ```
   shared_secret = viewing_privkey × ephemeral_pubkey
   ```
2. Hash it:
   ```
   s_h = keccak256(shared_secret)
   ```
3. **Check view tag first** (optimization):
   ```
   if s_h[0] != announcement.viewTag:
     skip this announcement  // 255/256 probability
   ```
4. If view tag matches, compute stealth pubkey and compare addresses

### 5. Spending (Recipient)

If the announcement is for them, compute the stealth private key:
```
stealth_privkey = spending_privkey + s_h (mod n)
```

This private key can spend from the stealth address.

## View Tags

View tags are a critical optimization in ERC-5564 that make scanning practical.

### Problem Without View Tags

Without optimization, recipients must perform expensive operations for every announcement:
1. Compute shared secret (1 elliptic curve multiplication)
2. Hash it (1 keccak256)
3. **Compute stealth pubkey** (1 EC multiplication + 1 EC addition)
4. Derive address and compare

For 10,000 announcements, this requires 10,000 full checks.

### Solution: View Tags

The view tag is the **first byte** of the hashed shared secret. Recipients can:

1. Compute shared secret and hash (cheap)
2. **Compare first byte** with announcement's view tag
3. Skip remaining operations if view tag doesn't match

**Efficiency:**
- Probability of view tag match: **1/256**
- Probability of skipping full check: **255/256 ≈ 99%**
- For 10,000 announcements: ~39 full checks instead of 10,000

**Speed Improvement:** ~6x faster scanning

### Security Trade-off

View tags reveal 1 byte of the shared secret, reducing security from 128 bits to 124 bits. This is acceptable because:
- 124 bits is still cryptographically secure
- The view tag only aids scanning, not address generation
- The privacy benefit of practical scanning outweighs the minimal security reduction

## Use Cases

### Private Donations

Accept donations without revealing your identity or linking multiple donations together.

```typescript
// Publish your stealth meta-address
const metaAddress = await w3pk.stealth?.getStealthMetaAddress()

// Donors send to unique stealth addresses
// You scan and collect all donations privately
```

### Anonymous Airdrops

Distribute tokens to users at stealth addresses, preserving their privacy.

### Privacy-Preserving Payments

Send or receive payments without on-chain linkability.

### Dark Pool Trading

Trade assets without revealing trading patterns.

### Unlinkable Transaction Chains

Break transaction graph analysis by using unique addresses for each payment.

## Security Considerations

### Best Practices

1. **Protect Private Keys**: Viewing and spending keys must be kept secret
2. **Secure Key Derivation**: w3pk uses BIP44 HD paths for deterministic key generation
3. **View Tag Trade-off**: Acceptable 1-byte security reduction for massive efficiency gain
4. **On-chain Announcements**: Ensure announcements are published reliably
5. **Backup**: Mnemonic phrase allows full recovery of all stealth addresses

### Threat Model

**What ERC-5564 Protects Against:**
- ✅ Linking multiple payments to the same recipient
- ✅ Identifying the recipient from on-chain data
- ✅ Transaction graph analysis

**What It Doesn't Protect Against:**
- ❌ Network-level analysis (use Tor/VPN)
- ❌ Amount analysis (use fixed denominations)
- ❌ Timing analysis (batch transactions)
- ❌ Compromised recipient keys (protect your mnemonic)

### Privacy Tips

1. **Don't reuse addresses**: Each stealth address should be used once
2. **Use mixers**: Combine with coin mixing for additional privacy
3. **Batch withdrawals**: Withdraw from multiple stealth addresses together
4. **Fixed amounts**: Use common denominations to obscure actual amounts
5. **Tor/VPN**: Hide network-level metadata

## Advanced Topics

### Custom Derivation Paths

w3pk uses these HD paths for stealth keys:
- Viewing key: `m/44'/60'/1'/0/0`
- Spending key: `m/44'/60'/1'/0/1`

### SECP256k1 Curve Operations

The implementation uses proper elliptic curve operations:
- **Point multiplication**: For ECDH and key derivation
- **Point addition**: For computing stealth public keys
- **Compressed points**: 33-byte format for efficiency

### Compatibility

w3pk's ERC-5564 implementation is compatible with:
- Other ERC-5564 implementations
- Standard Ethereum wallets (for spending from stealth addresses)
- ERC-6538 meta-address registry (future support planned)

## Future Enhancements

Planned features:
- **ERC-6538 Registry**: On-chain stealth meta-address registry
- **Contract Integration**: Helper contracts for announcements
- **Batch Operations**: Efficiently scan thousands of announcements
- **Alternative Curves**: Support for other elliptic curves

## Complete Integration Example

Here's a full end-to-end example integrating ERC-5564 in a React application:

```typescript
import { createWeb3Passkey, generateStealthAddress } from 'w3pk'
import { ethers } from 'ethers'
import { useState, useEffect } from 'react'

function StealthPaymentApp() {
  const [w3pk, setW3pk] = useState(null)
  const [metaAddress, setMetaAddress] = useState('')
  const [announcements, setAnnouncements] = useState([])

  useEffect(() => {
    const sdk = createWeb3Passkey({
      apiBaseUrl: 'https://webauthn.w3hc.org',
      stealthAddresses: {}
    })
    setW3pk(sdk)
  }, [])

  // RECIPIENT: Setup
  const setupRecipient = async () => {
    await w3pk.login()
    const meta = await w3pk.stealth?.getStealthMetaAddress()
    setMetaAddress(meta)
    console.log('Share this meta-address:', meta)
  }

  // SENDER: Generate and send to stealth address
  const sendPayment = async (recipientMetaAddress: string, amount: string) => {
    // Generate stealth address
    const announcement = generateStealthAddress(recipientMetaAddress)

    // Send transaction
    const provider = new ethers.JsonRpcProvider('https://cloudflare-eth.com')
    const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider)

    const tx = await wallet.sendTransaction({
      to: announcement.stealthAddress,
      value: ethers.parseEther(amount)
    })

    await tx.wait()

    // Publish announcement on-chain (emit event or store in transaction data)
    const announcementContract = new ethers.Contract(
      '0xYourAnnouncementContract',
      ['function announce(address stealth, bytes ephemeral, bytes1 viewTag)'],
      wallet
    )

    await announcementContract.announce(
      announcement.stealthAddress,
      announcement.ephemeralPublicKey,
      announcement.viewTag
    )

    console.log('Payment sent and announced!')
  }

  // RECIPIENT: Scan for payments
  const scanForPayments = async () => {
    // Fetch announcements from blockchain
    const provider = new ethers.JsonRpcProvider('https://cloudflare-eth.com')
    const announcementContract = new ethers.Contract(
      '0xYourAnnouncementContract',
      ['event Announced(address indexed stealth, bytes ephemeral, bytes1 viewTag)'],
      provider
    )

    const filter = announcementContract.filters.Announced()
    const events = await announcementContract.queryFilter(filter)

    const announcements = events.map(event => ({
      stealthAddress: event.args.stealth,
      ephemeralPublicKey: event.args.ephemeral,
      viewTag: event.args.viewTag
    }))

    // Scan announcements efficiently
    const myPayments = await w3pk.stealth?.scanAnnouncements(announcements)
    console.log(`Found ${myPayments.length} payments:`, myPayments)

    // Withdraw funds
    for (const payment of myPayments) {
      const wallet = new ethers.Wallet(payment.stealthPrivateKey, provider)
      const balance = await provider.getBalance(payment.stealthAddress)

      if (balance > 0n) {
        // Send to your main address
        const tx = await wallet.sendTransaction({
          to: yourMainAddress,
          value: balance - ethers.parseEther('0.001') // Leave gas
        })
        await tx.wait()
        console.log('Withdrawn:', ethers.formatEther(balance), 'ETH')
      }
    }
  }

  return (
    <div>
      <button onClick={setupRecipient}>Setup Recipient</button>
      {metaAddress && (
        <div>
          <p>Meta-Address: {metaAddress}</p>
          <button onClick={scanForPayments}>Scan for Payments</button>
        </div>
      )}
    </div>
  )
}
```

## Troubleshooting

### Common Issues

#### 1. "Cannot read property 'generateStealthAddress' of undefined"

**Problem**: Stealth address module not initialized.

**Solution**:
```typescript
// Make sure to enable stealth addresses in config
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  stealthAddresses: {}  // ← Don't forget this!
})

// Always check if stealth is available
if (!w3pk.stealth) {
  console.error('Stealth addresses not enabled')
}
```

#### 2. "Invalid stealth meta-address length"

**Problem**: Meta-address should be 134 characters (66 bytes with 0x prefix).

**Solution**:
```typescript
// Correct format: 0x + 132 hex chars = 134 total
const metaAddress = await w3pk.stealth?.getStealthMetaAddress()
console.log(metaAddress.length) // Should be 134

// If you have 66 characters, it's missing the 0x prefix
if (metaAddress.length === 132) {
  metaAddress = '0x' + metaAddress
}
```

#### 3. "View tag mismatch - payment not found"

**Problem**: This is expected! View tags filter out 99% of announcements.

**Solution**:
```typescript
// This is normal behavior - only ~1/256 announcements will match
const result = await w3pk.stealth?.parseAnnouncement(announcement)
if (!result.isForUser) {
  // This is expected for most announcements
  console.log('Not for me - view tag filtered it out')
}
```

#### 4. "Cannot spend from stealth address"

**Problem**: Wrong private key or insufficient gas.

**Solution**:
```typescript
// Make sure you're using the stealth private key, not your main key
const result = await w3pk.stealth?.parseAnnouncement(announcement)
if (result.isForUser) {
  const wallet = new ethers.Wallet(result.stealthPrivateKey, provider)

  // Check balance first
  const balance = await provider.getBalance(wallet.address)
  console.log('Balance:', ethers.formatEther(balance))

  // Leave enough for gas
  const gasEstimate = await provider.estimateGas({
    to: destinationAddress,
    value: balance
  })
  const gasCost = gasEstimate * (await provider.getFeeData()).gasPrice
  const amountToSend = balance - gasCost

  if (amountToSend > 0n) {
    const tx = await wallet.sendTransaction({
      to: destinationAddress,
      value: amountToSend
    })
    await tx.wait()
  }
}
```

#### 5. "Scanning is too slow"

**Problem**: Not using view tags or scanning too many announcements.

**Solution**:
```typescript
// Always use scanAnnouncements for bulk scanning
// It uses view tags for ~99% skip rate
const myPayments = await w3pk.stealth?.scanAnnouncements(announcements)

// For very large sets, filter by time range first
const recentAnnouncements = announcements.filter(a =>
  a.timestamp > Date.now() - 30 * 24 * 60 * 60 * 1000 // Last 30 days
)

// Or process in batches
const batchSize = 1000
for (let i = 0; i < announcements.length; i += batchSize) {
  const batch = announcements.slice(i, i + batchSize)
  const payments = await w3pk.stealth?.scanAnnouncements(batch)
  allPayments.push(...payments)
}
```

## Frequently Asked Questions

### General Questions

**Q: What's the difference between stealth addresses and regular addresses?**

A: Regular addresses are static and publicly linked to your identity. Stealth addresses are one-time, unlinkable addresses that only you can identify and control. Each payment uses a unique address that cannot be connected to you or your other transactions.

**Q: Do I need to communicate with the sender?**

A: No! ERC-5564 is completely non-interactive. The sender only needs your public stealth meta-address to generate a stealth address. No communication or coordination is required.

**Q: How does the recipient find their payments?**

A: Recipients scan blockchain announcements. The sender publishes the ephemeral public key and view tag on-chain (typically in an event). Recipients can efficiently check if an announcement is for them using the view tag.

**Q: What are view tags?**

A: View tags are a 1-byte optimization that allows recipients to skip ~99% (255/256) of announcements without performing expensive cryptographic operations. This makes scanning practical even with thousands of announcements.

### Security Questions

**Q: Is it safe to share my stealth meta-address publicly?**

A: Yes! The stealth meta-address contains only public keys. Sharing it publicly is like sharing an ENS name or regular address. However, never share your viewing or spending private keys.

**Q: What if someone steals my stealth meta-address?**

A: They can generate stealth addresses for you, but they cannot:
- Identify which existing stealth addresses belong to you
- Spend funds from your stealth addresses
- Access your private keys

Only you can scan announcements and spend funds.

**Q: Are stealth addresses more secure than regular addresses?**

A: They provide the same cryptographic security (SECP256k1) but offer additional privacy. The main benefit is unlinkability, not stronger cryptography.

**Q: What happens if I lose my mnemonic?**

A: You lose access to all stealth addresses derived from it. There's no recovery mechanism. Always backup your mnemonic securely.

### Technical Questions

**Q: Can I use hardware wallets with stealth addresses?**

A: Not directly for generating stealth addresses, as hardware wallets don't typically support custom HD derivation paths (m/44'/60'/1'/0/0). However, you can:
1. Generate stealth addresses using w3pk
2. Export the stealth private keys
3. Import them into a hardware wallet for signing

**Q: Do stealth addresses work on all EVM chains?**

A: Yes! The cryptography is chain-agnostic. However, you need announcement infrastructure on each chain (event emitters or registries).

**Q: How much does it cost to use stealth addresses?**

A: Costs include:
1. **Sending payment**: Normal transaction gas + announcement event emission (~50k gas)
2. **Receiving/scanning**: Free (done off-chain)
3. **Spending**: Normal transaction gas

**Q: Can I reuse a stealth address?**

A: Technically yes, but you shouldn't! Reusing stealth addresses defeats the purpose. Each payment should use a fresh stealth address for maximum privacy.

**Q: How do view tags work exactly?**

A: View tags are the first byte of the hashed shared secret:
```typescript
sharedSecret = viewing_privkey × ephemeral_pubkey
hashedSecret = keccak256(sharedSecret)
viewTag = hashedSecret[0]  // First byte (0x00 to 0xff)
```

Recipients compare the view tag before doing expensive operations. Only 1 in 256 announcements will match, making scanning ~6x faster.

### Integration Questions

**Q: How do I integrate stealth addresses in my dApp?**

A: See the [Complete Integration Example](#complete-integration-example) above. Key steps:
1. Enable stealth addresses in w3pk config
2. Recipient shares meta-address
3. Sender generates stealth address using recipient's meta-address
4. Sender publishes announcement on-chain
5. Recipient scans announcements periodically

**Q: Do I need to run my own announcement service?**

A: Not necessarily. You can:
- Use existing ERC-5564 announcement contracts
- Emit custom events from your contracts
- Use transaction calldata
- Wait for ERC-6538 registry adoption (coming soon)

**Q: Can I use stealth addresses with smart contracts?**

A: Yes! Smart contracts can generate stealth addresses if they have the recipient's meta-address. However, contracts cannot scan announcements (that's done off-chain by recipients).

**Q: How do I test stealth addresses on testnets?**

A: Same as mainnet:
```typescript
const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  stealthAddresses: {}
})

// Use testnet RPC
const provider = new ethers.JsonRpcProvider('https://rpc.sepolia.org')

// Test stealth address generation
const announcement = await w3pk.stealth?.generateStealthAddress()
console.log('Test stealth address:', announcement.stealthAddress)
```

## Resources

- [ERC-5564 Specification](https://eips.ethereum.org/EIPS/eip-5564)
- [ERC-6538 Registry](https://eips.ethereum.org/EIPS/eip-6538)
- [Example Implementation](../examples/erc5564-stealth-demo.ts)
- [Test Suite](../test/erc5564.test.ts)
- [Playground Demo](https://github.com/w3hc/w3pk-playground)

## Support

For questions or issues:
- GitHub Issues: https://github.com/w3hc/w3pk/issues
- Documentation: https://github.com/w3hc/w3pk#readme
