# Migration Guide: v0.5.0 → v0.6.0

This guide helps you migrate from w3pk v0.5.0 (server-based) to v0.6.0 (client-only).

## Breaking Changes

### 1. Client-Only Architecture

**v0.5.0** required a backend server for WebAuthn verification.

**v0.6.0** is fully client-side - no server needed.

```diff
- // v0.5.0: Required backend API
- const w3pk = createWeb3Passkey({
-   apiUrl: 'https://your-backend.com/api'
- })

+ // v0.6.0: No backend needed
+ const w3pk = createWeb3Passkey()
```

### 2. Authentication Flow Changed

The wallet generation flow has been reordered for better UX and security.

**Old Flow (v0.5.0):**
```typescript
// 1. Register first
await w3pk.register({ username: 'alice' })

// 2. Login
await w3pk.login()

// 3. Generate wallet
const wallet = await w3pk.generateWallet()
```

**New Flow (v0.6.0):**
```typescript
// 1. Generate wallet FIRST (no authentication needed)
const { mnemonic } = await w3pk.generateWallet()
console.log('Save this recovery phrase:', mnemonic)

// 2. Register (account #0 address derived automatically)
await w3pk.register({ username: 'alice' })

// 3. Save wallet (encrypts and stores securely)
await w3pk.saveWallet()  // ← New method
```

**Why this change?**
- The wallet's account #0 address is automatically used as the WebAuthn identifier
- Simpler API: no need to manually pass the address
- Better UX: user saves mnemonic, SDK handles the rest
- More secure: wallet address bound to WebAuthn credentials

### 3. New Method: `saveWallet()`

You must call `saveWallet()` after registration to persist the wallet securely.

```typescript
// Generate wallet
const { mnemonic } = await w3pk.generateWallet()

// Register (address derived automatically)
await w3pk.register({ username: 'alice' })

// NEW: Save wallet (required!)
await w3pk.saveWallet()
```

**What it does:**
- Encrypts the wallet mnemonic with WebAuthn-derived key
- Stores encrypted wallet in IndexedDB
- Requires the user to be authenticated

### 4. Registration API Simplified

```diff
+ // Generate wallet first
+ const { mnemonic } = await w3pk.generateWallet()
+
  await w3pk.register({
    username: 'alice'
+   // Address derived automatically from generated wallet
  })
```

## Step-by-Step Migration

### For New Users

Simply update your onboarding flow:

```typescript
// v0.6.0 onboarding
async function onboard(username: string) {
  // 1. Generate wallet
  const { mnemonic } = await w3pk.generateWallet()

  // 2. Show mnemonic to user
  console.log('⚠️  Save this recovery phrase:', mnemonic)

  // 3. Register (address derived automatically)
  await w3pk.register({ username })

  // 4. Save wallet
  await w3pk.saveWallet()

  console.log('✅ Setup complete!')
}
```

### For Returning Users

Login flow remains the same:

```typescript
// Works the same in both versions
await w3pk.login()
```

### For Existing Installations

If you have users on v0.5.0, you'll need to migrate their data:

1. **Export data from v0.5.0** (before upgrading):
```typescript
// Run this with v0.5.0 still installed
const users = await getAllUsers() // Your backend
const wallets = await exportAllWallets() // Your backend
```

2. **Upgrade to v0.6.0**

3. **Re-register users** with client-only flow:
```typescript
// Users will need to re-register with v0.6.0
// Their wallets can be imported if you saved the mnemonics
async function migrateUser(username: string, savedMnemonic: string) {
  // Import existing wallet
  await w3pk.importMnemonic(savedMnemonic)

  // Generate wallet (uses imported mnemonic)
  const { mnemonic } = await w3pk.generateWallet()

  // Register with new flow (address derived automatically)
  await w3pk.register({ username })

  await w3pk.saveWallet()
}
```

## Updated API Reference

### Methods That Changed

| Method | v0.5.0 | v0.6.0 | Notes |
|--------|--------|--------|-------|
| `generateWallet()` | Required auth, returned full wallet | No auth needed, returns `{ mnemonic }` | Now first step in flow |
| `register()` | `{ username }` | `{ username }` | Address derived internally |
| `saveWallet()` | N/A | **New method** | Required after registration |

### Methods That Stayed The Same

These methods work identically:
- ✅ `login()`
- ✅ `logout()`
- ✅ `deriveWallet(index)`
- ✅ `exportMnemonic()`
- ✅ `importMnemonic(mnemonic)`
- ✅ `signMessage(message)`
- ✅ `getEndpoints(chainId)`
- ✅ `supportsEIP7702(chainId)`

### Removed Methods/Config

```diff
- apiUrl           // No longer needed (client-only)
- serverEndpoints  // No longer needed (client-only)
```

## Configuration Changes

### Before (v0.5.0)
```typescript
const w3pk = createWeb3Passkey({
  apiUrl: 'https://backend.com/api',  // Removed
  rpId: 'example.com',                // Removed (auto-detected)
  debug: true,
  storage: localStorage
})
```

### After (v0.6.0)
```typescript
const w3pk = createWeb3Passkey({
  debug: true,                        // ✅ Same
  storage: localStorage,              // ✅ Same
  onError: (error) => {               // ✅ Same
    console.error(error)
  },
  onAuthStateChanged: (isAuth, user) => {  // ✅ Same
    console.log('Auth changed:', isAuth)
  },
  stealthAddresses: {},               // ✅ Same (ERC-5564)
  zkProofs: {                         // ✅ Same (optional)
    enabledProofs: ['membership']
  }
})
```

## Common Issues

### Issue: "Must be authenticated to generate wallet"

**Cause:** You're using the old v0.5.0 pattern.

**Solution:** Call `generateWallet()` BEFORE `register()`:
```typescript
// ✅ Correct order
const { mnemonic } = await w3pk.generateWallet()
await w3pk.register({ username: 'alice' })
```

### Issue: "No wallet found. Call generateWallet() first."

**Cause:** You're trying to register without generating a wallet first.

**Solution:** Generate wallet before registration:
```typescript
const { mnemonic } = await w3pk.generateWallet()
await w3pk.register({ username: 'alice' })
```

### Issue: Wallet not persisting

**Cause:** Forgot to call `saveWallet()`.

**Solution:** Call it after registration:
```typescript
await w3pk.register({ username: 'alice' })
await w3pk.saveWallet()  // ← Don't forget this!
```

## Testing Your Migration

Use this checklist:

- [ ] Remove `apiUrl` from config
- [ ] Update registration flow: generate → register → save
- [ ] Remove `ethereumAddress` from `register()` calls
- [ ] Update `generateWallet()` to destructure `{ mnemonic }`
- [ ] Add `saveWallet()` after registration
- [ ] Test new user flow
- [ ] Test returning user flow (login)
- [ ] Remove backend server code (if applicable)
- [ ] Update documentation/UI to show new flow

## Benefits of v0.6.0

✅ **No backend required** - Simpler deployment, lower costs
✅ **Better privacy** - All authentication local
✅ **Clearer UX** - Users see their wallet address before committing
✅ **More secure** - Wallet address bound to WebAuthn credentials
✅ **ERC-5564 support** - Stealth addresses for privacy
✅ **EIP-7702 detection** - 329+ supported networks
✅ **2390+ chains** - Built-in Chainlist integration

## Getting Help

- 📖 [README](./README.md) - Updated examples
- 📖 [CONTRIBUTING](./CONTRIBUTING.md) - Full API reference
- 🐛 [Issues](https://github.com/your-repo/w3pk/issues) - Report problems
- 💬 [Discussions](https://github.com/your-repo/w3pk/discussions) - Ask questions

## Example: Complete v0.6.0 App

```typescript
import { createWeb3Passkey } from 'w3pk'
import { ethers } from 'ethers'

const w3pk = createWeb3Passkey({
  debug: true,
  onAuthStateChanged: (isAuth, user) => {
    console.log('Authenticated:', isAuth)
    if (user) console.log('User:', user.username, user.ethereumAddress)
  }
})

// New user flow
async function registerNewUser(username: string) {
  try {
    // 1. Generate wallet
    const { mnemonic } = await w3pk.generateWallet()
    console.log('⚠️  Save this recovery phrase:', mnemonic)

    // 2. Register (address derived automatically)
    await w3pk.register({ username })

    // 3. Save wallet
    await w3pk.saveWallet()

    console.log('✅ Registration complete!')
    return mnemonic
  } catch (error) {
    console.error('Registration failed:', error)
    throw error
  }
}

// Returning user flow
async function loginExistingUser() {
  try {
    const user = await w3pk.login()
    console.log('✅ Welcome back,', user.username)
    return user
  } catch (error) {
    console.error('Login failed:', error)
    throw error
  }
}

// Use the wallet
async function sendTransaction(to: string, amount: string) {
  // Get derived wallet
  const wallet = await w3pk.deriveWallet(0)

  // Get RPC endpoint
  const endpoints = await w3pk.getEndpoints(1) // Ethereum
  const provider = new ethers.JsonRpcProvider(endpoints[0])

  // Create signer
  const signer = new ethers.Wallet(wallet.privateKey!, provider)

  // Send transaction
  const tx = await signer.sendTransaction({
    to,
    value: ethers.parseEther(amount)
  })

  console.log('Transaction sent:', tx.hash)
  return tx
}

// App initialization
async function initApp() {
  if (w3pk.isAuthenticated) {
    console.log('Already logged in as:', w3pk.user?.username)
  } else {
    console.log('Not authenticated')
  }
}

initApp()
```

---

**Last Updated:** v0.6.0
**Previous Version:** v0.5.0
