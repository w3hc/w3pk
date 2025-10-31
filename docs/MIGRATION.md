# Migration Guide

This guide helps you migrate between different versions of w3pk.

## Quick Links

- [v0.7.2 → v0.7.3](#v072--v073) - Base64 handling fixes (no breaking changes)
- [v0.6.0 → v0.7.0](#v060--v070) - Client-only architecture (breaking changes)

---

## v0.7.2 → v0.7.3

### Summary

**No breaking changes.** This is a bug fix release that improves base64/base64url handling.

### What Changed

Fixed critical registration error:
```
Failed to execute 'atob' on 'Window': The string to be decoded is not correctly encoded
```

### Impact

✅ **Zero migration needed** - All existing code continues to work
✅ **Drop-in replacement** - Just update the version
✅ **Better reliability** - Registration, authentication, and backups more robust

### Update Steps

1. **Update package.json:**
```diff
{
  "dependencies": {
-   "w3pk": "^0.7.2"
+   "w3pk": "^0.7.3"
  }
}
```

2. **Install:**
```bash
pnpm install
# or
npm install
```

3. **Done!** No code changes needed.

### Technical Details

The SDK now has improved base64url decoding that:
- Automatically adds padding to base64url strings
- Converts URL-safe characters (`-`, `_`) to standard base64 (`+`, `/`)
- Handles both base64 and base64url formats transparently

See [BASE64_HANDLING.md](./BASE64_HANDLING.md) for technical details.

### What's Fixed

- ✅ Registration with WebAuthn (attestation object decoding)
- ✅ Authentication signature verification
- ✅ Backup encryption/decryption
- ✅ All crypto operations with base64url data

### Testing

All existing tests pass without modification:
```bash
pnpm test  # All 50+ tests passing
```

---

## v0.6.0 → v0.7.0

This guide helps you migrate from w3pk v0.6.0 (server-based) to v0.7.0 (client-only).

## Breaking Changes

### 1. Client-Only Architecture

**v0.6.0** required a backend server for WebAuthn verification.

**v0.7.0** is fully client-side - no server needed.

```diff
- // v0.6.0: Required backend API
- const w3pk = createWeb3Passkey({
-   apiUrl: 'https://your-backend.com/api'
- })

+ // v0.7.0: No backend needed
+ const w3pk = createWeb3Passkey()
```

### 2. Authentication Flow Changed

The wallet generation flow has been reordered for better UX and security.

**Old Flow (v0.6.0):**
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
// 1. Generate wallet FIRST (no authentication needed - optional)
const { mnemonic } = await w3pk.generateWallet()
console.log('Save this recovery phrase:', mnemonic)

// 2. Register (auto-generates wallet if not already created, and stores it securely)
await w3pk.register({ username: 'alice' })
```

**Why this change?**
- The wallet's account #0 address is automatically used as the WebAuthn identifier
- Simpler API: no need to manually pass the address
- Better UX: user saves mnemonic, SDK handles the rest
- More secure: wallet address bound to WebAuthn credentials

### 3. Registration API Simplified

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
  // Register (auto-generates wallet and stores it securely)
  const { mnemonic } = await w3pk.register({ username })

  // Show mnemonic to user
  console.log('⚠️  Save this recovery phrase:', mnemonic)

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

If you have users on v0.6.0, you'll need to migrate their data:

1. **Export data from v0.6.0** (before upgrading):
```typescript
// Run this with v0.6.0 still installed
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

  // Register with new flow (uses imported mnemonic)
  await w3pk.register({ username })
}
```

## Updated API Reference

### Methods That Changed

| Method | v0.6.0 | v0.7.0 | Notes |
|--------|--------|--------|-------|
| `generateWallet()` | Required auth, returned full wallet | No auth needed, returns `{ mnemonic }` | Optional - for pre-generating wallet |
| `register()` | `{ username }` | `{ username }`, returns `{ mnemonic }` | Auto-generates wallet and stores it |

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

### Before (v0.6.0)
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

**Cause:** You're using the old v0.6.0 pattern.

**Solution:** Simply call `register()` - it auto-generates the wallet:
```typescript
// ✅ Correct - register auto-generates and stores wallet
const { mnemonic } = await w3pk.register({ username: 'alice' })
```

## Testing Your Migration

Use this checklist:

- [ ] Remove `apiUrl` from config
- [ ] Update registration flow: `register()` now returns and auto-stores the wallet
- [ ] Remove `ethereumAddress` from `register()` calls
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
    // Register (auto-generates wallet and stores it securely)
    const { mnemonic } = await w3pk.register({ username })
    console.log('⚠️  Save this recovery phrase:', mnemonic)

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

## Version History

- **v0.7.3** (2025-10-31) - Base64 handling fixes, no breaking changes
- **v0.7.2** (2025-10-30) - Backup system added
- **v0.7.1** (2025-10-25) - Stealth addresses & ZK proofs
- **v0.7.0** (2025-10-20) - Client-only architecture (breaking changes from v0.6.0)
- **v0.6.0** (2025-10-15) - Server-based architecture (legacy)

---

**Last Updated:** v0.7.3
**Current Version:** v0.7.3
