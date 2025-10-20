# Migration Guide: v0.5.x to v0.6.0

Version 0.6.0 introduces better separation of ZK features to improve developer experience and reduce bundle size for users who don't need zero-knowledge proofs.

## What Changed

### 1. ZK Imports are Now Separate

**Before (v0.5.x):**
```typescript
import { 
  createWeb3Passkey, 
  buildMerkleTree, 
  generateBlinding,
  ZKProofModule 
} from 'w3pk'
```

**After (v0.6.0):**
```typescript
// Core features
import { createWeb3Passkey } from 'w3pk'

// ZK features (optional)
import { ZKProofModule } from 'w3pk/zk'
import { buildMerkleTree, generateBlinding } from 'w3pk/zk/utils'
```

### 2. ZK Types No Longer in Main Export

**Before:**
```typescript
import { ZKProof, MembershipProofInput } from 'w3pk'
```

**After:**
```typescript
import type { ZKProof, MembershipProofInput } from 'w3pk/zk'
```

### 3. No Breaking Changes for Core Features

If you're not using ZK proofs, **no changes needed**:
```typescript
// This still works exactly the same
import { createWeb3Passkey } from 'w3pk'

const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org'
})
```

## Migration Steps

### Step 1: Update Imports

Find and replace in your codebase:
```bash
# Find ZK-related imports
grep -r "import.*from 'w3pk'" src/
```

Update them:
```typescript
// OLD
import { buildMerkleTree, generateBlinding } from 'w3pk'

// NEW
import { buildMerkleTree, generateBlinding } from 'w3pk/zk/utils'
```

### Step 2: Update Type Imports
```typescript
// OLD
import { ZKProof, ZKProofConfig } from 'w3pk'

// NEW
import type { ZKProof, ZKProofConfig } from 'w3pk/zk'
```

### Step 3: Ensure ZK Dependencies are Installed

If you use ZK features, make sure dependencies are installed:
```bash
npm install snarkjs circomlibjs
```

### Step 4: Test Your Build
```bash
npm run build
```

Check that your bundle size hasn't increased unexpectedly.

## Benefits of Migration

### For Users NOT Using ZK

✅ **Smaller bundle**: ~5MB instead of ~75MB  
✅ **Faster installs**: 10 seconds instead of 60 seconds  
✅ **Cleaner types**: No ZK types in autocomplete  
✅ **No changes needed**: Core API unchanged

### For Users Using ZK

✅ **Explicit imports**: Clear which features require heavy deps  
✅ **Better tree-shaking**: Unused ZK code eliminated  
✅ **Lazy loading**: Can load ZK only when needed  
✅ **Same functionality**: All ZK features still available

## Automated Migration Script

We provide a migration script to help:
```bash
npx w3pk-migrate
```

This will:
1. Scan your code for old imports
2. Suggest replacements
3. Optionally auto-fix imports

## Examples

### Before Migration
```typescript
import { 
  createWeb3Passkey,
  buildMerkleTree,
  generateBlinding,
  type ZKProof
} from 'w3pk'

const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  zkProofs: {
    enabledProofs: ['membership']
  }
})

const { root, tree } = await buildMerkleTree(leaves)
const blinding = generateBlinding()
```

### After Migration
```typescript
// Separate imports for clarity
import { createWeb3Passkey } from 'w3pk'
import { buildMerkleTree, generateBlinding } from 'w3pk/zk/utils'
import type { ZKProof } from 'w3pk/zk'

const w3pk = createWeb3Passkey({
  apiBaseUrl: 'https://webauthn.w3hc.org',
  zkProofs: {
    enabledProofs: ['membership']
  }
})

const { root, tree } = await buildMerkleTree(leaves)
const blinding = generateBlinding()
```

## Troubleshooting

### "Cannot find module 'w3pk/zk'"

**Solution:** Update your `package.json`:
```bash
npm install w3pk@latest
```

### "Module not found: Can't resolve 'snarkjs'"

**Solution:** Install ZK dependencies:
```bash
npm install snarkjs circomlibjs
```

### Type errors after migration

**Solution:** Update type imports:
```typescript
// Add 'type' keyword
import type { ZKProof } from 'w3pk/zk'
```

### Bundle size increased

**Solution:** Remove old imports:
```typescript
// Remove unused ZK imports
// import { buildMerkleTree } from 'w3pk' ❌
```
