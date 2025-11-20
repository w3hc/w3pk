# Release Template

Add this section to your auto-generated GitHub release notes.

---

## 🔐 Build Verification

**IPFS CIDv1 Hash:**
```
[PASTE_BUILD_HASH_HERE]
```

### Verify This Release

**Option 1: Using w3pk SDK**
```typescript
import { verifyBuildHash } from 'w3pk'

const TRUSTED_HASH = '[PASTE_BUILD_HASH_HERE]'
const isValid = await verifyBuildHash(TRUSTED_HASH)

if (isValid) {
  console.log('✅ Build integrity verified!')
} else {
  console.error('⚠️ Build verification failed!')
}
```

**Option 2: Build Locally**
```bash
git clone https://github.com/w3hc/w3pk.git
cd w3pk
git checkout v[VERSION]
pnpm install
pnpm build
pnpm build:hash
# Should output: [PASTE_BUILD_HASH_HERE]
```

**Option 3: Compare Multiple Sources**
```bash
# Check hash from npm package
npm view w3pk@[VERSION] dist.tarball | xargs curl -s | tar -xz
cat package/dist/BUILD_HASH.txt

# Should match: [PASTE_BUILD_HASH_HERE]
```

### Multi-Source Verification

For maximum security, verify the hash from multiple sources:

1. ✅ **This GitHub release** (you are here)
2. ✅ **npm README**: https://www.npmjs.com/package/w3pk
3. ✅ **On-chain registry**: Coming soon - DAO-maintained hash registry
4. ✅ **Local build**: Clone repo and build yourself

All sources should report the same hash: `[PASTE_BUILD_HASH_HERE]`

### What is Build Verification?

W3pk uses IPFS CIDv1 hashing to create a unique, deterministic fingerprint of each build. This allows you to:

- Verify package integrity
- Detect tampering or supply chain attacks
- Ensure reproducible builds
- Trust what you're installing

See the [Build Verification Guide](./docs/BUILD_VERIFICATION.md) for complete documentation.

---

## 📝 How to Use This Template

When creating a release:

1. Build the package: `pnpm build`
2. Compute the hash: `pnpm build:hash`
3. Copy the hash from the output
4. Replace `[PASTE_BUILD_HASH_HERE]` with the actual hash
5. Replace `[VERSION]` with the version number (e.g., `0.7.6`)
6. Append this to your auto-generated release notes
