## 🔐 Build Verification

**IPFS CIDv1 Hash:**
```
bafybeigvi2t7juchvhsk723fu2nuon2ks664k34653nnhar2fxaq4b2tba
```

### Verify This Release

**Option 1: Using w3pk SDK**
```typescript
import { verifyBuildHash } from 'w3pk'

const TRUSTED_HASH = 'bafybeigvi2t7juchvhsk723fu2nuon2ks664k34653nnhar2fxaq4b2tba'
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
git checkout v0.7.6
pnpm install
pnpm build
pnpm build:hash
# Should output: bafybeigvi2t7juchvhsk723fu2nuon2ks664k34653nnhar2fxaq4b2tba
```

**Option 3: Compare Multiple Sources**
```bash
# Check hash from npm package
npm view w3pk@0.7.6 dist.tarball | xargs curl -s | tar -xz
cat package/dist/BUILD_HASH.txt
# Should match: bafybeigvi2t7juchvhsk723fu2nuon2ks664k34653nnhar2fxaq4b2tba
```

### Multi-Source Verification

For maximum security, verify the hash from multiple sources:

1. ✅ **This GitHub release** (you are here)
2. ✅ **npm README**: https://www.npmjs.com/package/w3pk
3. ✅ **On-chain registry**: Coming soon - DAO-maintained hash registry
4. ✅ **Local build**: Clone repo and build yourself

All sources should report the same hash: `bafybeigvi2t7juchvhsk723fu2nuon2ks664k34653nnhar2fxaq4b2tba`

### What is Build Verification?

W3pk uses IPFS CIDv1 hashing to create a unique, deterministic fingerprint of each build. This allows you to:

- Verify package integrity
- Detect tampering or supply chain attacks
- Ensure reproducible builds
- Trust what you're installing

See the [Build Verification Guide](./docs/BUILD_VERIFICATION.md) for complete documentation.
