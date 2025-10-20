# Bundle Size Comparison

Understanding the bundle size impact of different w3pk configurations.

## Core Package (Without ZK)

**Recommended for most applications**
```bash
npm install w3pk ethers
```

### Size Breakdown
- **Total**: ~5MB uncompressed
- **w3pk core**: ~500KB
- **@simplewebauthn/browser**: ~100KB
- **ethers**: ~4.5MB

### Includes
- ✅ WebAuthn passwordless authentication
- ✅ Encrypted wallet management (AES-GCM-256)
- ✅ BIP39/BIP44 HD wallet generation
- ✅ Stealth addresses
- ✅ Message signing

## With Zero-Knowledge Proofs

**Only if you need privacy-preserving proofs**
```bash
npm install w3pk ethers snarkjs circomlibjs
```

### Size Breakdown
- **Total**: ~75MB uncompressed
- **Core package**: ~5MB (as above)
- **snarkjs**: ~60MB (ZK proof generation/verification)
- **circomlibjs**: ~10MB (Circom circuit utilities)

### Additional Features
- ✅ Membership proofs (prove you're in a set anonymously)
- ✅ Threshold proofs (prove balance > amount without revealing balance)
- ✅ Range proofs (prove age 18-65 without revealing exact age)
- ✅ NFT ownership proofs (prove NFT ownership anonymously)

## Decision Guide

### Use Core Package If:
- ✅ You need passwordless Web3 authentication
- ✅ You want encrypted wallet management
- ✅ You need stealth addresses for privacy
- ✅ You're building standard dApps
- ✅ Bundle size matters (<10MB target)

### Add ZK Proofs If:
- ✅ You need anonymous voting systems
- ✅ You're building privacy-preserving credential verification
- ✅ You need confidential token gating
- ✅ You're implementing private credit scoring
- ✅ You're OK with +70MB bundle size
- ✅ Your users need to prove statements without revealing data

## Production Optimization

### Tree-Shaking
Modern bundlers (Vite, Webpack 5, Rollup) will automatically remove unused ZK code if:
1. You don't import from `w3pk/zk`
2. You don't enable `zkProofs` in config
3. You use ES modules (`import` not `require`)

### Code Splitting
For applications that need ZK features for some users:
```typescript
// Lazy load ZK module
const loadZK = async () => {
  const { ZKProofModule } = await import('w3pk/zk');
  const { buildMerkleTree } = await import('w3pk/zk/utils');
  return { ZKProofModule, buildMerkleTree };
};

// Only load when needed
if (userNeedsZK) {
  const { ZKProofModule } = await loadZK();
  // Use ZK features
}
```

### CDN Usage
For quick prototyping, you can load from CDN (not recommended for production):
```html
<!-- Core only -->
<script type="module">
  import { createWeb3Passkey } from 'https://esm.sh/w3pk';
</script>

<!-- With ZK (large download) -->
<script type="module">
  import { createWeb3Passkey } from 'https://esm.sh/w3pk';
  import { ZKProofModule } from 'https://esm.sh/w3pk/zk';
</script>
```

## Benchmarks

### Installation Time (npm install)
- **Core only**: ~5-10 seconds
- **With ZK**: ~30-60 seconds (due to large deps)

### Build Time Impact
- **Core only**: Minimal (<1s added to build)
- **With ZK**: +5-10 seconds (if ZK code is used)

### Runtime Performance
- **Core features**: Fast (< 100ms operations)
- **ZK proof generation**: Slower (1-5 seconds per proof)
- **ZK proof verification**: Fast (< 100ms)

## Recommendations by Use Case

### Standard dApp
```bash
npm install w3pk ethers
```
Import: `import { createWeb3Passkey } from 'w3pk'`

### Privacy-Focused dApp
```bash
npm install w3pk ethers snarkjs circomlibjs
```
Import: 
```typescript
import { createWeb3Passkey } from 'w3pk'
import { ZKProofModule } from 'w3pk/zk'
import { buildMerkleTree } from 'w3pk/zk/utils'
```

### Hybrid (Some Users Need ZK)
```bash
npm install w3pk ethers snarkjs circomlibjs
```
Use code splitting:
```typescript
import { createWeb3Passkey } from 'w3pk'

// Load ZK only when needed
if (requiresPrivacy) {
  const zk = await import('w3pk/zk')
  // Use ZK features
}
```

## More Information

- [Quick Start Guide](./QUICK_START.md)
- [ZK Integration Guide](./ZK_INTEGRATION_GUIDE.md)
- [GitHub Repository](https://github.com/w3hc/w3pk)