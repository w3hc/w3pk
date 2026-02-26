# Build Verification

W3PK provides utilities to compute and verify IPFS hashes of package builds, with a DAO-maintained onchain registry for trusted release verification.

## Overview

The build verification system computes an IPFS CIDv1 hash from the concatenated main build artifacts (`index.js`, `index.mjs`, `index.d.ts`). This hash can be used to:

- **Verify package integrity**: Ensure the installed package matches the published version
- **Reproducible builds**: Verify that builds produce consistent outputs
- **Security auditing**: Check that you're running the expected code
- **Supply chain verification**: Detect tampering or compromised packages
- **Onchain verification**: Compare against DAO-maintained registry on OP Mainnet

## Onchain Registry

W3PK maintains an immutable onchain registry of official release hashes:

- **Contract Address:** [`0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a`](https://optimistic.etherscan.io/address/0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a)
- **Network:** OP Mainnet (Chain ID: 10)
- **Purpose:** Decentralized source of truth for verified W3PK builds
- **Governance:** DAO-controlled via contract ownership

### Available Contract Methods

```solidity
// Get CID for a specific version (recommended)
function getCidByVersion(string version) view returns (string cid)

// Get the latest release information
function getLatestRelease() view returns (string version, string cid, uint256 timestamp)

// Get version for a specific CID
function getVersionByCid(string cid) view returns (string version)
```

### Verification Approaches

**Option 1: Verify Installed Version (Recommended)**

Query the registry for the specific version installed in your `package.json`. This ensures you're verifying the exact version your app depends on.

```typescript
// Get version from package.json (e.g., "^0.9.0" or "~0.9.0")
const installedVersion = packageJson.dependencies['w3pk'].replace(/^[~^]/, ''); // "0.9.0"

// Query registry (note: version must include "v" prefix)
const onchainCid = await registry.getCidByVersion(`v${installedVersion}`); // "v0.9.0"
```

**Note:** The registry expects version strings with a `v` prefix (e.g., `v0.9.0`, `v0.9.1`).

**Option 2: Check Against Latest**

Compare your build against the latest release. Useful for warning users about outdated versions.

```typescript
const [latestVersion, latestCid] = await registry.getLatestRelease();
const isLatest = currentHash === latestCid;
```

Host applications should query this registry to verify their W3PK installation.

## API Reference

### `getCurrentBuildHash()`

Computes the IPFS hash for the currently installed w3pk version from the unpkg CDN.

```typescript
import { getCurrentBuildHash } from 'w3pk';

const hash = await getCurrentBuildHash();
console.log('Build hash:', hash);
// => bafybeiafdhdxz3c3nhxtrhe7zpxfco5dlywpvzzscl277hojn7zosmrob4
```

### `getW3pkBuildHash(distUrl)`

Computes the IPFS hash for w3pk build files from a specific URL.

**Parameters:**
- `distUrl` (string): URL to the dist folder containing build files

```typescript
import { getW3pkBuildHash } from 'w3pk';

// From unpkg CDN
const hash = await getW3pkBuildHash('https://unpkg.com/w3pk@0.7.6/dist');

// From your own CDN or server
const hash = await getW3pkBuildHash('https://cdn.example.com/w3pk/0.7.6/dist');

// From local development server
const hash = await getW3pkBuildHash('http://localhost:3000/dist');
```

### `verifyBuildHash(expectedHash)`

Verifies if the current build matches an expected hash.

**Parameters:**
- `expectedHash` (string): The IPFS hash to verify against

**Returns:**
- `Promise<boolean>`: `true` if hashes match, `false` otherwise

```typescript
import { verifyBuildHash } from 'w3pk';

const trustedHash = 'bafybeiafdhdxz3c3nhxtrhe7zpxfco5dlywpvzzscl277hojn7zosmrob4';
const isValid = await verifyBuildHash(trustedHash);

if (isValid) {
  console.log('✅ Build integrity verified!');
} else {
  console.log('⚠️  Warning: Build hash mismatch!');
}
```

### `getPackageVersion()`

Gets the current package version.

```typescript
import { getPackageVersion } from 'w3pk';

const version = getPackageVersion();
console.log('Version:', version); // => 0.7.6
```

## CLI Script

You can compute the build hash locally using the included script:

```bash
# Build the package
pnpm build

# Compute the IPFS hash
pnpm build:hash
```

Output:
```
📦 Computing IPFS hash of w3pk build...

   ✓ index.js (112424 bytes)
   ✓ index.mjs (112170 bytes)
   ✓ index.d.ts (49398 bytes)

📊 Total size: 273992 bytes

🔐 IPFS Build Hash (CIDv1):
   bafybeiafdhdxz3c3nhxtrhe7zpxfco5dlywpvzzscl277hojn7zosmrob4
   bafyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

📌 Version: x.x.x

✅ Hash computation complete!

💾 Hash saved to: dist/BUILD_HASH.txt
```

The hash is also saved to `dist/BUILD_HASH.txt` for reference.

## Integration Examples

### React Component with Onchain Verification

```typescript
import { getCurrentBuildHash } from 'w3pk';
import { ethers } from 'ethers';
import { useState, useEffect, useRef } from 'react';
import packageJson from '../package.json';

const REGISTRY_ADDRESS = '0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a';
const REGISTRY_ABI = [
  'function getCidByVersion(string version) view returns (string)',
  'function getLatestRelease() view returns (string version, string cid, uint256 timestamp)',
];

// Get installed w3pk version from package.json
const getInstalledW3pkVersion = (): string => {
  const w3pkVersion = packageJson.dependencies['w3pk'] as string;
  return w3pkVersion.replace(/^[~^]/, ''); // Remove ^ or ~ prefix
};

function BuildVerification() {
  const [buildHash, setBuildHash] = useState<string>('');
  const [trustedHash, setTrustedHash] = useState<string>('');
  const [installedVersion, setInstalledVersion] = useState<string>('');
  const [isVerified, setIsVerified] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const hasVerified = useRef(false);

  useEffect(() => {
    if (hasVerified.current) return;

    async function verify() {
      hasVerified.current = true;

      try {
        // Get current build hash
        const hash = await getCurrentBuildHash();
        setBuildHash(hash);

        // Get installed w3pk version from package.json
        const version = getInstalledW3pkVersion();
        setInstalledVersion(version);

        // Query onchain registry for the specific installed version
        const provider = new ethers.JsonRpcProvider('https://mainnet.optimism.io');
        const registry = new ethers.Contract(REGISTRY_ADDRESS, REGISTRY_ABI, provider);
        const onchainCid = await registry.getCidByVersion(`v${version}`);
        setTrustedHash(onchainCid);

        // Verify
        const verified = hash === onchainCid;
        setIsVerified(verified);

        // Log to console
        console.log('🔐 W3PK Build Verification');
        console.log('═'.repeat(50));
        console.log('Installed version:', version);
        console.log('Current build hash:', hash);
        console.log('Expected hash:    ', onchainCid);
        console.log('Verification:     ', verified ? '✅ VERIFIED' : '❌ FAILED');
        console.log('Registry contract:', REGISTRY_ADDRESS);
        console.log('Network:          OP Mainnet');
        console.log('═'.repeat(50));
      } catch (error) {
        console.error('Build verification failed:', error);
        setIsVerified(false);
      } finally {
        setLoading(false);
      }
    }

    verify();
  }, []);

  if (loading) return <div>Verifying w3pk version against onchain registry...</div>;

  return (
    <div>
      <h3>W3PK Build Verification</h3>
      <p><strong>Installed Version:</strong> v{installedVersion}</p>
      <p><strong>Local Hash:</strong> <code>{buildHash}</code></p>
      <p><strong>Onchain Hash:</strong> <code>{trustedHash}</code></p>
      <p>
        <strong>Status:</strong>{' '}
        {isVerified ? (
          <span style={{ color: 'green' }}>✅ Verified</span>
        ) : (
          <span style={{ color: 'red' }}>⚠️  Verification Failed</span>
        )}
      </p>
      {isVerified && (
        <p style={{ fontSize: '0.875rem', color: '#666' }}>
          This app is running a verified and trusted version of W3PK.
          The cryptographic build hash matches the DAO-maintained onchain registry.
        </p>
      )}
    </div>
  );
}
```

### Next.js App

```typescript
// app/api/verify-w3pk/route.ts
import { getCurrentBuildHash } from 'w3pk';
import { ethers } from 'ethers';
import { NextResponse } from 'next/server';
import packageJson from '../../../../package.json';

const REGISTRY_ADDRESS = '0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a';
const REGISTRY_ABI = ['function getCidByVersion(string version) view returns (string)'];

export async function GET() {
  try {
    const installedVersion = (packageJson.dependencies as any)['w3pk'].replace(/^[~^]/, '');
    const currentHash = await getCurrentBuildHash();

    const provider = new ethers.JsonRpcProvider('https://mainnet.optimism.io');
    const registry = new ethers.Contract(REGISTRY_ADDRESS, REGISTRY_ABI, provider);
    const onchainCid = await registry.getCidByVersion(`v${installedVersion}`);

    return NextResponse.json({
      verified: currentHash === onchainCid,
      installedVersion,
      localHash: currentHash,
      onchainCid,
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Verification failed', message: (error as Error).message },
      { status: 500 }
    );
  }
}
```

### Backend Verification with Onchain Registry (Node.js)

```typescript
// server.ts
import { getCurrentBuildHash } from 'w3pk';
import { ethers } from 'ethers';
import express from 'express';
import fs from 'fs';
import path from 'path';

const app = express();

const REGISTRY_ADDRESS = '0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a';
const REGISTRY_ABI = [
  'function getCidByVersion(string version) view returns (string)',
  'function getLatestRelease() view returns (string version, string cid, uint256 timestamp)',
];

// Get installed w3pk version from package.json
const getInstalledW3pkVersion = (): string => {
  const packageJsonPath = path.join(__dirname, '../package.json');
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
  const w3pkVersion = packageJson.dependencies['w3pk'];
  return w3pkVersion.replace(/^[~^]/, '');
};

app.get('/api/w3pk/verify', async (req, res) => {
  try {
    const currentHash = await getCurrentBuildHash();
    const installedVersion = getInstalledW3pkVersion();

    // Query onchain registry for the installed version
    const provider = new ethers.JsonRpcProvider('https://mainnet.optimism.io');
    const registry = new ethers.Contract(REGISTRY_ADDRESS, REGISTRY_ABI, provider);
    const onchainCid = await registry.getCidByVersion(`v${installedVersion}`);

    res.json({
      verified: currentHash === onchainCid,
      installedVersion,
      localHash: currentHash,
      onchainCid,
      registry: REGISTRY_ADDRESS,
      network: 'OP Mainnet',
    });
  } catch (error) {
    res.status(500).json({
      error: 'Verification failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});
```

### Startup Verification with Onchain Registry

```typescript
// main.ts
import { getCurrentBuildHash } from 'w3pk';
import { ethers } from 'ethers';
import fs from 'fs';
import path from 'path';

const REGISTRY_ADDRESS = '0xAF48C2DB335eD5da14A2C36a59Bc34407C63e01a';
const REGISTRY_ABI = [
  'function getCidByVersion(string version) view returns (string)',
];

// Get installed w3pk version from package.json
const getInstalledW3pkVersion = (): string => {
  const packageJsonPath = path.join(__dirname, '../package.json');
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
  const w3pkVersion = packageJson.dependencies['w3pk'];
  return w3pkVersion.replace(/^[~^]/, '');
};

async function verifyAndStart() {
  console.log('🔐 Verifying W3PK build against onchain registry...\n');

  try {
    // Get local build hash
    const hash = await getCurrentBuildHash();
    const installedVersion = getInstalledW3pkVersion();

    console.log('Installed version:', installedVersion);
    console.log('Local build hash: ', hash);

    // Query onchain registry for the specific installed version
    const provider = new ethers.JsonRpcProvider('https://mainnet.optimism.io');
    const registry = new ethers.Contract(REGISTRY_ADDRESS, REGISTRY_ABI, provider);
    const onchainCid = await registry.getCidByVersion(`v${installedVersion}`);

    console.log('Expected hash:    ', onchainCid);
    console.log('Registry:         ', REGISTRY_ADDRESS);
    console.log('Network:          OP Mainnet\n');

    const isValid = hash === onchainCid;

    if (!isValid) {
      console.error('❌ W3PK build verification FAILED!');
      console.error('The installed package does not match the onchain registry.');
      console.error('This could indicate a compromised package, development version, or tampering.\n');

      if (process.env.NODE_ENV === 'production') {
        process.exit(1); // Abort in production
      }
    } else {
      console.log('✅ W3PK build verified successfully against onchain registry\n');
    }
  } catch (error) {
    console.error('Build verification error:', error);

    if (process.env.NODE_ENV === 'production') {
      process.exit(1); // Fail secure in production
    }
  }

  // Continue with app initialization...
  startApp();
}

verifyAndStart();
```

## Security Best Practices

1. **Use onchain registry**: Query the DAO-maintained registry on OP Mainnet as the source of truth
2. **Verify on startup**: Check the build hash when your application initializes
3. **Use HTTPS**: Always fetch build files over HTTPS to prevent MITM attacks
4. **Multiple RPC endpoints**: Use reliable RPC providers for onchain queries
5. **Fail secure**: In production, consider failing to start if verification fails
6. **Cache verification results**: Cache onchain query results to reduce RPC calls

## How It Works

The build verification system:

1. Fetches the three main build files: `index.js`, `index.mjs`, and `index.d.ts`
2. Concatenates them in order
3. Computes a SHA-256 hash of the concatenated data
4. Formats the hash as an IPFS CIDv1 using:
   - Multihash format (0x12 for SHA-256, 0x20 for 32 bytes)
   - CIDv1 format (0x01 for version, 0x70 for dag-pb codec)
   - Base32 encoding (RFC 4648)

The resulting hash is deterministic and can be independently verified.

## Troubleshooting

### Hash Mismatch

If you get a hash mismatch:

1. **Check version**: Ensure you're comparing the same version
2. **Check source**: Different CDNs may serve different builds
3. **Clear cache**: Browser or CDN caching might serve old files
4. **Verify integrity**: The package may have been tampered with

### Network Errors

If fetching fails:

1. **Check connectivity**: Ensure you can reach the CDN
2. **Check CORS**: Browser may block cross-origin requests
3. **Use proxy**: Consider proxying requests through your backend
4. **Local verification**: Use the CLI script for local builds

## See Also

- [Security Documentation](./SECURITY.md)
- [API Reference](./API_REFERENCE.md)
- [Examples](/examples/verify-build-hash.ts)
