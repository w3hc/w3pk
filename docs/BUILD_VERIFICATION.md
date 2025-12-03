# Build Verification

W3PK provides utilities to compute and verify IPFS hashes of package builds, enabling reproducible builds and supply chain verification.

## Overview

The build verification system computes an IPFS CIDv1 hash from the concatenated main build artifacts (`index.js`, `index.mjs`, `index.d.ts`). This hash can be used to:

- **Verify package integrity**: Ensure the installed package matches the published version
- **Reproducible builds**: Verify that builds produce consistent outputs
- **Security auditing**: Check that you're running the expected code
- **Supply chain verification**: Detect tampering or compromised packages

## API Reference

### `getCurrentBuildHash()`

Computes the IPFS hash for the currently installed w3pk version from the unpkg CDN.

```typescript
import { getCurrentBuildHash } from 'w3pk';

const hash = await getCurrentBuildHash();
console.log('Build hash:', hash);
// => bafybeiagxwcdquymmq6hqup45xlh25x3qrwpn3j5oj3f5t47ltzuzmzlpi
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

const trustedHash = 'bafybeiagxwcdquymmq6hqup45xlh25x3qrwpn3j5oj3f5t47ltzuzmzlpi';
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
   bafybeiagxwcdquymmq6hqup45xlh25x3qrwpn3j5oj3f5t47ltzuzmzlpi
   bafyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

📌 Version: x.x.x

✅ Hash computation complete!

💾 Hash saved to: dist/BUILD_HASH.txt
```

The hash is also saved to `dist/BUILD_HASH.txt` for reference.

## Integration Examples

### React Component

```typescript
import { getCurrentBuildHash, verifyBuildHash } from 'w3pk';
import { useState, useEffect } from 'react';

function BuildVerification() {
  const [buildHash, setBuildHash] = useState<string>('');
  const [isVerified, setIsVerified] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function verify() {
      try {
        // Get current build hash
        const hash = await getCurrentBuildHash();
        setBuildHash(hash);

        // Fetch trusted hash from your backend
        const response = await fetch('/api/w3pk/trusted-hash');
        const trustedHash = await response.text();

        // Verify
        const verified = await verifyBuildHash(trustedHash);
        setIsVerified(verified);
      } catch (error) {
        console.error('Build verification failed:', error);
        setIsVerified(false);
      } finally {
        setLoading(false);
      }
    }

    verify();
  }, []);

  if (loading) return <div>Verifying build...</div>;

  return (
    <div>
      <h3>W3PK Build Verification</h3>
      <p><strong>Hash:</strong> {buildHash}</p>
      <p>
        <strong>Status:</strong>{' '}
        {isVerified ? (
          <span style={{ color: 'green' }}>✅ Verified</span>
        ) : (
          <span style={{ color: 'red' }}>⚠️  Verification Failed</span>
        )}
      </p>
    </div>
  );
}
```

### Next.js App

```typescript
// app/page.tsx
import { getCurrentBuildHash } from 'w3pk';

export default async function Home() {
  // Compute hash at build time
  const buildHash = await getCurrentBuildHash();

  return (
    <div>
      <h1>My W3PK App</h1>
      <p>Using W3PK build: {buildHash}</p>
    </div>
  );
}
```

### Backend Verification (Node.js)

```typescript
// server.ts
import { getW3pkBuildHash } from 'w3pk';
import express from 'express';

const app = express();

// Store trusted hash (from GitHub releases, etc.)
const TRUSTED_HASH = 'bafybeiagxwcdquymmq6hqup45xlh25x3qrwpn3j5oj3f5t47ltzuzmzlpi';

app.get('/api/w3pk/verify', async (req, res) => {
  try {
    const currentHash = await getW3pkBuildHash(
      'https://unpkg.com/w3pk@0.7.6/dist'
    );

    res.json({
      verified: currentHash === TRUSTED_HASH,
      hash: currentHash,
      trustedHash: TRUSTED_HASH,
    });
  } catch (error) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

app.get('/api/w3pk/trusted-hash', (req, res) => {
  res.send(TRUSTED_HASH);
});
```

### Startup Verification

```typescript
// main.ts
import { verifyBuildHash, getCurrentBuildHash } from 'w3pk';

const TRUSTED_HASH = 'bafybeiagxwcdquymmq6hqup45xlh25x3qrwpn3j5oj3f5t47ltzuzmzlpi';

async function verifyAndStart() {
  console.log('Verifying W3PK build integrity...');

  try {
    const hash = await getCurrentBuildHash();
    console.log('Build hash:', hash);

    const isValid = await verifyBuildHash(TRUSTED_HASH);

    if (!isValid) {
      console.error('⚠️  WARNING: W3PK build verification failed!');
      console.error('The installed package does not match the trusted hash.');
      console.error('This could indicate a compromised package.');

      if (process.env.NODE_ENV === 'production') {
        process.exit(1); // Abort in production
      }
    } else {
      console.log('✅ W3PK build verified successfully');
    }
  } catch (error) {
    console.error('Build verification error:', error);
  }

  // Continue with app initialization...
  startApp();
}

verifyAndStart();
```

## Security Best Practices

1. **Store trusted hashes securely**: Keep the expected build hash in your backend or configuration, not hardcoded in client code
2. **Verify on startup**: Check the build hash when your application initializes
3. **Use HTTPS**: Always fetch build files over HTTPS to prevent MITM attacks
4. **Multiple sources**: Compare hashes from different sources (npm, CDN, GitHub releases)
5. **Fail secure**: In production, consider failing to start if verification fails

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
