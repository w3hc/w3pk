/**
 * Generate GitHub release notes section with build verification info
 * Usage: pnpm release:notes
 */

import fs from 'fs';
import path from 'path';

async function generateReleaseNotes() {
  // Read package.json for version
  const packageJson = JSON.parse(
    fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf-8')
  );
  const version = packageJson.version;

  // Read build hash
  const hashFilePath = path.join(process.cwd(), 'dist', 'BUILD_HASH.txt');

  if (!fs.existsSync(hashFilePath)) {
    console.error('❌ Error: BUILD_HASH.txt not found.');
    console.error('   Run `pnpm build && pnpm build:hash` first.');
    process.exit(1);
  }

  const buildHash = fs.readFileSync(hashFilePath, 'utf-8').trim();

  // Generate release notes
  const releaseNotes = `## 🔐 Build Verification

**IPFS CIDv1 Hash:**
\`\`\`
${buildHash}
\`\`\`

### Verify This Release

**Option 1: Using w3pk SDK**
\`\`\`typescript
import { verifyBuildHash } from 'w3pk'

const TRUSTED_HASH = '${buildHash}'
const isValid = await verifyBuildHash(TRUSTED_HASH)

if (isValid) {
  console.log('✅ Build integrity verified!')
} else {
  console.error('⚠️ Build verification failed!')
}
\`\`\`

**Option 2: Build Locally**
\`\`\`bash
git clone https://github.com/w3hc/w3pk.git
cd w3pk
git checkout v${version}
pnpm install
pnpm build
pnpm build:hash
# Should output: ${buildHash}
\`\`\`

**Option 3: Compare Multiple Sources**
\`\`\`bash
# Check hash from npm package
npm view w3pk@${version} dist.tarball | xargs curl -s | tar -xz
cat package/dist/BUILD_HASH.txt
# Should match: ${buildHash}
\`\`\`

### Multi-Source Verification

For maximum security, verify the hash from multiple sources:

1. ✅ **This GitHub release** (you are here)
2. ✅ **npm README**: https://www.npmjs.com/package/w3pk
3. ✅ **On-chain registry**: Coming soon - DAO-maintained hash registry
4. ✅ **Local build**: Clone repo and build yourself

All sources should report the same hash: \`${buildHash}\`

### What is Build Verification?

W3pk uses IPFS CIDv1 hashing to create a unique, deterministic fingerprint of each build. This allows you to:

- Verify package integrity
- Detect tampering or supply chain attacks
- Ensure reproducible builds
- Trust what you're installing

See the [Build Verification Guide](./docs/BUILD_VERIFICATION.md) for complete documentation.
`;

  // Save to file
  const outputPath = path.join(process.cwd(), '.github', 'release-notes-addon.md');
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, releaseNotes);

  console.log('✅ Release notes generated!\n');
  console.log('📄 Saved to:', outputPath);
  console.log('\n📋 Copy this content and append to your auto-generated GitHub release notes:');
  console.log('\n' + '='.repeat(80));
  console.log(releaseNotes);
  console.log('='.repeat(80));
}

generateReleaseNotes().catch((error) => {
  console.error('❌ Error:', error);
  process.exit(1);
});
