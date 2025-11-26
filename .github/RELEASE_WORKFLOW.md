# Release Workflow with Build Verification

Quick reference for creating a new w3pk release with build verification.

## Important Notes

⚠️ **The build hash in README.md should ONLY be updated when publishing to npm.**

- If you improve code and merge to main without releasing → **Don't update README hash**
- The README hash should always match the **latest published npm version**
- Users need to verify the package they install from npm, not git commits

## Pre-Release Checklist

- [ ] All tests passing
- [ ] CHANGELOG.md updated
- [ ] Version bumped in package.json
- [ ] Code reviewed and merged to main

## Release Steps

### 1. Build and Compute Hash

```bash
# Clean build
pnpm build

# Compute IPFS hash
pnpm build:hash
```

This will output the build hash and save it to `dist/BUILD_HASH.txt`.

**Example output:**
```
🔐 IPFS Build Hash (CIDv1):
   bafybeif5vae62gg5sj3d2nzieh4tk3rgqozsduhlwm7dqk4g3ba7bhr5tm
```

### 2. Update README.md

⚠️ **ONLY do this when publishing to npm!**

Update the "Security & Verification" section in README.md:

```markdown
### Current Build Hash (v0.7.7)  # <- Update version to match package.json

```
bafybeif5vae62gg5sj3d2nzieh4tk3rgqozsduhlwm7dqk4g3ba7bhr5tm  # <- Update hash from build:hash output
```
```

### 3. Generate Release Notes

```bash
pnpm release:notes
```

This creates `.github/release-notes-addon.md` with the verification section pre-filled.

### 4. Commit Changes

```bash
git add README.md
git commit -m "chore: update build hash for v0.7.7"
git push
```

### 5. Create GitHub Release

1. Go to: https://github.com/w3hc/w3pk/releases/new
2. Click "Auto-generate release notes" (or write your own)
3. **Append** the content from `.github/release-notes-addon.md` to the auto-generated notes
4. Publish release

### 6. Publish to npm

```bash
pnpm publish
```

The `prepublishOnly` script will automatically run the build.

### 7. Update On-Chain Registry (Future)

Once the DAO registry is deployed:

```bash
# Submit hash to DAO for approval
# Details TBD
```

## Verification Checklist

After publishing, verify the hash appears in all locations:

- [ ] GitHub release notes
- [ ] npm package page (via README)
- [ ] `dist/BUILD_HASH.txt` in published package
- [ ] On-chain registry (when available)

All sources should show the same hash!

## Quick Commands Reference

```bash
# Full release workflow
pnpm build                    # Build package
pnpm build:hash              # Compute hash
pnpm release:notes           # Generate release notes section
# ... update README.md ...
# ... create GitHub release ...
pnpm publish                 # Publish to npm

# Verification
pnpm tsx examples/verify-build-hash.ts  # Test verification
```

## Workflows

### Publishing a New Version (with hash update)

```bash
# 1. Bump version
npm version patch  # or minor/major

# 2. Build and compute hash
pnpm build
pnpm build:hash

# 3. Update README.md with new hash
# Edit README.md "Security & Verification" section

# 4. Generate release notes
pnpm release:notes

# 5. Commit version bump + hash update
git add package.json README.md
git commit -m "chore: release v0.7.7"
git push

# 6. Create GitHub release (paste release notes)
# 7. Publish to npm
pnpm publish
```

### Regular Development (NO hash update)

```bash
# Make improvements, fix bugs, etc.
git add .
git commit -m "feat: add cool feature"
git push

# Create PR, merge to main
# ❌ DO NOT update README hash
# ❌ DO NOT update version
# The hash still points to the npm version
```

## Troubleshooting

**Hash doesn't match after rebuild?**
- Make sure you're on the exact same commit
- Check that dependencies are the same (`pnpm install --frozen-lockfile`)
- Verify Node version matches

**Release notes script fails?**
- Make sure you ran `pnpm build:hash` first
- Check that `dist/BUILD_HASH.txt` exists

**README hash different from current code?**
- ✅ This is normal if code was merged but not released
- ✅ README hash should match the latest **npm package**, not git
- ❌ Only update README hash when publishing to npm

## Notes

- The build hash is deterministic - same code = same hash
- Users verify the **npm package**, not git commits
- Multi-source verification provides maximum security
- On-chain storage adds immutability layer
- README hash = published version, not current git HEAD
