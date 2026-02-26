/**
 * Example: Verify w3pk Build Hash
 *
 * This example demonstrates how to compute and verify the IPFS hash
 * of the w3pk package build in your application.
 *
 * This is useful for:
 * - Verifying package integrity
 * - Ensuring reproducible builds
 * - Security auditing
 * - Supply chain verification
 */

import {
  getCurrentBuildHash,
  verifyBuildHash,
  getW3pkBuildHash,
  getPackageVersion,
} from "w3pk";

async function example1_GetCurrentBuildHash() {
  console.log("📦 Example 1: Get Current Build Hash\n");

  try {
    // Get the IPFS hash of the currently installed w3pk version
    const hash = await getCurrentBuildHash();
    const version = getPackageVersion();

    console.log(`Version: ${version}`);
    console.log(`Build Hash: ${hash}`);
    console.log(`\n✅ Successfully computed build hash!`);
  } catch (error) {
    console.error("❌ Error:", error);
  }
}

async function example2_VerifyBuildHash() {
  console.log("\n📋 Example 2: Verify Build Hash\n");

  try {
    // Known hash from a trusted source (e.g., GitHub release notes)
    const trustedHash =
      "bafybeiafdhdxz3c3nhxtrhe7zpxfco5dlywpvzzscl277hojn7zosmrob4";

    console.log(`Verifying against trusted hash: ${trustedHash}`);

    const isValid = await verifyBuildHash(trustedHash);

    if (isValid) {
      console.log("✅ Build integrity verified! Package is authentic.");
    } else {
      console.log(
        "⚠️  Warning: Build hash mismatch! Package may be compromised.",
      );
    }
  } catch (error) {
    console.error("❌ Error:", error);
  }
}

async function example3_ComputeHashFromCDN() {
  console.log("\n🌐 Example 3: Compute Hash from CDN\n");

  try {
    // Compute hash for a specific version from unpkg CDN
    const version = "0.7.6";
    const hash = await getW3pkBuildHash(
      `https://unpkg.com/w3pk@${version}/dist`,
    );

    console.log(`Version: ${version}`);
    console.log(`CDN Build Hash: ${hash}`);
    console.log(`\n✅ Successfully verified CDN build!`);
  } catch (error) {
    console.error("❌ Error:", error);
  }
}

async function example4_CompareLocalAndCDN() {
  console.log("\n🔄 Example 4: Compare Local and CDN Builds\n");

  try {
    const version = getPackageVersion();

    console.log("Computing hashes...");
    const localHash = await getCurrentBuildHash();
    const cdnHash = await getW3pkBuildHash(
      `https://unpkg.com/w3pk@${version}/dist`,
    );

    console.log(`\nLocal build hash:  ${localHash}`);
    console.log(`CDN build hash:    ${cdnHash}`);

    if (localHash === cdnHash) {
      console.log("\n✅ Local and CDN builds match!");
    } else {
      console.log("\n⚠️  Local and CDN builds differ!");
    }
  } catch (error) {
    console.error("❌ Error:", error);
  }
}

// Usage in a web application (React, Vue, etc.)
function WebAppExample() {
  return `
// In your React/Vue/etc. component:

import { getCurrentBuildHash, verifyBuildHash } from 'w3pk';
import { useState, useEffect } from 'react';

function BuildVerification() {
  const [buildHash, setBuildHash] = useState<string>('');
  const [isVerified, setIsVerified] = useState<boolean | null>(null);

  useEffect(() => {
    async function verify() {
      try {
        // Get current build hash
        const hash = await getCurrentBuildHash();
        setBuildHash(hash);

        // Verify against known good hash from your backend/config
        const trustedHash = await fetch('/api/trusted-hash').then(r => r.text());
        const verified = await verifyBuildHash(trustedHash);
        setIsVerified(verified);
      } catch (error) {
        console.error('Build verification failed:', error);
        setIsVerified(false);
      }
    }

    verify();
  }, []);

  return (
    <div>
      <h2>Build Verification</h2>
      <p>Build Hash: {buildHash || 'Computing...'}</p>
      {isVerified === null && <p>Verifying...</p>}
      {isVerified === true && <p style={{color: 'green'}}>✅ Verified</p>}
      {isVerified === false && <p style={{color: 'red'}}>⚠️ Verification Failed</p>}
    </div>
  );
}
  `;
}

// Run all examples
async function runAllExamples() {
  console.log("🔐 W3PK Build Hash Verification Examples\n");
  console.log("=".repeat(50));

  await example1_GetCurrentBuildHash();
  await example2_VerifyBuildHash();
  await example3_ComputeHashFromCDN();
  await example4_CompareLocalAndCDN();

  console.log("\n" + "=".repeat(50));
  console.log("\n📝 Web App Integration Example:");
  console.log(WebAppExample());
}

// Run if executed directly
if (require.main === module) {
  runAllExamples().catch(console.error);
}

export { runAllExamples };
