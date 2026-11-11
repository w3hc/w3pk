/**
 * ERC-5564 Stealth Address Compliance Tests
 * Tests the implementation against the ERC-5564 standard
 */

import { ethers } from "ethers";
import {
  deriveStealthKeys,
  generateStealthAddress,
  checkStealthAddress,
  computeStealthPrivateKey,
} from "../src/stealth/crypto";
import { StealthAddressModule } from "../src/stealth";

console.log("\n🧪 ERC-5564 Stealth Address Tests\n");
console.log("=".repeat(50));

// Test 1: Stealth Meta-Address Format
console.log("\n1. Testing Stealth Meta-Address Format (ERC-5564)");
console.log("-".repeat(50));

const testMnemonic =
  "test test test test test test test test test test test junk";
const keys = deriveStealthKeys(testMnemonic);

console.log("✓ Stealth meta-address generated");
console.log(`  Length: ${keys.stealthMetaAddress.length} characters`);
console.log(`  Expected: ${2 + 66 * 2} characters (0x + 66 bytes hex)`);

// Verify format: 0x + 33 bytes + 33 bytes = 134 chars
if (keys.stealthMetaAddress.length !== 134) {
  throw new Error(
    `Invalid stealth meta-address length: ${keys.stealthMetaAddress.length}`
  );
}

console.log("✓ Meta-address has correct length (66 bytes)");

// Verify spending and viewing public keys are compressed (33 bytes each)
if (keys.spendingPubKey.length !== 68) {
  // 0x + 33 bytes * 2
  throw new Error(`Invalid spending public key length: ${keys.spendingPubKey.length}`);
}
if (keys.viewingPubKey.length !== 68) {
  throw new Error(`Invalid viewing public key length: ${keys.viewingPubKey.length}`);
}

console.log("✓ Spending public key is compressed (33 bytes)");
console.log("✓ Viewing public key is compressed (33 bytes)");

console.log("\nKeys:");
console.log(`  Stealth Meta-Address: ${keys.stealthMetaAddress}`);
console.log(`  Spending PubKey: ${keys.spendingPubKey}`);
console.log(`  Viewing PubKey:  ${keys.viewingPubKey}`);

// Test 2: Generate Stealth Address
console.log("\n2. Testing Stealth Address Generation (Sender)");
console.log("-".repeat(50));

const stealthResult = generateStealthAddress(keys.stealthMetaAddress);

console.log("✓ Stealth address generated");
console.log(`  Stealth Address: ${stealthResult.stealthAddress}`);
console.log(`  Ephemeral PubKey: ${stealthResult.ephemeralPubKey}`);
console.log(`  View Tag: ${stealthResult.viewTag}`);

// Verify stealth address is valid Ethereum address
if (!ethers.isAddress(stealthResult.stealthAddress)) {
  throw new Error("Invalid stealth address format");
}
console.log("✓ Stealth address is valid Ethereum address");

// Verify ephemeral public key is compressed
if (stealthResult.ephemeralPubKey.length !== 68) {
  throw new Error("Ephemeral public key must be compressed (33 bytes)");
}
console.log("✓ Ephemeral public key is compressed");

// Verify view tag is 1 byte
if (stealthResult.viewTag.length !== 4) {
  // 0x + 1 byte hex
  throw new Error(`View tag must be 1 byte, got: ${stealthResult.viewTag}`);
}
console.log("✓ View tag is 1 byte");

// Test 3: Check Stealth Address (Recipient)
console.log("\n3. Testing Stealth Address Checking (Recipient)");
console.log("-".repeat(50));

const checkResult = checkStealthAddress(
  keys.viewingKey,
  keys.spendingPubKey,
  stealthResult.ephemeralPubKey,
  stealthResult.stealthAddress,
  stealthResult.viewTag
);

if (!checkResult.isForUser) {
  throw new Error("Failed to recognize own stealth address");
}
console.log("✓ Recipient correctly identified their stealth address");

if (
  checkResult.stealthAddress?.toLowerCase() !==
  stealthResult.stealthAddress.toLowerCase()
) {
  throw new Error("Stealth address mismatch");
}
console.log("✓ Stealth addresses match");

// Test 4: View Tag Filtering
console.log("\n4. Testing View Tag Optimization");
console.log("-".repeat(50));

// Test with wrong view tag (should fail fast)
const wrongViewTag = stealthResult.viewTag === "0xff" ? "0x00" : "0xff";
const wrongTagResult = checkStealthAddress(
  keys.viewingKey,
  keys.spendingPubKey,
  stealthResult.ephemeralPubKey,
  stealthResult.stealthAddress,
  wrongViewTag
);

if (wrongTagResult.isForUser) {
  throw new Error("Should reject announcement with wrong view tag");
}
console.log("✓ View tag filtering works (rejected wrong tag)");

// Test without view tag (should still work but slower)
const noTagResult = checkStealthAddress(
  keys.viewingKey,
  keys.spendingPubKey,
  stealthResult.ephemeralPubKey,
  stealthResult.stealthAddress
);

if (!noTagResult.isForUser) {
  throw new Error("Should still work without view tag");
}
console.log("✓ Works without view tag (fallback mode)");

// Test 5: Compute Stealth Private Key
console.log("\n5. Testing Stealth Private Key Computation");
console.log("-".repeat(50));

const stealthPrivateKey = computeStealthPrivateKey(
  keys.viewingKey,
  keys.spendingKey,
  stealthResult.ephemeralPubKey
);

console.log(`✓ Stealth private key computed`);

// Verify the private key derives to the stealth address
const stealthWallet = new ethers.Wallet(stealthPrivateKey);
if (
  stealthWallet.address.toLowerCase() !== stealthResult.stealthAddress.toLowerCase()
) {
  throw new Error(
    `Private key mismatch:\n  Expected: ${stealthResult.stealthAddress}\n  Got: ${stealthWallet.address}`
  );
}
console.log("✓ Private key correctly derives to stealth address");
console.log(`  Address: ${stealthWallet.address}`);

// Test 6: Multiple Stealth Addresses
console.log("\n6. Testing Multiple Stealth Address Generation");
console.log("-".repeat(50));

const addresses = new Set<string>();
for (let i = 0; i < 5; i++) {
  const result = generateStealthAddress(keys.stealthMetaAddress);
  addresses.add(result.stealthAddress);

  // Verify recipient can identify each one
  const check = checkStealthAddress(
    keys.viewingKey,
    keys.spendingPubKey,
    result.ephemeralPubKey,
    result.stealthAddress,
    result.viewTag
  );

  if (!check.isForUser) {
    throw new Error(`Failed to identify stealth address #${i + 1}`);
  }
}

if (addresses.size !== 5) {
  throw new Error("Generated duplicate stealth addresses");
}
console.log("✓ Generated 5 unique stealth addresses");
console.log("✓ Recipient identified all 5 addresses");

// Test 7: Different Users Cannot Identify Each Other's Addresses
console.log("\n7. Testing Privacy (Cross-User Check)");
console.log("-".repeat(50));

const alice = deriveStealthKeys(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
);
const bob = deriveStealthKeys(
  "legal winner thank year wave sausage worth useful legal winner thank yellow"
);

const aliceStealthResult = generateStealthAddress(alice.stealthMetaAddress);

// Bob tries to identify Alice's stealth address
const bobCheck = checkStealthAddress(
  bob.viewingKey,
  bob.spendingPubKey,
  aliceStealthResult.ephemeralPubKey,
  aliceStealthResult.stealthAddress,
  aliceStealthResult.viewTag
);

if (bobCheck.isForUser) {
  throw new Error("Bob should not be able to identify Alice's stealth address");
}
console.log("✓ Bob cannot identify Alice's stealth address");

// Alice can identify her own address
const aliceCheck = checkStealthAddress(
  alice.viewingKey,
  alice.spendingPubKey,
  aliceStealthResult.ephemeralPubKey,
  aliceStealthResult.stealthAddress,
  aliceStealthResult.viewTag
);

if (!aliceCheck.isForUser) {
  throw new Error("Alice should be able to identify her own stealth address");
}
console.log("✓ Alice can identify her own stealth address");

// Test 8: End-to-End Flow
console.log("\n8. Testing End-to-End Flow");
console.log("-".repeat(50));

// Sender side (knows only recipient's stealth meta-address)
console.log("Sender:");
const recipientMetaAddress = alice.stealthMetaAddress;
const announcement = generateStealthAddress(recipientMetaAddress);
console.log(`  ✓ Generated stealth address: ${announcement.stealthAddress}`);
console.log(`  ✓ Ephemeral pubkey: ${announcement.ephemeralPubKey}`);
console.log(`  ✓ View tag: ${announcement.viewTag}`);

// Recipient side (scans announcements)
console.log("\nRecipient:");
const recipientCheck = checkStealthAddress(
  alice.viewingKey,
  alice.spendingPubKey,
  announcement.ephemeralPubKey,
  announcement.stealthAddress,
  announcement.viewTag
);

if (!recipientCheck.isForUser) {
  throw new Error("Recipient failed to identify announcement");
}
console.log("  ✓ Identified announcement as theirs");

const recipientPrivKey = computeStealthPrivateKey(
  alice.viewingKey,
  alice.spendingKey,
  announcement.ephemeralPubKey
);

const recipientWallet = new ethers.Wallet(recipientPrivKey);
console.log(`  ✓ Computed private key for spending`);
console.log(`  ✓ Can spend from: ${recipientWallet.address}`);

if (recipientWallet.address.toLowerCase() !== announcement.stealthAddress.toLowerCase()) {
  throw new Error("Address mismatch in end-to-end test");
}

// Test 9: Scanning Efficiency
console.log("\n9. Testing Scanning Efficiency (View Tags)");
console.log("-".repeat(50));

const announcements = [];
for (let i = 0; i < 100; i++) {
  const result = generateStealthAddress(alice.stealthMetaAddress);
  announcements.push(result);
}

// Add one announcement for Bob
const bobAnnouncement = generateStealthAddress(bob.stealthMetaAddress);
announcements.push(bobAnnouncement);

console.log(`Generated ${announcements.length} announcements`);

let viewTagFiltered = 0;
let fullCheckCount = 0;

for (const ann of announcements) {
  const result = checkStealthAddress(
    bob.viewingKey,
    bob.spendingPubKey,
    ann.ephemeralPubKey,
    ann.stealthAddress,
    ann.viewTag
  );

  if (!result.isForUser) {
    viewTagFiltered++;
  } else {
    fullCheckCount++;
  }
}

console.log(`✓ View tag filtered ${viewTagFiltered}/${announcements.length} announcements`);
console.log(`✓ Found ${fullCheckCount} matching announcement(s)`);

if (fullCheckCount !== 1) {
  throw new Error(`Expected to find 1 announcement, found ${fullCheckCount}`);
}

const expectedFilterRate = (viewTagFiltered / announcements.length) * 100;
console.log(`✓ Filter rate: ${expectedFilterRate.toFixed(2)}% (expected ~99%)`);

// Test 10: Cross-implementation vectors
// Generated with @scopelift/stealth-address-sdk 1.0.0-beta.5 (generateStealthAddress
// with a fixed ephemeral private key, then computeStealthKey), which hashes the
// shared secret as a 33-byte compressed point.
console.log("\n10. Testing ScopeLift SDK Vectors");
console.log("-".repeat(50));

const scopeLiftVectors = [
  {
    mnemonic: testMnemonic,
    ephemeralPrivateKey: "0x" + "11".repeat(32),
    stealthMetaAddress:
      "0x03f2e32f9a060b8fe18736f5c4da328265d9d29ac13d5fed45649700a9c5f2cdca03037f40766fbc839e1b69a19685ce42f967a74a87d597a52ef525810484908b33",
    ephemeralPubKey:
      "0x034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
    viewTag: "0x13",
    stealthAddress: "0xB1A9e94E1f0B3C9940EFE3dFC3D5644eCB6b731d",
    stealthPrivateKey:
      "0x0b68fea69985b842b3f31c3e38a1ab03cb44abd441586f20d2e770beb874ee96",
  },
  {
    mnemonic:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    ephemeralPrivateKey: "0x" + "22".repeat(32),
    stealthMetaAddress:
      "0x0226e593ae184aef22184e8d139b9189715020553c5a5f2f83aa8517fb9435fa2d038ccc8186e5933e845afd096cc6d3f2fdb25fbe4db4864b944619afa8e4e8bd5e",
    ephemeralPubKey:
      "0x02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
    viewTag: "0xdc",
    stealthAddress: "0x20952ce8049CF0d33EAa974da5633E6123069dc5",
    stealthPrivateKey:
      "0xbd7830020c1fb8e2614286a5229d7a3d3350c6f7bb0db49e7cfe22f41dce020c",
  },
];

for (const vector of scopeLiftVectors) {
  const vectorKeys = deriveStealthKeys(vector.mnemonic);
  if (vectorKeys.stealthMetaAddress !== vector.stealthMetaAddress) {
    throw new Error(`Meta-address mismatch: ${vectorKeys.stealthMetaAddress}`);
  }
  if (
    new ethers.Wallet(vector.ephemeralPrivateKey).signingKey.compressedPublicKey !==
    vector.ephemeralPubKey
  ) {
    throw new Error("Ephemeral public key mismatch");
  }

  const vectorCheck = checkStealthAddress(
    vectorKeys.viewingKey,
    vectorKeys.spendingPubKey,
    vector.ephemeralPubKey,
    vector.stealthAddress,
    vector.viewTag
  );
  if (!vectorCheck.isForUser || vectorCheck.stealthAddress !== vector.stealthAddress) {
    throw new Error(`ScopeLift vector not recognized: ${vector.stealthAddress}`);
  }

  const vectorPrivKey = computeStealthPrivateKey(
    vectorKeys.viewingKey,
    vectorKeys.spendingKey,
    vector.ephemeralPubKey
  );
  if (vectorPrivKey !== vector.stealthPrivateKey) {
    throw new Error(`Stealth private key mismatch: ${vectorPrivKey}`);
  }
  if (new ethers.Wallet(vectorPrivKey).address !== vector.stealthAddress) {
    throw new Error("Stealth private key does not control the stealth address");
  }
}
console.log("✓ View tags, stealth addresses and keys match ScopeLift's SDK");

const uncompressedVector = checkStealthAddress(
  keys.viewingKey,
  keys.spendingPubKey,
  scopeLiftVectors[0].ephemeralPubKey,
  "0xe313D64b394524d4f69388951B4E030d6f99b82c"
);
if (uncompressedVector.isForUser) {
  throw new Error("The uncompressed shared-secret address must not be recognized");
}
console.log("✓ The uncompressed shared-secret address is not recognized");

(async () => {
  // Test: getKeys() never returns the spending private key
  console.log("\nTesting StealthAddressModule.getKeys()");
  console.log("-".repeat(50));

  const authCalls: (boolean | undefined)[] = [];
  const module = new StealthAddressModule({}, async (requireAuth) => {
    authCalls.push(requireAuth);
    return testMnemonic;
  });
  const moduleKeys = await module.getKeys();
  if ("spendingKey" in moduleKeys) {
    throw new Error("getKeys() must not return the spending private key");
  }
  if (
    moduleKeys.stealthMetaAddress !== keys.stealthMetaAddress ||
    moduleKeys.viewingKey !== keys.viewingKey ||
    moduleKeys.spendingPubKey !== keys.spendingPubKey ||
    moduleKeys.viewingPubKey !== keys.viewingPubKey
  ) {
    throw new Error("getKeys() should return the meta-address, public keys and viewing key");
  }
  if (JSON.stringify(moduleKeys).includes(keys.spendingKey.slice(2))) {
    throw new Error("getKeys() output contains the spending private key");
  }
  console.log("✓ getKeys() omits the spending private key");

  const sent = generateStealthAddress(keys.stealthMetaAddress);
  const announcement = {
    stealthAddress: sent.stealthAddress,
    ephemeralPublicKey: sent.ephemeralPubKey,
    viewTag: sent.viewTag,
  };
  const stealthKey = computeStealthPrivateKey(
    keys.viewingKey,
    keys.spendingKey,
    sent.ephemeralPubKey
  ).slice(2);

  console.log("\nTesting StealthAddressModule.parseAnnouncement() and scanAnnouncements()");
  console.log("-".repeat(50));

  const parsed = await module.parseAnnouncement(announcement);
  if (!parsed.isForUser || parsed.stealthAddress !== sent.stealthAddress) {
    throw new Error("parseAnnouncement() should find the stealth address");
  }
  if ("stealthPrivateKey" in parsed || JSON.stringify(parsed).includes(stealthKey)) {
    throw new Error("parseAnnouncement() must not return the stealth private key");
  }
  console.log("✓ parseAnnouncement() returns the stealth address and no private key");

  const scanned = await module.scanAnnouncements([
    announcement,
    { ...announcement, stealthAddress: ethers.Wallet.createRandom().address },
  ]);
  if (scanned.length !== 1 || scanned[0].stealthAddress !== sent.stealthAddress) {
    throw new Error("scanAnnouncements() should return only the user's announcement");
  }
  if (JSON.stringify(scanned).includes(stealthKey)) {
    throw new Error("scanAnnouncements() must not return the stealth private key");
  }
  console.log("✓ scanAnnouncements() returns no private key");

  console.log("\nTesting StealthAddressModule.signTransaction()");
  console.log("-".repeat(50));

  const tx = {
    to: ethers.Wallet.createRandom().address,
    value: 1000n,
    data: "0x1234",
    chainId: 11155111,
    nonce: 7,
    gasLimit: 30000n,
    maxFeePerGas: 2000000000n,
    maxPriorityFeePerGas: 1000000000n,
  };
  authCalls.length = 0;
  const signed = await module.signTransaction(announcement, tx);
  const decoded = ethers.Transaction.from(signed);
  if (
    decoded.from !== sent.stealthAddress ||
    decoded.to !== tx.to ||
    decoded.value !== tx.value ||
    decoded.data !== tx.data ||
    decoded.chainId !== BigInt(tx.chainId) ||
    decoded.nonce !== tx.nonce ||
    decoded.gasLimit !== tx.gasLimit ||
    decoded.maxFeePerGas !== tx.maxFeePerGas ||
    decoded.maxPriorityFeePerGas !== tx.maxPriorityFeePerGas ||
    decoded.type !== 2
  ) {
    throw new Error("signTransaction() should sign the transaction from the stealth address");
  }
  console.log("✓ signTransaction() signs from the stealth address");

  if (authCalls.length !== 1 || authCalls[0] !== true) {
    throw new Error("signTransaction() should require a fresh passkey assertion");
  }
  console.log("✓ signTransaction() requires a fresh passkey assertion");

  const other = deriveStealthKeys(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  );
  const notMine = generateStealthAddress(other.stealthMetaAddress);
  let refused = false;
  try {
    await module.signTransaction(
      {
        stealthAddress: notMine.stealthAddress,
        ephemeralPublicKey: notMine.ephemeralPubKey,
        viewTag: notMine.viewTag,
      },
      tx
    );
  } catch (error: any) {
    refused =
      error.code === "STEALTH_SIGN_ERROR" &&
      error.originalError?.message === "Announcement is not for this user";
  }
  if (!refused) {
    throw new Error("signTransaction() should refuse an announcement that isn't for the user");
  }
  console.log("✓ signTransaction() refuses an announcement that isn't for the user");

  console.log("\n" + "=".repeat(50));
  console.log("✅ All ERC-5564 compliance tests passed!");
  console.log("=".repeat(50) + "\n");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
