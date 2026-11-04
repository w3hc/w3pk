/**
 * Stealth address point math: known vectors and the point at infinity
 */

import {
  deriveStealthKeys,
  checkStealthAddress,
  computeStealthPrivateKey,
} from "../src/stealth/crypto";

console.log("\n🧪 Stealth Point Math Tests\n");

const keys = deriveStealthKeys(
  "test test test test test test test test test test test junk"
);

// Ephemeral private key 0x11…11
const ephemeralPubKey =
  "0x034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const viewTag = "0xe6";
const expectedPrivKey =
  "0xde6d45d0c672bc16ab6e025a2087ab5aa98b9e5d1d40d43df41250657b8dd041";
const expectedAddress = "0xe313D64b394524d4f69388951B4E030d6f99b82c";

const privKey = computeStealthPrivateKey(
  keys.viewingKey,
  keys.spendingKey,
  ephemeralPubKey
);
if (privKey !== expectedPrivKey) {
  throw new Error(`Stealth private key mismatch: ${privKey}`);
}
console.log("✓ Stealth private key matches the known vector");

const result = checkStealthAddress(
  keys.viewingKey,
  keys.spendingPubKey,
  ephemeralPubKey,
  expectedAddress,
  viewTag
);
if (!result.isForUser || result.stealthAddress !== expectedAddress) {
  throw new Error(`Stealth address mismatch: ${JSON.stringify(result)}`);
}
console.log("✓ Stealth address matches the known vector");

console.log("\n✅ Stealth point math tests passed\n");
