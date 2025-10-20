/**
 * EIP-7702 SDK method tests
 */

import { createWeb3Passkey } from "../src/index";

async function testSDKSupportsEIP7702() {
  console.log("\n🧪 Testing w3pk.supportsEIP7702()...");

  const w3pk = createWeb3Passkey({
    apiBaseUrl: "https://webauthn.w3hc.org",
  });

  // Test supported networks (cached - instant)
  const supportedChains = [
    { id: 1, name: "Ethereum Mainnet" },
    { id: 11155111, name: "Sepolia" },
    { id: 10, name: "Optimism" },
    { id: 8453, name: "Base" },
    { id: 42161, name: "Arbitrum One" },
    { id: 137, name: "Polygon" },
    { id: 84532, name: "Base Sepolia" },
  ];

  console.log("\n✅ Testing cached supported chains:");
  for (const { id, name } of supportedChains) {
    const supported = await w3pk.supportsEIP7702(id);
    if (!supported) {
      throw new Error(`❌ ${name} (${id}) should support EIP-7702!`);
    }
    console.log(`  ✓ ${name} (${id})`);
  }

  // Count total supported chains
  const sampleChains = [1, 10, 8453, 42161, 57073, 100, 42220, 137, 11155111];
  let totalSupported = 0;
  for (const id of sampleChains) {
    if (await w3pk.supportsEIP7702(id)) {
      totalSupported++;
    }
  }

  console.log(`\n✅ Verified ${totalSupported} sample chains support EIP-7702`);
  console.log("✅ w3pk.supportsEIP7702() working correctly");
}

async function runTests() {
  console.log("=================================");
  console.log("🚀 EIP-7702 SDK Method Tests");
  console.log("=================================");

  try {
    await testSDKSupportsEIP7702();

    console.log("\n=================================");
    console.log("✅ All tests passed!");
    console.log("=================================\n");
  } catch (error) {
    console.error("\n=================================");
    console.error("❌ Tests failed!");
    console.error("=================================");
    console.error(error);
    process.exit(1);
  }
}

runTests();
