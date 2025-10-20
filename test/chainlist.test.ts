/**
 * Chainlist module tests
 */

import {
  getEndpoints,
  getAllChains,
  getChainById,
  clearCache,
} from "../src/chainlist/index";

async function testGetEndpoints() {
  console.log("\n🧪 Testing getEndpoints()...");

  // Test Ethereum mainnet (chainId: 1)
  console.log("\n📡 Fetching Ethereum mainnet endpoints (chainId: 1)...");
  const ethEndpoints = await getEndpoints(1);
  console.log(`Found ${ethEndpoints.length} RPC endpoints without API keys:`);
  ethEndpoints.forEach((endpoint, i) => {
    console.log(`  ${i + 1}. ${endpoint}`);
  });

  // Verify no API key patterns
  const hasApiKeyPattern = ethEndpoints.some(
    (url) =>
      url.includes("${") ||
      url.includes("{") ||
      url.includes("<") ||
      url.toLowerCase().includes("api_key")
  );
  if (hasApiKeyPattern) {
    throw new Error("❌ Found endpoint with API key pattern!");
  }
  console.log("✅ All endpoints are API key free");

  // Verify no websocket URLs
  const hasWebsocket = ethEndpoints.some(
    (url) => url.startsWith("wss://") || url.startsWith("ws://")
  );
  if (hasWebsocket) {
    throw new Error("❌ Found websocket endpoint!");
  }
  console.log("✅ No websocket endpoints included");

  // Test Polygon (chainId: 137)
  console.log("\n📡 Fetching Polygon endpoints (chainId: 137)...");
  const polygonEndpoints = await getEndpoints(137);
  console.log(`Found ${polygonEndpoints.length} endpoints for Polygon`);

  // Test non-existent chain (using a very unlikely chain ID)
  console.log("\n📡 Testing non-existent chain (chainId: 123456789)...");
  const nonExistent = await getEndpoints(123456789);
  if (nonExistent.length !== 0) {
    console.log(`⚠️  Warning: Chain ID 123456789 exists with ${nonExistent.length} endpoints`);
  } else {
    console.log("✅ Returns empty array for non-existent chain");
  }
}

async function testGetChainById() {
  console.log("\n🧪 Testing getChainById()...");

  const ethChain = await getChainById(1);
  if (!ethChain) {
    throw new Error("❌ Should find Ethereum mainnet!");
  }
  console.log(`✅ Found chain: ${ethChain.name} (${ethChain.chainId})`);
  console.log(`   Symbol: ${ethChain.nativeCurrency.symbol}`);
  console.log(`   RPC endpoints: ${ethChain.rpc.length}`);

  const nonExistent = await getChainById(123456789);
  if (nonExistent !== undefined) {
    console.log(`⚠️  Warning: Chain ID 123456789 exists: ${nonExistent.name}`);
  } else {
    console.log("✅ Returns undefined for non-existent chain");
  }
}

async function testGetAllChains() {
  console.log("\n🧪 Testing getAllChains()...");

  const chains = await getAllChains();
  console.log(`✅ Fetched ${chains.length} chains`);

  // Verify some well-known chains exist
  const ethereum = chains.find((c) => c.chainId === 1);
  const polygon = chains.find((c) => c.chainId === 137);
  const optimism = chains.find((c) => c.chainId === 10);

  if (!ethereum || !polygon || !optimism) {
    throw new Error("❌ Missing well-known chains!");
  }
  console.log("✅ Found well-known chains (Ethereum, Polygon, Optimism)");
}

async function testCaching() {
  console.log("\n🧪 Testing caching mechanism...");

  clearCache();
  console.log("✅ Cache cleared");

  const start1 = Date.now();
  await getEndpoints(1);
  const time1 = Date.now() - start1;
  console.log(`First fetch took: ${time1}ms`);

  const start2 = Date.now();
  await getEndpoints(1);
  const time2 = Date.now() - start2;
  console.log(`Second fetch (cached) took: ${time2}ms`);

  if (time2 >= time1) {
    console.log("⚠️  Warning: Cache might not be working (second call not faster)");
  } else {
    console.log("✅ Cache is working (second call faster)");
  }
}

async function runTests() {
  console.log("=================================");
  console.log("🚀 Chainlist Module Tests");
  console.log("=================================");

  try {
    await testGetEndpoints();
    await testGetChainById();
    await testGetAllChains();
    await testCaching();

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
