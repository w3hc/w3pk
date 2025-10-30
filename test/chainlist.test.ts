/**
 * Chainlist module tests
 */

import {
  getEndpoints,
  getAllChains,
  getChainById,
  clearCache,
} from "../src/chainlist/index";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  logDetail,
  logInfo,
  logWarning,
  assert,
  assertTruthy,
} from "./test-utils";

async function runTests() {
  startTestSuite("Chainlist Module Tests");

  // Test 1: getEndpoints()
  await runTest("getEndpoints()", async () => {
    // Test Ethereum mainnet (chainId: 1)
    logInfo("Fetching Ethereum mainnet endpoints (chainId: 1)...");
    const ethEndpoints = await getEndpoints(1);
    logDetail(`Found ${ethEndpoints.length} RPC endpoints without API keys`);

    // Verify no API key patterns
    const hasApiKeyPattern = ethEndpoints.some(
      (url) =>
        url.includes("${") ||
        url.includes("{") ||
        url.includes("<") ||
        url.toLowerCase().includes("api_key")
    );
    assert(!hasApiKeyPattern, "Found endpoint with API key pattern!");
    passTest("All endpoints are API key free");

    // Verify no websocket URLs
    const hasWebsocket = ethEndpoints.some(
      (url) => url.startsWith("wss://") || url.startsWith("ws://")
    );
    assert(!hasWebsocket, "Found websocket endpoint!");
    passTest("No websocket endpoints included");

    // Test Polygon (chainId: 137)
    logInfo("Fetching Polygon endpoints (chainId: 137)...");
    const polygonEndpoints = await getEndpoints(137);
    logDetail(`Found ${polygonEndpoints.length} endpoints for Polygon`);

    // Test non-existent chain (using a very unlikely chain ID)
    logInfo("Testing non-existent chain (chainId: 123456789)...");
    const nonExistent = await getEndpoints(123456789);
    if (nonExistent.length !== 0) {
      logWarning(`Chain ID 123456789 exists with ${nonExistent.length} endpoints`);
    } else {
      passTest("Returns empty array for non-existent chain");
    }
  });

  // Test 2: getChainById()
  await runTest("getChainById()", async () => {
    const ethChain = await getChainById(1);
    assertTruthy(ethChain, "Should find Ethereum mainnet!");

    passTest(`Found chain: ${ethChain!.name} (${ethChain!.chainId})`);
    logDetail(`Symbol: ${ethChain!.nativeCurrency.symbol}`);
    logDetail(`RPC endpoints: ${ethChain!.rpc.length}`);

    const nonExistent = await getChainById(123456789);
    if (nonExistent !== undefined) {
      logWarning(`Chain ID 123456789 exists: ${nonExistent.name}`);
    } else {
      passTest("Returns undefined for non-existent chain");
    }
  });

  // Test 3: getAllChains()
  await runTest("getAllChains()", async () => {
    const chains = await getAllChains();
    passTest(`Fetched ${chains.length} chains`);

    // Verify some well-known chains exist
    const ethereum = chains.find((c) => c.chainId === 1);
    const polygon = chains.find((c) => c.chainId === 137);
    const optimism = chains.find((c) => c.chainId === 10);

    assertTruthy(ethereum && polygon && optimism, "Missing well-known chains!");
    passTest("Found well-known chains (Ethereum, Polygon, Optimism)");
  });

  // Test 4: Caching mechanism
  await runTest("Caching mechanism", async () => {
    clearCache();
    passTest("Cache cleared");

    const start1 = Date.now();
    await getEndpoints(1);
    const time1 = Date.now() - start1;
    logDetail(`First fetch took: ${time1}ms`);

    const start2 = Date.now();
    await getEndpoints(1);
    const time2 = Date.now() - start2;
    logDetail(`Second fetch (cached) took: ${time2}ms`);

    if (time2 >= time1) {
      logWarning("Cache might not be working (second call not faster)");
    } else {
      passTest("Cache is working (second call faster)");
    }
  });

  endTestSuite();
}

runTests().catch(console.error);
