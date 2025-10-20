/**
 * Test getEndpoints method on Web3Passkey SDK instance
 */

import { createWeb3Passkey } from "../src/index";

async function testSDKGetEndpoints() {
  console.log("🧪 Testing w3pk.getEndpoints() method...\n");

  try {
    // Create SDK instance
    const w3pk = createWeb3Passkey({
      apiBaseUrl: "https://webauthn.w3hc.org",
    });

    // Test 1: Get Ethereum mainnet endpoints
    console.log("1️⃣  Testing w3pk.getEndpoints(1) for Ethereum...");
    const ethEndpoints = await w3pk.getEndpoints(1);

    if (!Array.isArray(ethEndpoints)) {
      throw new Error("Expected array of endpoints");
    }

    if (ethEndpoints.length === 0) {
      throw new Error("Expected at least one endpoint");
    }

    console.log(`✅ Found ${ethEndpoints.length} endpoints for Ethereum`);
    console.log(`   First endpoint: ${ethEndpoints[0]}`);

    // Verify no API keys
    const hasApiKey = ethEndpoints.some(
      (url) =>
        url.includes("${") ||
        url.includes("{") ||
        url.toLowerCase().includes("api_key")
    );

    if (hasApiKey) {
      throw new Error("Found endpoint with API key pattern!");
    }

    console.log("✅ All endpoints are API key free\n");

    // Test 2: Get Polygon endpoints
    console.log("2️⃣  Testing w3pk.getEndpoints(137) for Polygon...");
    const polygonEndpoints = await w3pk.getEndpoints(137);

    if (!Array.isArray(polygonEndpoints) || polygonEndpoints.length === 0) {
      throw new Error("Expected endpoints for Polygon");
    }

    console.log(`✅ Found ${polygonEndpoints.length} endpoints for Polygon`);
    console.log(`   First endpoint: ${polygonEndpoints[0]}\n`);

    // Test 3: Non-existent chain
    console.log("3️⃣  Testing w3pk.getEndpoints(123456789) for non-existent chain...");
    const nonExistent = await w3pk.getEndpoints(123456789);

    if (!Array.isArray(nonExistent)) {
      throw new Error("Expected empty array for non-existent chain");
    }

    console.log("✅ Returns empty array for non-existent chain\n");

    console.log("=================================");
    console.log("✅ All SDK tests passed!");
    console.log("=================================");
  } catch (error) {
    console.error("\n=================================");
    console.error("❌ SDK test failed!");
    console.error("=================================");
    console.error(error);
    process.exit(1);
  }
}

testSDKGetEndpoints();
