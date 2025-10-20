/**
 * Test importing chainlist from the built package
 */

async function testImport() {
  console.log("🧪 Testing chainlist package import...\n");

  try {
    // Test importing from the built dist files
    const chainlist = await import("../dist/chainlist/index.mjs");

    // Verify all exports are available
    const { getEndpoints, getChainById, getAllChains, clearCache } = chainlist;

    if (!getEndpoints || typeof getEndpoints !== "function") {
      throw new Error("getEndpoints not exported correctly");
    }
    if (!getChainById || typeof getChainById !== "function") {
      throw new Error("getChainById not exported correctly");
    }
    if (!getAllChains || typeof getAllChains !== "function") {
      throw new Error("getAllChains not exported correctly");
    }
    if (!clearCache || typeof clearCache !== "function") {
      throw new Error("clearCache not exported correctly");
    }

    console.log("✅ All functions exported correctly");

    // Quick functional test
    const endpoints = await getEndpoints(1);
    if (!Array.isArray(endpoints) || endpoints.length === 0) {
      throw new Error("getEndpoints did not return valid data");
    }

    console.log(`✅ getEndpoints works (found ${endpoints.length} endpoints)`);

    const chain = await getChainById(1);
    if (!chain || chain.chainId !== 1) {
      throw new Error("getChainById did not return valid data");
    }

    console.log(`✅ getChainById works (found ${chain.name})`);

    console.log("\n✅ All import tests passed!");
  } catch (error) {
    console.error("\n❌ Import test failed!");
    console.error(error);
    process.exit(1);
  }
}

testImport();
