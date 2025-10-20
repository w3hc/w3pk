/**
 * Chainlist Module Demo
 *
 * This example demonstrates how to use the chainlist module to fetch
 * RPC endpoints for different blockchain networks.
 */

import {
  getEndpoints,
  getChainById,
  getAllChains,
} from "../src/chainlist/index";

async function main() {
  console.log("🔗 Chainlist Module Demo\n");

  // Example 1: Get RPC endpoints for Ethereum mainnet
  console.log("1️⃣  Getting RPC endpoints for Ethereum mainnet (chainId: 1)");
  const ethEndpoints = await getEndpoints(1);
  console.log(`   Found ${ethEndpoints.length} public RPC endpoints:`);
  ethEndpoints.slice(0, 5).forEach((url, i) => {
    console.log(`   ${i + 1}. ${url}`);
  });
  if (ethEndpoints.length > 5) {
    console.log(`   ... and ${ethEndpoints.length - 5} more`);
  }
  console.log();

  // Example 2: Get RPC endpoints for Polygon
  console.log("2️⃣  Getting RPC endpoints for Polygon (chainId: 137)");
  const polygonEndpoints = await getEndpoints(137);
  console.log(`   Found ${polygonEndpoints.length} public RPC endpoints:`);
  polygonEndpoints.slice(0, 3).forEach((url, i) => {
    console.log(`   ${i + 1}. ${url}`);
  });
  console.log();

  // Example 3: Get full chain information
  console.log("3️⃣  Getting full chain information for Optimism (chainId: 10)");
  const optimismChain = await getChainById(10);
  if (optimismChain) {
    console.log(`   Name: ${optimismChain.name}`);
    console.log(`   Native Currency: ${optimismChain.nativeCurrency.symbol}`);
    console.log(`   Total RPC URLs: ${optimismChain.rpc.length}`);
    const publicRpcs = await getEndpoints(10);
    console.log(`   Public RPC URLs (no API key): ${publicRpcs.length}`);
  }
  console.log();

  // Example 4: List some popular chains
  console.log("4️⃣  Popular chains and their available public RPCs:");
  const popularChainIds = [
    { id: 1, name: "Ethereum" },
    { id: 137, name: "Polygon" },
    { id: 10, name: "Optimism" },
    { id: 42161, name: "Arbitrum One" },
    { id: 8453, name: "Base" },
    { id: 56, name: "BNB Chain" },
  ];

  for (const { id, name } of popularChainIds) {
    const endpoints = await getEndpoints(id);
    console.log(`   ${name}: ${endpoints.length} public RPCs`);
  }
  console.log();

  // Example 5: Get total number of chains
  console.log("5️⃣  Getting total number of chains");
  const allChains = await getAllChains();
  console.log(`   Total chains available: ${allChains.length}`);
  console.log();

  console.log("✅ Demo completed!");
}

main().catch(console.error);
