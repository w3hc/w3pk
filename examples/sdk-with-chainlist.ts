/**
 * Example: Using getEndpoints() with Web3Passkey SDK
 *
 * This example shows how to use the chainlist functionality
 * integrated into the Web3Passkey SDK to automatically fetch
 * public RPC endpoints for connecting to different networks.
 */

import { createWeb3Passkey } from "../src/index";

async function main() {
  console.log("🚀 Web3Passkey SDK with Chainlist Example\n");

  // Create SDK instance
  const w3pk = createWeb3Passkey({
    apiBaseUrl: "https://webauthn.w3hc.org",
    debug: false,
  });

  console.log("✅ SDK initialized\n");

  // Example 1: Get endpoints for the network you want to connect to
  console.log("📡 Fetching Ethereum mainnet RPC endpoints...");
  const ethEndpoints = await w3pk.getEndpoints(1);

  console.log(`Found ${ethEndpoints.length} public RPC endpoints:`);
  ethEndpoints.forEach((url, i) => {
    console.log(`  ${i + 1}. ${url}`);
  });
  console.log();

  // Example 2: Use with ethers.js (pseudo-code, ethers not imported)
  console.log("💡 Example: Using with ethers.js\n");
  console.log("```typescript");
  console.log("import { ethers } from 'ethers'");
  console.log("import { createWeb3Passkey } from 'w3pk'");
  console.log();
  console.log("const w3pk = createWeb3Passkey({");
  console.log("  apiBaseUrl: 'https://webauthn.w3hc.org'");
  console.log("})");
  console.log();
  console.log("// Get RPC endpoints for Polygon");
  console.log("const endpoints = await w3pk.getEndpoints(137)");
  console.log();
  console.log("// Try connecting to the first available endpoint");
  console.log("const provider = new ethers.JsonRpcProvider(endpoints[0])");
  console.log("const blockNumber = await provider.getBlockNumber()");
  console.log("console.log(`Current block: ${blockNumber}`)");
  console.log("```\n");

  // Example 3: Multi-chain support
  console.log("🌐 Multi-chain support:");
  const chains = [
    { id: 1, name: "Ethereum" },
    { id: 137, name: "Polygon" },
    { id: 10, name: "Optimism" },
    { id: 42161, name: "Arbitrum" },
    { id: 8453, name: "Base" },
  ];

  for (const chain of chains) {
    const endpoints = await w3pk.getEndpoints(chain.id);
    console.log(`  ${chain.name} (${chain.id}): ${endpoints.length} RPCs available`);
  }
  console.log();

  // Example 4: Fallback logic
  console.log("💡 Example: Fallback connection logic\n");
  console.log("```typescript");
  console.log("async function connectToChain(chainId: number) {");
  console.log("  const endpoints = await w3pk.getEndpoints(chainId)");
  console.log();
  console.log("  for (const rpcUrl of endpoints) {");
  console.log("    try {");
  console.log("      const provider = new ethers.JsonRpcProvider(rpcUrl)");
  console.log("      await provider.getBlockNumber() // Test connection");
  console.log("      console.log(`Connected to ${rpcUrl}`)");
  console.log("      return provider");
  console.log("    } catch (error) {");
  console.log("      console.log(`Failed ${rpcUrl}, trying next...`)");
  console.log("    }");
  console.log("  }");
  console.log("  throw new Error('All RPC endpoints failed')");
  console.log("}");
  console.log("```\n");

  console.log("✅ Example completed!");
  console.log("\n📚 Key Benefits:");
  console.log("  • No hardcoded RPC URLs needed");
  console.log("  • Automatic filtering of API key-protected endpoints");
  console.log("  • Support for 2390+ networks");
  console.log("  • Built-in caching for performance");
  console.log("  • Easy integration with ethers.js, viem, web3.js, etc.");
}

main().catch(console.error);
