/**
 * EIP-7702 SDK method tests
 */

import { mockLocalStorage } from "./setup";
import { createWeb3Passkey } from "../src/index";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  logDetail,
  assert,
} from "./test-utils";

async function runTests() {
  startTestSuite("EIP-7702 SDK Method Tests");

  await runTest("w3pk.supportsEIP7702()", async () => {
    const w3pk = createWeb3Passkey({
      storage: mockLocalStorage,
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

    passTest("Testing cached supported chains:");
    for (const { id, name } of supportedChains) {
      const supported = await w3pk.supportsEIP7702(id);
      assert(supported, `${name} (${id}) should support EIP-7702!`);
      logDetail(`✓ ${name} (${id})`);
    }

    // Count total supported chains
    const sampleChains = [1, 10, 8453, 42161, 57073, 100, 42220, 137, 11155111];
    let totalSupported = 0;
    for (const id of sampleChains) {
      if (await w3pk.supportsEIP7702(id)) {
        totalSupported++;
      }
    }

    passTest(`Verified ${totalSupported} sample chains support EIP-7702`);
    passTest("w3pk.supportsEIP7702() working correctly");
  });

  endTestSuite();
}

runTests().catch(console.error);
