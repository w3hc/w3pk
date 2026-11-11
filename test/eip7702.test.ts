/**
 * EIP-7702 SDK method tests
 */

import "./setup";
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
    const w3pk = createWeb3Passkey();

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

  await runTest("supportsEIP7702() probes only the configured RPC", async () => {
    const originalFetch = globalThis.fetch;
    const calls: string[] = [];
    let honorsOverrides = true;
    let supports7702 = true;
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      calls.push(String(url));
      const body = JSON.parse(String(init?.body));
      const { code } = Object.values(body.params[2])[0] as { code: string };
      const reverts = code === "0x60006000fd" ? honorsOverrides : !supports7702;
      return new Response(
        JSON.stringify(reverts ? { jsonrpc: "2.0", id: 1, error: { code: 3, message: "execution reverted" } } : { jsonrpc: "2.0", id: 1, result: "0x5208" }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }) as typeof fetch;
    try {
      const unlisted = 999999999999;

      assert(!(await createWeb3Passkey().supportsEIP7702(unlisted)), "false without rpcUrls");
      assert(calls.length === 0, "no request without rpcUrls");

      const sdk = createWeb3Passkey({ rpcUrls: { [unlisted]: ["https://rpc.example"] } });
      assert(await sdk.supportsEIP7702(unlisted), "a supporting RPC passes");
      assert(calls.every((url) => url === "https://rpc.example"), "only the configured RPC is called");

      supports7702 = false;
      assert(!(await sdk.supportsEIP7702(unlisted)), "an RPC rejecting the delegation fails");

      supports7702 = true;
      honorsOverrides = false;
      assert(!(await sdk.supportsEIP7702(unlisted)), "an RPC ignoring state overrides fails");

      calls.length = 0;
      assert(await sdk.supportsEIP7702(1), "a listed chain passes");
      assert(calls.length === 0, "without a request");
    } finally {
      globalThis.fetch = originalFetch;
    }
    passTest("supportsEIP7702() never calls a public endpoint");
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
