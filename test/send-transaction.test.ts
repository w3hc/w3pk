/**
 * sendTransaction Tests
 *
 * Tests for the sendTransaction() SDK method covering:
 * - Method existence and shape
 * - Authentication guard
 * - STRICT / STANDARD / YOLO broadcast an EOA transaction (PRIMARY mode is in
 *   send-transaction-primary.test.ts)
 * - Return type structure
 * - Mode / tag / origin isolation (wallet derivation correctness)
 * - RPC resolution: explicit rpcUrl, then app rpcUrls, never chainlist
 * - No app-set RPC endpoint error
 * - ethers sendTransaction delegation (provider mock)
 * - STANDARD / STRICT / YOLO mode wiring
 * - Deterministic sender address (same mode+tag → same from)
 * - Different tags → different from addresses
 */

import "./setup";
import { UnauthorizedError, UserRejectedRequestError, createWeb3Passkey, getSigningDigests } from "../src/index";
import { startMockBundler } from "./fixtures/mock-bundler";
import { getOriginSpecificAddress } from "../src/wallet/origin-derivation";
import { deriveWalletFromPath } from "../src/wallet/generate";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  logDetail,
  logInfo,
  skipTest,
  assert,
  assertEqual,
} from "./test-utils";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_MNEMONIC =
  "test test test test test test test test test test test junk";
const TEST_ORIGIN = "https://example.com";
const TEST_CONTRACT = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";

/** Build a minimal mock provider that captures the tx sent to it. */
function makeMockProvider(txHash = "0xabc123deadbeef") {
  const sent: any[] = [];
  return {
    sent,
    // ethers calls provider.broadcastTransaction / sendTransaction internally —
    // we intercept at the wallet level via a mock JsonRpcProvider.
    mock: {
      getNetwork: async () => ({ chainId: 1n }),
      getTransactionCount: async () => 0,
      getFeeData: async () => ({
        maxFeePerGas: 10n ** 9n,
        maxPriorityFeePerGas: 10n ** 9n,
        gasPrice: 10n ** 9n,
      }),
      estimateGas: async () => 21000n,
      broadcastTransaction: async (signedTx: string) => {
        sent.push(signedTx);
        return {
          hash: txHash,
          wait: async () => ({ blockNumber: 1, status: 1 }),
        };
      },
      // ethers v6 uses _detectNetwork + _perform
      _detectNetwork: async () => ({ chainId: 1n }),
      _perform: async (req: any) => {
        if (req.method === "eth_chainId") return "0x1";
        if (req.method === "eth_getTransactionCount") return "0x0";
        if (req.method === "eth_gasPrice") return "0x3b9aca00";
        if (req.method === "eth_estimateGas") return "0x5208";
        if (req.method === "eth_maxPriorityFeePerGas") return "0x3b9aca00";
        if (req.method === "eth_feeHistory") return { baseFeePerGas: ["0x3b9aca00"], reward: [["0x3b9aca00"]] };
        if (req.method === "eth_sendRawTransaction") {
          sent.push(req.signedTransaction);
          return txHash;
        }
        return null;
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Derive the expected sender address for a given mode + tag, same as SDK does
// ---------------------------------------------------------------------------
async function expectedFrom(
  mode: "STANDARD" | "STRICT" | "YOLO",
  tag: string,
  origin = TEST_ORIGIN
): Promise<string> {
  const derived = await getOriginSpecificAddress(
    TEST_MNEMONIC,
    origin,
    mode,
    tag
  );
  return derived.address;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

async function runTests() {
  startTestSuite("sendTransaction Tests");

  // ------------------------------------------------------------------
  // 1. Method exists on SDK instance
  // ------------------------------------------------------------------
  await runTest("sendTransaction method exists on SDK", async () => {
    const sdk = createWeb3Passkey({ debug: false });
    assert(
      typeof sdk.sendTransaction === "function",
      "sendTransaction should be a function on the SDK"
    );
    passTest("sendTransaction method is present");
  });

  // ------------------------------------------------------------------
  // 2. Throws when not authenticated
  // ------------------------------------------------------------------
  await runTest("sendTransaction throws when not authenticated", async () => {
    const sdk = createWeb3Passkey({ debug: false });

    try {
      await sdk.sendTransaction({ to: TEST_CONTRACT, chainId: 1 });
      throw new Error("Should have thrown");
    } catch (error) {
      const msg = (error as Error).message;
      const cause = (error as any).cause?.message ?? "";
      const full = msg + " " + cause;
      assert(
        full.includes("authenticated") || msg.includes("Failed to send transaction"),
        `Expected auth error, got: ${msg}`
      );
      passTest("Correctly requires authentication");
      logDetail(`Error: ${msg}`);
    }
  });

  // ------------------------------------------------------------------
  // 3. STRICT / STANDARD / YOLO send a signed EOA transaction, as in v0.11.2
  // ------------------------------------------------------------------
  await runTest("STRICT / STANDARD / YOLO broadcast an EOA transaction signed by the mode's wallet", async () => {
    const { Transaction, keccak256 } = await import("ethers");
    const chain = await startMockBundler();
    try {
      for (const mode of ["STRICT", "STANDARD", "YOLO"] as const) {
        const sdk = createWeb3Passkey({ debug: false, rpcUrls: { 1: [chain.url] } });
        (sdk as any).currentUser = { username: "eoa", ethereumAddress: TEST_CONTRACT, credentialId: "eoa" };
        let requireAuth: boolean | undefined;
        (sdk as any).getMnemonicFromSession = async (fresh: boolean) => {
          requireAuth = fresh;
          return TEST_MNEMONIC;
        };
        chain.calls.length = 0;
        const result = await sdk.sendTransaction(
          { to: TEST_CONTRACT, value: 3n, data: "0xbeef", chainId: 1 },
          { mode }
        );
        const raw = chain.calls.find((c) => c.method === "eth_sendRawTransaction")!.params[0];
        const sent = Transaction.from(raw);
        const from = await expectedFrom(mode, "MAIN", window.location.origin);
        assertEqual(sent.from, from, `${mode}: signed by the mode's wallet`);
        assertEqual(result.from, from, `${mode}: from`);
        assertEqual(result.hash, keccak256(raw), `${mode}: hash of the raw transaction`);
        assertEqual(sent.to, TEST_CONTRACT, `${mode}: to`);
        assertEqual(sent.value, 3n, `${mode}: value`);
        assertEqual(sent.data, "0xbeef", `${mode}: data`);
        assertEqual(sent.chainId, 1n, `${mode}: chainId`);
        assertEqual(result.mode, mode, `${mode}: mode`);
        assertEqual((result as any).userOpHash, undefined, `${mode}: no userOpHash`);
        assertEqual(requireAuth, mode === "STRICT", `${mode}: fresh authentication only in STRICT`);
        assert(
          !chain.calls.some((c) => c.method.includes("UserOperation")),
          `${mode}: no bundler call`
        );
      }
    } finally {
      await chain.close();
    }
    passTest("STRICT / STANDARD / YOLO send as in v0.11.2");
  });

  // ------------------------------------------------------------------
  // 4. onBeforeSign in STRICT / STANDARD / YOLO
  // ------------------------------------------------------------------
  await runTest("STRICT / STANDARD / YOLO await onBeforeSign with the digests before the passkey prompt", async () => {
    const { Transaction } = await import("ethers");
    const chain = await startMockBundler();
    try {
      for (const mode of ["STRICT", "STANDARD", "YOLO"] as const) {
        const sdk = createWeb3Passkey({ debug: false, rpcUrls: { 1: [chain.url] } });
        (sdk as any).currentUser = { username: "eoa", ethereumAddress: TEST_CONTRACT, credentialId: "eoa" };
        const log: string[] = [];
        (sdk as any).getMnemonicFromSession = async () => {
          log.push("passkey");
          return TEST_MNEMONIC;
        };
        const sent = () => chain.calls.filter((c) => c.method === "eth_sendRawTransaction");
        chain.calls.length = 0;

        const tx = { to: TEST_CONTRACT, value: 3n, data: "0xbeef", chainId: 1 };
        const expected = getSigningDigests({ method: "eth_sendTransaction", params: [tx] });
        await sdk.sendTransaction(tx, {
          mode,
          onBeforeSign: async (digests) => {
            log.push("hook");
            assert(!Array.isArray(digests), `${mode}: one transaction, one digests object`);
            assertEqual(digests.method, "eth_sendTransaction", `${mode}: method`);
            assertEqual(digests.calldataDigest, expected.calldataDigest, `${mode}: Calldata Digest`);
            assertEqual(digests.to, expected.to, `${mode}: to`);
            assertEqual(digests.value, 3n, `${mode}: value`);
            tx.data = "0xdead";
            tx.value = 9n;
          },
        });
        assertEqual(log.join(","), "hook,passkey", `${mode}: hook before the passkey prompt`);
        const signed = Transaction.from(sent()[0].params[0]);
        assertEqual(signed.data, "0xbeef", `${mode}: the copy taken before the hook is sent`);
        assertEqual(signed.value, 3n, `${mode}: value from the copy`);

        const cancel = new Error("cancelled");
        const cancels = [
          { hook: () => false, cause: undefined },
          { hook: () => { throw cancel; }, cause: cancel },
          { hook: () => Promise.reject(cancel), cause: cancel },
        ];
        for (const { hook, cause } of cancels) {
          log.length = 0;
          chain.calls.length = 0;
          const error = await sdk
            .sendTransaction({ to: TEST_CONTRACT, chainId: 1 }, { mode, onBeforeSign: hook })
            .catch((e) => e);
          assert(error instanceof UserRejectedRequestError, `${mode}: UserRejectedRequestError, got ${error}`);
          assertEqual(error.code, 4001, `${mode}: code 4001`);
          assertEqual(error.cause, cause, `${mode}: the hook's error as cause`);
          assertEqual(log.length, 0, `${mode}: no passkey prompt`);
          assertEqual(sent().length, 0, `${mode}: nothing sent`);
        }
      }
    } finally {
      await chain.close();
    }
    passTest("onBeforeSign approves or cancels EOA transactions before the passkey prompt");
  });

  await runTest("STRICT / STANDARD / YOLO: options.from other than the signer throws 4100 before signing", async () => {
    const { Transaction } = await import("ethers");
    const chain = await startMockBundler();
    try {
      for (const mode of ["STRICT", "STANDARD", "YOLO"] as const) {
        const sdk = createWeb3Passkey({ debug: false, rpcUrls: { 1: [chain.url] } });
        (sdk as any).currentUser = { username: "eoa", ethereumAddress: TEST_CONTRACT, credentialId: "eoa" };
        (sdk as any).getMnemonicFromSession = async () => TEST_MNEMONIC;
        const signer = await expectedFrom(mode, "MAIN", window.location.origin);
        const sent = () => chain.calls.filter((c) => c.method === "eth_sendRawTransaction");
        chain.calls.length = 0;

        const tx = { to: TEST_CONTRACT, chainId: 1 };
        const error = await sdk.sendTransaction(tx, { mode, from: TEST_CONTRACT }).catch((e) => e);
        assert(error instanceof UnauthorizedError, `${mode}: UnauthorizedError, got ${error}`);
        assertEqual(error.code, 4100, `${mode}: code 4100`);
        assertEqual(sent().length, 0, `${mode}: nothing sent`);
        const signError = await sdk.signMessage("hi", { mode, from: TEST_CONTRACT }).catch((e) => e);
        assert(signError instanceof UnauthorizedError, `${mode}: signMessage throws UnauthorizedError, got ${signError}`);

        await sdk.sendTransaction(tx, { mode, from: signer.toLowerCase() });
        assertEqual(Transaction.from(sent()[0].params[0]).from, signer, `${mode}: lowercase from is sent`);
        const signed = await sdk.signMessage("hi", { mode, from: signer.toUpperCase().replace("0X", "0x") });
        assertEqual(signed.address, signer, `${mode}: uppercase from signs`);
      }
    } finally {
      await chain.close();
    }
    passTest("options.from is checked against the signer, in any letter case");
  });

  await runTest("STRICT / STANDARD / YOLO send gasPrice, and refuse it with EIP-1559 fees before the passkey prompt", async () => {
    const { Transaction } = await import("ethers");
    const chain = await startMockBundler();
    try {
      for (const mode of ["STRICT", "STANDARD", "YOLO"] as const) {
        const sdk = createWeb3Passkey({ debug: false, rpcUrls: { 1: [chain.url] } });
        (sdk as any).currentUser = { username: "eoa", ethereumAddress: TEST_CONTRACT, credentialId: "eoa" };
        let prompts = 0;
        (sdk as any).getMnemonicFromSession = async () => {
          prompts++;
          return TEST_MNEMONIC;
        };
        chain.calls.length = 0;
        await sdk.sendTransaction({ to: TEST_CONTRACT, chainId: 1, gasPrice: 7n }, { mode });
        const sent = Transaction.from(chain.calls.find((c) => c.method === "eth_sendRawTransaction")!.params[0]);
        const fees = sent.type === 0 ? [sent.gasPrice] : [sent.maxFeePerGas, sent.maxPriorityFeePerGas];
        assert(fees.every((fee) => fee === 7n), `${mode}: gasPrice is the fee, got type ${sent.type} ${fees}`);

        prompts = 0;
        for (const fees of [{ maxFeePerGas: 9n }, { maxPriorityFeePerGas: 1n }]) {
          const error = await sdk
            .sendTransaction({ to: TEST_CONTRACT, chainId: 1, gasPrice: 7n, ...fees }, { mode })
            .catch((e) => e);
          assert(error.message.includes("gasPrice"), `${mode}: names gasPrice, got ${error.message}`);
        }
        assertEqual(prompts, 0, `${mode}: no passkey prompt`);
      }
    } finally {
      await chain.close();
    }
    passTest("gasPrice is honoured, and exclusive of EIP-1559 fees");
  });

  // ------------------------------------------------------------------
  // 5. Return type structure (requires a live provider mock)
  //    We test at the derivation layer to verify the shape contract.
  // ------------------------------------------------------------------
  await runTest("return type shape: derivation layer produces correct fields", async () => {
    // Verify the fields SDK would return by inspecting what
    // getOriginSpecificAddress yields for each mode (no WebAuthn needed).
    const modes = ["STANDARD", "STRICT", "YOLO"] as const;
    for (const mode of modes) {
      const derived = await getOriginSpecificAddress(
        TEST_MNEMONIC,
        TEST_ORIGIN,
        mode,
        "MAIN"
      );

      assert(typeof derived.address === "string", `${mode}: address is string`);
      assert(derived.address.startsWith("0x"), `${mode}: address starts with 0x`);
      assert(typeof derived.mode === "string", `${mode}: mode is string`);
      assert(typeof derived.tag === "string", `${mode}: tag is string`);
      assert(typeof derived.origin === "string", `${mode}: origin is string`);
      assertEqual(derived.mode, mode, `${mode}: mode field matches`);
      assertEqual(derived.tag, "MAIN", `${mode}: tag field matches`);

      logDetail(`${mode}: ${derived.address}`);
    }
    passTest("Derivation layer produces correct field shape for all modes");
  });

  // ------------------------------------------------------------------
  // 6. STANDARD / STRICT / YOLO produce distinct sender addresses
  // ------------------------------------------------------------------
  await runTest("STANDARD / STRICT / YOLO produce distinct sender addresses", async () => {
    const modes = ["STANDARD", "STRICT", "YOLO"] as const;
    const addresses: string[] = [];

    for (const mode of modes) {
      const addr = await expectedFrom(mode, "MAIN");
      addresses.push(addr);
      logDetail(`${mode.padEnd(10)}: ${addr}`);
    }

    const unique = new Set(addresses);
    assert(unique.size === 3, "All three modes must derive distinct addresses");
    passTest("Each security mode derives a unique sender address");
  });

  // ------------------------------------------------------------------
  // 7. Different tags → different sender addresses (YOLO mode)
  // ------------------------------------------------------------------
  await runTest("Different tags produce different sender addresses", async () => {
    const tags = ["MAIN", "GAMING", "TRADING", "DEFI"];
    const addresses: string[] = [];

    for (const tag of tags) {
      const addr = await expectedFrom("YOLO", tag);
      addresses.push(addr);
      logDetail(`YOLO/${tag.padEnd(8)}: ${addr}`);
    }

    const unique = new Set(addresses);
    assert(unique.size === tags.length, "Each tag must derive a unique address");
    passTest("Different tags produce different sender addresses");
  });

  // ------------------------------------------------------------------
  // 8. Derivation is deterministic: same mode+tag → same address
  // ------------------------------------------------------------------
  await runTest("Sender address is deterministic (same mode+tag → same address)", async () => {
    const addr1 = await expectedFrom("STANDARD", "MAIN");
    const addr2 = await expectedFrom("STANDARD", "MAIN");
    assertEqual(addr1, addr2, "Same mode+tag should always derive the same address");

    const yolo1 = await expectedFrom("YOLO", "GAMING");
    const yolo2 = await expectedFrom("YOLO", "GAMING");
    assertEqual(yolo1, yolo2, "YOLO+GAMING address must be deterministic");

    passTest("Sender address is deterministic");
    logDetail(`STANDARD/MAIN: ${addr1}`);
    logDetail(`YOLO/GAMING:   ${yolo1}`);
  });

  // ------------------------------------------------------------------
  // 9. YOLO mode exposes private key; STANDARD/STRICT do not
  // ------------------------------------------------------------------
  await runTest("YOLO exposes privateKey, STANDARD/STRICT do not", async () => {
    const yolo = await getOriginSpecificAddress(
      TEST_MNEMONIC, TEST_ORIGIN, "YOLO", "MAIN"
    );
    const standard = await getOriginSpecificAddress(
      TEST_MNEMONIC, TEST_ORIGIN, "STANDARD", "MAIN"
    );
    const strict = await getOriginSpecificAddress(
      TEST_MNEMONIC, TEST_ORIGIN, "STRICT", "MAIN"
    );

    assert(typeof yolo.privateKey === "string" && yolo.privateKey.length > 0,
      "YOLO mode should expose privateKey");
    assert(!standard.privateKey,
      "STANDARD mode must NOT expose privateKey");
    assert(!strict.privateKey,
      "STRICT mode must NOT expose privateKey");

    passTest("Key exposure matches mode contract");
    logDetail(`YOLO privateKey present: ${!!yolo.privateKey}`);
    logDetail(`STANDARD privateKey present: ${!!standard.privateKey}`);
    logDetail(`STRICT privateKey present: ${!!strict.privateKey}`);
  });

  // ------------------------------------------------------------------
  // 10. Wallet can be instantiated + signs a tx (ethers layer test,
  //     no network required — uses a mock provider)
  // ------------------------------------------------------------------
  await runTest("Wallet derived from mnemonic can sign a transaction", async () => {
    const { Wallet } = await import("ethers");

    // Derive STANDARD wallet (path-based, no privateKey in derived)
    const derived = await getOriginSpecificAddress(
      TEST_MNEMONIC, TEST_ORIGIN, "STANDARD", "MAIN"
    );
    const { privateKey } = deriveWalletFromPath(TEST_MNEMONIC, derived.path);
    const wallet = new Wallet(privateKey);

    // Address must match what the derivation layer reports
    assertEqual(
      wallet.address.toLowerCase(),
      derived.address.toLowerCase(),
      "Wallet address must match derived address"
    );

    // Sign a dummy transaction to confirm the key is valid
    const signed = await wallet.signTransaction({
      to: TEST_CONTRACT,
      value: 0n,
      nonce: 0,
      chainId: 1n,
      gasLimit: 21000n,
      maxFeePerGas: 10n ** 9n,
      maxPriorityFeePerGas: 10n ** 9n,
      type: 2,
    });

    assert(typeof signed === "string" && signed.startsWith("0x"),
      "Signed transaction should be a hex string");
    passTest("STANDARD mode wallet signs a transaction correctly");
    logDetail(`Address: ${wallet.address}`);
    logDetail(`Signed tx (truncated): ${signed.slice(0, 30)}...`);
  });

  // ------------------------------------------------------------------
  // 11. YOLO wallet (private key path) also signs correctly
  // ------------------------------------------------------------------
  await runTest("YOLO wallet (private key path) signs a transaction correctly", async () => {
    const { Wallet } = await import("ethers");

    const derived = await getOriginSpecificAddress(
      TEST_MNEMONIC, TEST_ORIGIN, "YOLO", "GAMING"
    );

    assert(!!derived.privateKey, "YOLO should expose privateKey");
    const wallet = new Wallet(derived.privateKey!);

    assertEqual(
      wallet.address.toLowerCase(),
      derived.address.toLowerCase(),
      "YOLO wallet address must match derived address"
    );

    const signed = await wallet.signTransaction({
      to: TEST_CONTRACT,
      value: 10n ** 17n,
      nonce: 0,
      chainId: 1n,
      gasLimit: 21000n,
      maxFeePerGas: 2n * 10n ** 9n,
      maxPriorityFeePerGas: 10n ** 9n,
      type: 2,
    });

    assert(typeof signed === "string" && signed.startsWith("0x"),
      "Signed tx should be hex");
    passTest("YOLO mode wallet signs a transaction correctly");
    logDetail(`YOLO/GAMING address: ${wallet.address}`);
    logDetail(`Signed tx (truncated): ${signed.slice(0, 30)}...`);
  });

  // ------------------------------------------------------------------
  // 12. SDK method is available and not undefined in exported surface
  // ------------------------------------------------------------------
  await runTest("sendTransaction is exported via createWeb3Passkey", async () => {
    const sdk = createWeb3Passkey({ debug: false });
    assert("sendTransaction" in sdk, "sendTransaction should be in SDK");
    assert(sdk.sendTransaction !== undefined, "sendTransaction should not be undefined");
    passTest("sendTransaction is in the public SDK surface");
  });

  // ------------------------------------------------------------------
  // 15. origin isolation: different origins → different addresses
  // ------------------------------------------------------------------
  await runTest("Different origins derive different sender addresses", async () => {
    const origins = [
      "https://app-a.example.com",
      "https://app-b.example.com",
      "https://totally-different.io",
    ];
    const addresses: string[] = [];

    for (const origin of origins) {
      const derived = await getOriginSpecificAddress(
        TEST_MNEMONIC, origin, "STANDARD", "MAIN"
      );
      addresses.push(derived.address);
      logDetail(`${origin}: ${derived.address}`);
    }

    const unique = new Set(addresses);
    assert(unique.size === origins.length, "Each origin must derive a unique address");
    passTest("Origin isolation: each origin maps to a unique sender address");
  });

  // ------------------------------------------------------------------
  // 16. RPC selection: per-call rpcUrl, then app rpcUrls, never chainlist
  // ------------------------------------------------------------------
  await runTest("sendTransaction uses per-call rpcUrl, then app rpcUrls, and throws without either", async () => {
    const { JsonRpcProvider } = await import("ethers");
    const { clearCache } = await import("../src/chainlist");
    const proto = JsonRpcProvider.prototype as any;
    const originalSend = proto._send;
    const originalFetch = globalThis.fetch;
    const urls: string[] = [];
    let fetches = 0;
    let prompts = 0;
    proto._send = async function (payload: any) {
      urls.push(this._getConnection().url);
      const requests = Array.isArray(payload) ? payload : [payload];
      if (requests[0].method === "eth_chainId") {
        return requests.map((r: any) => ({ id: r.id, result: "0x1" }));
      }
      throw new Error("stub RPC");
    };
    globalThis.fetch = (async () => {
      fetches++;
      return new Response(JSON.stringify([
        { chainId: 1, rpc: ["http://plain.example", "https://chainlist.example"] },
      ]));
    }) as typeof fetch;
    clearCache();

    const send = async (config: object, rpcUrl?: string) => {
      const sdk = createWeb3Passkey({ debug: false, ...config });
      (sdk as any).currentUser = { username: "rpc", ethereumAddress: TEST_CONTRACT, credentialId: "rpc" };
      (sdk as any).getMnemonicFromSession = async () => {
        prompts++;
        return TEST_MNEMONIC;
      };
      urls.length = 0;
      const error = await sdk.sendTransaction({ to: TEST_CONTRACT, chainId: 1 }, { rpcUrl }).catch((e) => e);
      return { url: urls[0], error: error as Error };
    };

    try {
      const appRpc = { rpcUrls: { 1: ["https://app.example"] } };
      assertEqual((await send(appRpc, "https://call.example")).url, "https://call.example", "per-call rpcUrl first");
      assertEqual((await send({}, "https://call.example")).url, "https://call.example", "per-call rpcUrl without rpcUrls");
      assertEqual((await send(appRpc)).url, "https://app.example", "app rpcUrls without per-call rpcUrl");

      for (const config of [{}, { rpcUrls: { 1: [] } }, { rpcUrls: { 10: ["https://op.example"] } }]) {
        prompts = 0;
        fetches = 0;
        const { url, error } = await send(config);
        assert(error.message.includes("rpcUrls"), `error names rpcUrls, got: ${error.message}`);
        assertEqual(url, undefined, "no RPC request without an app-set endpoint");
        assertEqual(fetches, 0, "chainid.network not fetched");
        assertEqual(prompts, 0, "no passkey prompt");
      }

      const sdk = createWeb3Passkey({ debug: false, ...appRpc });
      assertEqual(
        JSON.stringify(await sdk.getEndpoints(1)),
        JSON.stringify(["https://app.example", "https://chainlist.example"]),
        "getEndpoints lists app endpoints first"
      );

      globalThis.fetch = (async () => { throw new Error("offline"); }) as typeof fetch;
      clearCache();
      assertEqual(
        JSON.stringify(await sdk.getEndpoints(1)),
        JSON.stringify(["https://app.example"]),
        "getEndpoints keeps app endpoints when chainid.network is unreachable"
      );
    } finally {
      proto._send = originalSend;
      globalThis.fetch = originalFetch;
      clearCache();
    }
    passTest("RPC endpoint: per-call, then app rpcUrls, else a clear error");
  });

  // ------------------------------------------------------------------
  // Informational note
  // ------------------------------------------------------------------
  logInfo("Transactions are broadcast to an in-process mock RPC, not a live node.");

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
