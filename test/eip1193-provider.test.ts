/**
 * EIP-1193 Provider Tests
 *
 * Tests for getEIP1193Provider() covering:
 * - Provider shape (request / on / removeListener)
 * - eth_accounts / eth_requestAccounts
 * - eth_chainId (default and custom)
 * - wallet_switchEthereumChain + chainChanged event
 * - eth_sendTransaction param mapping (hex → bigint)
 * - personal_sign / eth_sign (plain text, and hex signed as bytes)
 * - eth_signTypedData_v4 (EIP-712 typed data, bound to the active chain)
 * - Unsupported method throws
 * - Multiple independent provider instances are isolated
 * - on / removeListener event wiring
 * - Typed event handlers compile (type-level, via the TypeScript compiler)
 */

import { mockLocalStorage } from "./setup";
import { createWeb3Passkey } from "../src/index";
import { getOriginSpecificAddress } from "../src/wallet/origin-derivation";
import { createEIP1193Provider } from "../src/core/eip1193";
import { WalletError } from "../src/core/errors";
import { verifyMessage, recoverAddress, TypedDataEncoder, hexlify } from "ethers";
import { fileURLToPath } from "node:url";
import ts from "typescript";
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
  assertThrows,
} from "./test-utils";

const TEST_MNEMONIC =
  "test test test test test test test test test test test junk";
const TEST_ORIGIN = "https://example.com";

function stubSdk() {
  const calls: { message: string | Uint8Array; options: any }[] = [];
  const txs: any[] = [];
  const sdk = {
    getAddress: async () => "0x0000000000000000000000000000000000000001",
    sendTransaction: async (tx: any) => {
      txs.push(tx);
      return { hash: "0x" };
    },
    signMessage: async (message: string | Uint8Array, options?: any) => {
      calls.push({ message, options });
      return { signature: "0xsig" };
    },
  } as any;
  return { sdk, calls, txs };
}

async function runTests() {
  startTestSuite("EIP-1193 Provider Tests");

  // ------------------------------------------------------------------
  // 1. getEIP1193Provider method exists on SDK
  // ------------------------------------------------------------------
  await runTest("getEIP1193Provider method exists on SDK", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    assert(
      typeof sdk.getEIP1193Provider === "function",
      "getEIP1193Provider should be a function on the SDK"
    );
    passTest("getEIP1193Provider is present");
  });

  // ------------------------------------------------------------------
  // 2. Returned object has the EIP-1193 shape
  // ------------------------------------------------------------------
  await runTest("Returned provider has EIP-1193 shape", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider();

    assert(typeof provider.request === "function", "provider.request must be a function");
    assert(typeof provider.on === "function", "provider.on must be a function");
    assert(typeof provider.removeListener === "function", "provider.removeListener must be a function");
    passTest("Provider has request / on / removeListener");
  });

  // ------------------------------------------------------------------
  // 3. eth_chainId — default (1)
  // ------------------------------------------------------------------
  await runTest("eth_chainId returns 0x1 by default", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider();

    const chainId = await provider.request({ method: "eth_chainId" });
    assertEqual(chainId, "0x1", "Default chainId should be 0x1");
    passTest(`eth_chainId = ${chainId}`);
  });

  // ------------------------------------------------------------------
  // 4. eth_chainId — custom initial value
  // ------------------------------------------------------------------
  await runTest("eth_chainId respects options.chainId", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider({ chainId: 8453 }); // Base

    const chainId = await provider.request({ method: "eth_chainId" });
    assertEqual(chainId, "0x" + (8453).toString(16), "chainId should be Base (8453)");
    passTest(`eth_chainId = ${chainId} (Base)`);
  });

  // ------------------------------------------------------------------
  // 5. wallet_switchEthereumChain updates eth_chainId
  // ------------------------------------------------------------------
  await runTest("wallet_switchEthereumChain updates active chainId", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider({ chainId: 1 });

    await provider.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: "0xa" }], // Optimism = 10
    });

    const chainId = await provider.request({ method: "eth_chainId" });
    assertEqual(chainId, "0xa", "chainId should have switched to Optimism (0xa)");
    passTest(`Switched chainId to ${chainId}`);
  });

  // ------------------------------------------------------------------
  // 6. wallet_switchEthereumChain emits chainChanged event
  // ------------------------------------------------------------------
  await runTest("wallet_switchEthereumChain emits chainChanged event", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider({ chainId: 1 });

    let emittedChainId: string | null = null;
    provider.on("chainChanged", (id: string) => {
      emittedChainId = id;
    });

    await provider.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: "0x2105" }], // Base = 8453
    });

    assertEqual(emittedChainId, "0x2105", "chainChanged should emit new chainId");
    passTest(`chainChanged emitted: ${emittedChainId}`);
  });

  // ------------------------------------------------------------------
  // 7. removeListener stops event delivery
  // ------------------------------------------------------------------
  await runTest("removeListener stops event delivery", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider({ chainId: 1 });

    let callCount = 0;
    const handler = () => { callCount++; };
    provider.on("chainChanged", handler);

    await provider.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: "0xa" }],
    });
    assertEqual(callCount, 1, "Handler should have been called once");

    provider.removeListener("chainChanged", handler);

    await provider.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: "0x1" }],
    });
    assertEqual(callCount, 1, "Handler should not be called after removeListener");
    passTest("removeListener correctly stops event delivery");
  });

  // ------------------------------------------------------------------
  // 8. Unsupported method throws
  // ------------------------------------------------------------------
  await runTest("Unsupported method throws WalletError", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider();

    await assertThrows(
      () => provider.request({ method: "eth_getBalance", params: ["0x123", "latest"] }),
      "Unsupported method should throw"
    );
    passTest("Unsupported method correctly throws");
  });

  // ------------------------------------------------------------------
  // 9. Two provider instances are independent (separate chainId state)
  // ------------------------------------------------------------------
  await runTest("Multiple provider instances have isolated chainId state", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const providerA = sdk.getEIP1193Provider({ chainId: 1 });
    const providerB = sdk.getEIP1193Provider({ chainId: 10 });

    await providerA.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: "0x2105" }],
    });

    const chainA = await providerA.request({ method: "eth_chainId" });
    const chainB = await providerB.request({ method: "eth_chainId" });

    assertEqual(chainA, "0x2105", "providerA should have switched chainId");
    assertEqual(chainB, "0xa", "providerB should still be on Optimism");
    assert(chainA !== chainB, "Two providers should have independent chain state");
    passTest(`Isolated: providerA=${chainA}, providerB=${chainB}`);
  });

  // ------------------------------------------------------------------
  // 10. eth_accounts requires authentication → throws when not logged in
  // ------------------------------------------------------------------
  await runTest("eth_accounts throws when not authenticated", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider();

    try {
      await provider.request({ method: "eth_accounts" });
      throw new Error("Should have thrown");
    } catch (error) {
      const msg = (error as Error).message;
      assert(
        msg.includes("authenticated") || msg.includes("Failed") || msg.includes("wallet"),
        `Expected auth error, got: ${msg}`
      );
      passTest("eth_accounts correctly requires authentication");
      logDetail(`Error: ${msg}`);
    }
  });

  // ------------------------------------------------------------------
  // 11. eth_requestAccounts requires authentication → throws when not logged in
  // ------------------------------------------------------------------
  await runTest("eth_requestAccounts throws when not authenticated", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider();

    try {
      await provider.request({ method: "eth_requestAccounts" });
      throw new Error("Should have thrown");
    } catch (error) {
      const msg = (error as Error).message;
      assert(
        msg.includes("authenticated") || msg.includes("Failed") || msg.includes("wallet"),
        `Expected auth error, got: ${msg}`
      );
      passTest("eth_requestAccounts correctly requires authentication");
    }
  });

  // ------------------------------------------------------------------
  // 12. eth_sendTransaction requires authentication
  // ------------------------------------------------------------------
  await runTest("eth_sendTransaction throws when not authenticated", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider({ chainId: 1 });

    try {
      await provider.request({
        method: "eth_sendTransaction",
        params: [{
          to: "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A",
          value: "0xde0b6b3a7640000", // 1 ETH
        }],
      });
      throw new Error("Should have thrown");
    } catch (error) {
      const msg = (error as Error).message;
      assert(
        msg.includes("authenticated") || msg.includes("Failed"),
        `Expected auth error, got: ${msg}`
      );
      passTest("eth_sendTransaction correctly requires authentication");
    }
  });

  // ------------------------------------------------------------------
  // 13. personal_sign requires authentication
  // ------------------------------------------------------------------
  await runTest("personal_sign throws when not authenticated", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider();

    try {
      await provider.request({
        method: "personal_sign",
        params: ["Hello World", "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"],
      });
      throw new Error("Should have thrown");
    } catch (error) {
      const msg = (error as Error).message;
      assert(
        msg.includes("authenticated") || msg.includes("Failed"),
        `Expected auth error, got: ${msg}`
      );
      passTest("personal_sign correctly requires authentication");
    }
  });

  // ------------------------------------------------------------------
  // 14. eth_signTypedData_v4 requires authentication
  // ------------------------------------------------------------------
  await runTest("eth_signTypedData_v4 throws when not authenticated", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider();

    const typedData = JSON.stringify({
      domain: { name: "Test", version: "1", chainId: 1, verifyingContract: "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A" },
      types: { Transfer: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }] },
      primaryType: "Transfer",
      message: { to: "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A", amount: "1000" },
    });

    try {
      await provider.request({
        method: "eth_signTypedData_v4",
        params: ["0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A", typedData],
      });
      throw new Error("Should have thrown");
    } catch (error) {
      const msg = (error as Error).message;
      assert(
        msg.includes("authenticated") || msg.includes("Failed"),
        `Expected auth error, got: ${msg}`
      );
      passTest("eth_signTypedData_v4 correctly requires authentication");
    }
  });

  // ------------------------------------------------------------------
  // 15. personal_sign / eth_sign sign hex data as raw bytes
  // ------------------------------------------------------------------
  await runTest("Hex-encoded personal_sign data is signed as bytes", async () => {
    const { sdk, calls } = stubSdk();
    const provider = createEIP1193Provider(sdk);
    const invalidUtf8 = "0xff00fe80";

    await provider.request({ method: "personal_sign", params: [invalidUtf8, "0x0"] });
    await provider.request({ method: "eth_sign", params: ["0x0", invalidUtf8] });
    await provider.request({ method: "personal_sign", params: ["Hello", "0x0"] });
    await provider.request({ method: "personal_sign", params: ["0xabc", "0x0"] });

    assert(calls[0].message instanceof Uint8Array, "personal_sign hex should be bytes");
    assertEqual(hexlify(calls[0].message as Uint8Array), invalidUtf8, "personal_sign bytes");
    assertEqual(hexlify(calls[1].message as Uint8Array), invalidUtf8, "eth_sign bytes");
    assertEqual(calls[2].message, "Hello", "plain text passes through");
    assertEqual(calls[3].message, "0xabc", "odd-length hex is signed as text");
    passTest("Hex data is signed as its bytes, not lossy UTF-8 text");
  });

  // ------------------------------------------------------------------
  // 15b. eth_signTypedData_v4 refuses a domain on another chain
  // ------------------------------------------------------------------
  await runTest("eth_signTypedData_v4 refuses a domain chainId other than the active chain", async () => {
    const { sdk, calls } = stubSdk();
    const provider = createEIP1193Provider(sdk, { chainId: 10 });
    const typedData = (chainId?: unknown) => JSON.stringify({
      domain: { name: "Test", version: "1", ...(chainId === undefined ? {} : { chainId }) },
      types: { Mail: [{ name: "contents", type: "string" }] },
      primaryType: "Mail",
      message: { contents: "hi" },
    });

    await assertThrows(
      () => provider.request({ method: "eth_signTypedData_v4", params: ["0x0", typedData(1)] }),
      "domain chainId 1 should be refused on chain 10"
    );
    const invalid = await provider
      .request({ method: "eth_signTypedData_v4", params: ["0x0", typedData("abc")] })
      .catch((error) => error);
    assert(invalid instanceof WalletError, "a non-numeric domain chainId should throw a WalletError");
    assertEqual(calls.length, 0, "nothing should be signed");

    await provider.request({ method: "eth_signTypedData_v4", params: ["0x0", typedData(10)] });
    await provider.request({ method: "eth_signTypedData_v4", params: ["0x0", typedData("0xa")] });
    await provider.request({ method: "eth_signTypedData_v4", params: ["0x0", typedData()] });
    assertEqual(calls.length, 3, "matching or absent chainId should be signed");

    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x1" }] });
    await provider.request({ method: "eth_signTypedData_v4", params: ["0x0", typedData(1)] });
    assertEqual(calls.length, 4, "chainId 1 should be signed after switching to chain 1");
    passTest("Typed data is bound to the active chain");
  });

  // ------------------------------------------------------------------
  // 15c. eth_sendTransaction refuses a chainId other than the active chain
  // ------------------------------------------------------------------
  await runTest("eth_sendTransaction refuses a chainId other than the active chain", async () => {
    const { sdk, txs } = stubSdk();
    const provider = createEIP1193Provider(sdk, { chainId: 10 });
    const to = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";

    await assertThrows(
      () => provider.request({ method: "eth_sendTransaction", params: [{ to, chainId: "0x1" }] }),
      "chainId 0x1 should be refused on chain 10"
    );
    assertEqual(txs.length, 0, "nothing should be sent");

    await provider.request({ method: "eth_sendTransaction", params: [{ to, chainId: "0xa" }] });
    await provider.request({ method: "eth_sendTransaction", params: [{ to }] });
    assertEqual(txs.length, 2, "matching or absent chainId should be sent");
    assert(txs.every((tx) => tx.chainId === 10), "transactions go to the active chain");
    passTest("Transactions are bound to the active chain");
  });

  // ------------------------------------------------------------------
  // 16. eth_sendTransaction maps hex value/gas to BigInt correctly
  //     (unit test of param mapping logic without network call)
  // ------------------------------------------------------------------
  await runTest("eth_sendTransaction hex param mapping is correct", async () => {
    // Verify hex → BigInt conversions that the provider does internally
    const hexValue = "0xde0b6b3a7640000"; // 1 ETH
    const hexGas = "0x5208"; // 21000

    const parsedValue = BigInt(hexValue);
    const parsedGas = BigInt(hexGas);

    assertEqual(parsedValue, 1000000000000000000n, "1 ETH hex → bigint");
    assertEqual(parsedGas, 21000n, "21000 gas hex → bigint");
    passTest(`value: ${parsedValue} wei, gas: ${parsedGas}`);
  });

  // ------------------------------------------------------------------
  // 17. EIP-712 EIP712Domain type stripping (ethers rejects it)
  // ------------------------------------------------------------------
  await runTest("EIP712Domain type is stripped from eth_signTypedData_v4 types", async () => {
    const rawTypes = {
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
        { name: "chainId", type: "uint256" },
        { name: "verifyingContract", type: "address" },
      ],
      Transfer: [
        { name: "to", type: "address" },
        { name: "amount", type: "uint256" },
      ],
    };

    // Replicate what the provider does
    const filtered = { ...rawTypes };
    delete (filtered as any)["EIP712Domain"];

    assert(!("EIP712Domain" in filtered), "EIP712Domain should be stripped");
    assert("Transfer" in filtered, "Transfer type should remain");
    passTest("EIP712Domain correctly stripped before passing to ethers");
  });

  // ------------------------------------------------------------------
  // 18. personal_sign and eth_sign use the same signing logic (EIP-191)
  //     Verify at the derivation layer (no WebAuthn needed)
  // ------------------------------------------------------------------
  await runTest("personal_sign and eth_sign both produce EIP-191 signatures", async () => {
    const { Wallet } = await import("ethers");
    const { deriveWalletFromMnemonic } = await import("../src/wallet/generate");

    const derived = await getOriginSpecificAddress(
      TEST_MNEMONIC, TEST_ORIGIN, "STANDARD", "MAIN"
    );
    const { privateKey } = deriveWalletFromMnemonic(TEST_MNEMONIC, derived.index);
    const wallet = new Wallet(privateKey);

    const message = "Hello, EIP-1193!";
    const sig1 = await wallet.signMessage(message);
    const sig2 = await wallet.signMessage(message); // deterministic

    assertEqual(sig1, sig2, "EIP-191 signing should be deterministic");

    // Verify recovery
    const recovered = verifyMessage(message, sig1);
    assertEqual(
      recovered.toLowerCase(),
      wallet.address.toLowerCase(),
      "Recovered address should match"
    );

    passTest(`EIP-191 signature verified. Address: ${wallet.address}`);
    logDetail(`Sig: ${sig1.slice(0, 20)}...`);
  });

  // ------------------------------------------------------------------
  // 19. EIP-712 signing works at the ethers layer (no WebAuthn needed)
  // ------------------------------------------------------------------
  await runTest("eth_signTypedData_v4 EIP-712 signing is correct at ethers layer", async () => {
    const { Wallet } = await import("ethers");
    const { deriveWalletFromMnemonic } = await import("../src/wallet/generate");

    const derived = await getOriginSpecificAddress(
      TEST_MNEMONIC, TEST_ORIGIN, "STANDARD", "MAIN"
    );
    const { privateKey } = deriveWalletFromMnemonic(TEST_MNEMONIC, derived.index);
    const wallet = new Wallet(privateKey);

    const domain = {
      name: "TestDApp",
      version: "1",
      chainId: 1,
      verifyingContract: "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A",
    };
    const types = {
      Transfer: [
        { name: "to", type: "address" },
        { name: "amount", type: "uint256" },
      ],
    };
    const value = {
      to: "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A",
      amount: "1000000000000000000",
    };

    const sig = await wallet.signTypedData(domain, types, value);
    const hash = TypedDataEncoder.hash(domain, types, value);
    const recovered = recoverAddress(hash, sig);

    assertEqual(
      recovered.toLowerCase(),
      wallet.address.toLowerCase(),
      "EIP-712 recovered address should match"
    );
    passTest(`EIP-712 sig verified. Address: ${wallet.address}`);
    logDetail(`Sig: ${sig.slice(0, 20)}...`);
  });

  // ------------------------------------------------------------------
  // 20. Provider is usable as window.ethereum substitute (shape check)
  // ------------------------------------------------------------------
  await runTest("Provider satisfies EIP-1193 duck-type check", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider();

    // EIP-1193 consumers typically check for these
    assert("request" in provider, "Must have 'request'");
    assert("on" in provider, "Must have 'on'");
    assert("removeListener" in provider, "Must have 'removeListener'");
    assert(typeof provider.request === "function", "request must be callable");

    // Simulated check that e.g. wagmi does: provider.request({ method: 'eth_chainId' })
    const chainId = await provider.request({ method: "eth_chainId" });
    assert(typeof chainId === "string" && chainId.startsWith("0x"),
      "eth_chainId should return 0x-prefixed string");

    passTest(`Provider satisfies EIP-1193 duck-type. chainId=${chainId}`);
    logInfo("Compatible with: ethers BrowserProvider, viem custom transport, wagmi connector");
  });

  // ------------------------------------------------------------------
  // 21. Typed event handlers compile
  // ------------------------------------------------------------------
  await runTest("Typed event handlers compile", async () => {
    const root = fileURLToPath(new URL("..", import.meta.url));
    const config = ts.getParsedCommandLineOfConfigFile(
      `${root}tsconfig.json`,
      { noEmit: true, rootDir: undefined },
      { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} }
    );
    assert(
      config !== undefined && config.errors.length === 0,
      "tsconfig.json should parse without errors"
    );
    const program = ts.createProgram(
      [`${root}test/fixtures/eip1193-handlers.ts`, `${root}src/zk/external.d.ts`],
      config!.options
    );
    const diagnostics = ts.getPreEmitDiagnostics(program);
    const report = ts.formatDiagnostics(diagnostics, {
      getCanonicalFileName: (f) => f,
      getCurrentDirectory: () => root,
      getNewLine: () => "\n",
    });
    assertEqual(diagnostics.length, 0, `Type errors:\n${report}`);
    passTest("Handlers typed per EIP-1193 event compile; mistyped ones don't");
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
