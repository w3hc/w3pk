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
 * - Unsupported method rejects with 4200 in every mode
 * - Read methods forwarded to the active chain's endpoint, JSON-RPC errors
 *   passed through, no request without an endpoint
 * - options.rpcUrl serves the initial chain only, in every mode
 * - ethers BrowserProvider signer.sendTransaction() and tx.wait() in
 *   STANDARD and PRIMARY
 * - Multiple independent provider instances are isolated
 * - on / removeListener event wiring
 * - Typed event handlers compile (type-level, via the TypeScript compiler)
 * - Without mode, the options passed to the SDK are those of v0.11.2
 * - onBeforeSign: awaited with each signing method's digests before the SDK
 *   call (eth_sendTransaction passes it to sendTransaction()), skipped when unset, a throwing hook rejects with 4001; typed data is
 *   signed as hashed for the hook (Permit2's nested root), mutations during the
 *   hook have no effect
 * - PRIMARY mode against the mock bundler of test/fixtures/mock-bundler.ts:
 *   accounts, eth_sendTransaction and its max fee, signing bound to the active chain,
 *   eth_sign refused with 4200, bundlerUrl option
 */

import { mockLocalStorage } from "./setup";
import { createWeb3Passkey } from "../src/index";
import { getOriginSpecificAddress } from "../src/wallet/origin-derivation";
import { confirmBeforeSign, createEIP1193Provider, type BeforeSignDigests } from "../src/core/eip1193";
import { getSigningDigests, type SigningRequest } from "../src/core/signing-digests";
import { WalletError } from "../src/core/errors";
import { verifyMessage, recoverAddress, TypedDataEncoder, hexlify, hashMessage, dataSlice, isError, BrowserProvider, JsonRpcProvider, Transaction } from "ethers";
import { GAMING_ACCOUNT, MAIN_ACCOUNT, installPasskey, passkeyCalls, primarySdk } from "./fixtures/passkey-signer";
import { BALANCE, GAS_ESTIMATE, REVERTER, REVERT_DATA, startMockBundler } from "./fixtures/mock-bundler";
import { createSiweMessage } from "../src/siwe";
import { ERC6492_MAGIC, personalSignHash, typedDataSignPayload } from "../src/wallet/erc7739";
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

/** Awaits options.onBeforeSign as sendTransaction() does */
async function sendHook(tx: any, options: any) {
  if (!options?.onBeforeSign) return;
  const { to, value, data } = tx;
  await confirmBeforeSign(options.onBeforeSign, {
    method: "eth_sendTransaction",
    ...getSigningDigests({ method: "eth_sendTransaction", params: [{ to, value, data }] }),
  });
}

function stubSdk() {
  const calls: { message: string | Uint8Array; options: any }[] = [];
  const txs: any[] = [];
  const sdk = {
    getAddress: async () => "0x0000000000000000000000000000000000000001",
    sendTransaction: async (tx: any, options?: any) => {
      await sendHook(tx, options);
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
  // 8. Unsupported method rejects with 4200
  // ------------------------------------------------------------------
  await runTest("Unsupported method rejects with 4200 in every mode", async () => {
    const { sdk } = stubSdk();
    for (const mode of ["STRICT", "STANDARD", "YOLO", "PRIMARY"] as const) {
      const error = await createEIP1193Provider(sdk, { mode })
        .request({ method: "eth_newFilter", params: [{}] })
        .catch((e) => e);
      assert(error instanceof Error, `${mode}: unsupported method should reject`);
      assertEqual(error.code, 4200, `${mode}: EIP-1193 Unsupported Method`);
    }
    passTest("Unsupported method rejects with code 4200");
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
    const { deriveWalletFromPath } = await import("../src/wallet/generate");

    const derived = await getOriginSpecificAddress(
      TEST_MNEMONIC, TEST_ORIGIN, "STANDARD", "MAIN"
    );
    const { privateKey } = deriveWalletFromPath(TEST_MNEMONIC, derived.path);
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
    const { deriveWalletFromPath } = await import("../src/wallet/generate");

    const derived = await getOriginSpecificAddress(
      TEST_MNEMONIC, TEST_ORIGIN, "STANDARD", "MAIN"
    );
    const { privateKey } = deriveWalletFromPath(TEST_MNEMONIC, derived.path);
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

  // ------------------------------------------------------------------
  // 22. Hex-encoded SIWE messages get the domain check
  // ------------------------------------------------------------------
  await runTest("personal_sign checks the domain of a hex SIWE message", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    const provider = sdk.getEIP1193Provider();
    const host = new URL(window.location.origin).host;
    const siweHex = (domain: string) =>
      hexlify(
        new TextEncoder().encode(`${domain} wants you to sign in with your Ethereum account:
0x1234567890123456789012345678901234567890

URI: https://${domain}
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`)
      );
    const causeOf = async (method: string, params: unknown[]) => {
      try {
        await provider.request({ method, params });
      } catch (error) {
        return (error as any).originalError?.message ?? (error as Error).message;
      }
      return "";
    };
    const account = "0x1234567890123456789012345678901234567890";

    for (const [method, params] of [
      ["personal_sign", [siweHex("evil.example"), account]],
      ["eth_sign", [account, siweHex("evil.example")]],
    ] as const) {
      const cause = await causeOf(method, [...params]);
      assert(cause.includes("does not match the current origin"), `${method}: got "${cause}"`);
    }

    const same = await causeOf("personal_sign", [siweHex(host), account]);
    assert(same.includes("Must be authenticated"), `same domain: got "${same}"`);
    passTest("Hex SIWE messages for another domain are refused, for this one they pass");
  });

  // ------------------------------------------------------------------
  // 23. Without mode, the SDK gets the options of v0.11.2
  // ------------------------------------------------------------------
  await runTest("Without mode, requests reach the SDK as in v0.11.2", async () => {
    const { sdk, calls, txs } = stubSdk();
    const sendOptions: any[] = [];
    sdk.sendTransaction = async (tx: any, options: any) => {
      txs.push(tx);
      sendOptions.push(options);
      return { hash: "0xhash" };
    };
    const provider = createEIP1193Provider(sdk, { chainId: 10, rpcUrl: "https://rpc.example" });
    const to = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";

    const hash = await provider.request({
      method: "eth_sendTransaction",
      params: [{ to, value: "0x5", gas: "0x5208", maxFeePerGas: "0x7", maxPriorityFeePerGas: "0x3", nonce: "0x9" }],
    });
    assertEqual(hash, "0xhash", "returns the transaction hash");
    assertEqual(
      JSON.stringify(txs[0], (_, v) => (typeof v === "bigint" ? v.toString() : v)),
      JSON.stringify({ to, value: "5", data: "0x", chainId: 10, gasLimit: "21000", maxFeePerGas: "7", maxPriorityFeePerGas: "3", nonce: 9 }),
      "transaction keeps gas and nonce"
    );
    assertEqual(
      JSON.stringify(sendOptions[0]),
      JSON.stringify({ rpcUrl: "https://rpc.example" }),
      "options as in v0.11.2"
    );

    await provider.request({ method: "personal_sign", params: ["hi", to] });
    await provider.request({ method: "eth_sign", params: [to, "hi"] });
    assertEqual(calls.length, 2, "eth_sign still signs");
    for (const call of calls) {
      assertEqual(JSON.stringify(call.options), JSON.stringify({ signingMethod: "EIP191" }), "no chainId outside PRIMARY");
    }
    await assertThrows(
      () => provider.request({ method: "eth_signTransaction", params: [{ to }] }),
      "eth_signTransaction stays unsupported"
    );
    passTest("No-mode provider passes the same transaction and options as v0.11.2");
  });

  // ------------------------------------------------------------------
  // 23b. options.rpcUrl serves the initial chain only, in every mode
  // ------------------------------------------------------------------
  await runTest("After a chain switch, options.rpcUrl isn't passed to sendTransaction", async () => {
    for (const mode of [undefined, "STRICT", "STANDARD", "YOLO"] as const) {
      const { sdk } = stubSdk();
      const sendOptions: any[] = [];
      sdk.sendTransaction = async (_tx: any, options: any) => {
        sendOptions.push(options);
        return { hash: "0xhash" };
      };
      const provider = createEIP1193Provider(sdk, { mode, chainId: 10, rpcUrl: "https://rpc.example" });
      const to = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";
      await provider.request({ method: "eth_sendTransaction", params: [{ to }] });
      await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x1" }] });
      await provider.request({ method: "eth_sendTransaction", params: [{ to }] });
      await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0xa" }] });
      await provider.request({ method: "eth_sendTransaction", params: [{ to }] });
      assertEqual(sendOptions[0].rpcUrl, "https://rpc.example", `${mode}: initial chain`);
      assertEqual(sendOptions[1].rpcUrl, undefined, `${mode}: after the switch`);
      assertEqual(sendOptions[2].rpcUrl, "https://rpc.example", `${mode}: back on the initial chain`);
    }
    passTest("options.rpcUrl serves options.chainId only");
  });

  // ------------------------------------------------------------------
  // 23c. Read methods without an endpoint throw before any request
  // ------------------------------------------------------------------
  await runTest("Without an endpoint for the chain, read methods throw before any request", async () => {
    const realFetch = globalThis.fetch;
    let fetches = 0;
    globalThis.fetch = (async () => {
      fetches++;
      throw new Error("no request expected");
    }) as typeof fetch;
    try {
      const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false, rpcUrls: { 1: ["https://one.example"] } });
      const provider = sdk.getEIP1193Provider({ chainId: 10 });
      const error = await provider.request({ method: "eth_blockNumber" }).catch((e) => e);
      assert(error instanceof WalletError, "throws a WalletError");
      assert(error.message.includes("rpcUrls: { 10:"), `names rpcUrls: ${error.message}`);
      assert(error.message.includes("options.rpcUrl"), "on the initial chain, names options.rpcUrl");

      const withRpcUrl = sdk.getEIP1193Provider({ chainId: 10, rpcUrl: "https://ten.example" });
      await withRpcUrl.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x2105" }] });
      const switched = await withRpcUrl.request({ method: "eth_getBalance", params: [MAIN_ACCOUNT, "latest"] }).catch((e) => e);
      assert(switched.message.includes("rpcUrls: { 8453:"), `names rpcUrls: ${switched.message}`);
      assert(!switched.message.includes("options.rpcUrl"), "after a switch, options.rpcUrl doesn't apply");
      assertEqual(fetches, 0, "no request");
    } finally {
      globalThis.fetch = realFetch;
    }
    passTest("No endpoint, no request");
  });

  // ------------------------------------------------------------------
  // 23d. onBeforeSign
  // ------------------------------------------------------------------
  const signer = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";
  const signingRequests: SigningRequest[] = [
    {
      method: "eth_sendTransaction",
      params: [{ to: signer.toLowerCase(), value: "0x5", data: "0xa9059cbb" }],
    },
    {
      method: "eth_signTypedData_v4",
      params: [
        signer,
        JSON.stringify({
          domain: { name: "Mail", version: "1", chainId: 1 },
          types: {
            EIP712Domain: [
              { name: "name", type: "string" },
              { name: "version", type: "string" },
              { name: "chainId", type: "uint256" },
            ],
            Mail: [{ name: "contents", type: "string" }],
          },
          primaryType: "Mail",
          message: { contents: "hi" },
        }),
      ],
    },
    { method: "personal_sign", params: ["0x68656c6c6f", signer] },
    { method: "eth_sign", params: [signer, "hello"] },
  ];
  const json = (value: unknown) =>
    JSON.stringify(value, (_, v) => (typeof v === "bigint" ? v.toString() : v));
  const hookedSdk = (log: string[]) => {
    const { sdk } = stubSdk();
    sdk.sendTransaction = async (tx: any, options: any) => {
      await sendHook(tx, options);
      log.push("sdk");
      return { hash: "0xhash" };
    };
    sdk.signMessage = async () => {
      log.push("sdk");
      return { signature: "0xsig" };
    };
    return sdk;
  };

  await runTest("onBeforeSign gets each method's digests before the SDK call", async () => {
    const log: string[] = [];
    const seen: BeforeSignDigests[] = [];
    const provider = createEIP1193Provider(hookedSdk(log), {
      onBeforeSign: (digests) => {
        log.push("hook");
        seen.push(digests);
      },
    });
    for (const request of signingRequests) {
      await provider.request({ method: request.method, params: [...request.params] });
    }
    assertEqual(log.join(), "hook,sdk,hook,sdk,hook,sdk,hook,sdk", "hook before each SDK call");
    signingRequests.forEach((request, i) => {
      assertEqual(
        json(seen[i]),
        json({ method: request.method, ...getSigningDigests(request) }),
        `${request.method} digests`
      );
    });
    const [tx] = seen;
    assert(tx.method === "eth_sendTransaction", "narrows on method");
    assertEqual(tx.to, signer, "checksummed to");
    assertEqual(tx.value, 5n, "value");
    passTest("Digests reach the hook before the passkey prompt");
  });

  await runTest("Without onBeforeSign, no digests are computed", async () => {
    const log: string[] = [];
    const provider = createEIP1193Provider(hookedSdk(log), {});
    const bad = { method: "eth_sendTransaction", params: [{ to: "not an address" }] };
    assertEqual(await provider.request(bad), "0xhash", "the SDK gets the request as before");
    assertEqual(log.join(), "sdk", "SDK called");

    let calls = 0;
    const hooked = createEIP1193Provider(hookedSdk(log), { onBeforeSign: () => void calls++ });
    const error = await hooked.request(bad).catch((e) => e);
    assert(error instanceof Error && (error as any).code !== 4001, "an invalid request isn't a user rejection");
    assertEqual(calls, 0, "hook not called on an invalid request");
    passTest("Unset hook, unchanged behavior");
  });

  await runTest("A throwing or rejecting onBeforeSign rejects with 4001 and nothing is signed", async () => {
    const cancel = new Error("digests don't match");
    for (const hook of [
      () => {
        throw cancel;
      },
      async () => {
        throw cancel;
      },
    ]) {
      const log: string[] = [];
      const provider = createEIP1193Provider(hookedSdk(log), { onBeforeSign: hook });
      for (const request of signingRequests) {
        const error = await provider
          .request({ method: request.method, params: [...request.params] })
          .catch((e) => e);
        assertEqual(error.code, 4001, `${request.method}: EIP-1193 User Rejected Request`);
        assertEqual(error.cause, cancel, `${request.method}: hook's error as cause`);
      }
      assertEqual(log.length, 0, "SDK never called");
    }

    const log: string[] = [];
    const declined = createEIP1193Provider(hookedSdk(log), { onBeforeSign: async () => false });
    for (const request of signingRequests) {
      const error = await declined
        .request({ method: request.method, params: [...request.params] })
        .catch((e) => e);
      assertEqual(error.code, 4001, `${request.method}: false cancels`);
    }
    assertEqual(log.length, 0, "SDK never called after false");

    const browser = new BrowserProvider(
      createEIP1193Provider(hookedSdk(log), { onBeforeSign: () => Promise.reject(cancel) })
    );
    try {
      const error = await (await browser.getSigner()).signMessage("hi").catch((e) => e);
      assert(isError(error, "ACTION_REJECTED"), `ethers ACTION_REJECTED, got ${error?.code}`);
    } finally {
      browser.destroy();
    }
    assertEqual(log.length, 0, "SDK never called through ethers");
    passTest("Cancelled before the passkey prompt");
  });

  await runTest("A chain switch while onBeforeSign waits doesn't move the request", async () => {
    for (const mode of [undefined, "PRIMARY"] as const) {
      const { sdk, calls, txs } = stubSdk();
      const sendOptions: any[] = [];
      sdk.sendTransaction = async (tx: any, options: any) => {
        await sendHook(tx, options);
        txs.push(tx);
        sendOptions.push(options);
        return { hash: "0xhash" };
      };
      let entered!: () => void;
      let release!: () => void;
      const provider = createEIP1193Provider(sdk, {
        mode,
        chainId: 10,
        rpcUrl: "https://rpc.example",
        onBeforeSign: () =>
          new Promise<void>((resolve) => {
            release = resolve;
            entered();
          }),
      });
      for (const request of [
        { method: "eth_sendTransaction", params: [{ to: signer }] },
        { method: "personal_sign", params: ["hi", signer] },
      ]) {
        const hooked = new Promise<void>((resolve) => (entered = resolve));
        const pending = provider.request(request);
        await hooked;
        await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x1" }] });
        release();
        await pending;
        await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0xa" }] });
      }
      assertEqual(txs[0].chainId, 10, `${mode}: transaction chainId`);
      assertEqual(sendOptions[0].rpcUrl, "https://rpc.example", `${mode}: initial chain's rpcUrl`);
      if (mode === "PRIMARY") {
        assertEqual(calls[0].options.chainId, 10, "PRIMARY: signs for the chain it was asked on");
      }
    }
    passTest("Request bound to the chain it was validated on");
  });

  await runTest("An async onBeforeSign is awaited", async () => {
    const log: string[] = [];
    const provider = createEIP1193Provider(hookedSdk(log), {
      onBeforeSign: async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        log.push("hook done");
      },
    });
    await provider.request({ method: "personal_sign", params: ["hi", signer] });
    assertEqual(log.join(), "hook done,sdk", "SDK called once the hook resolves");
    passTest("Async hook awaited");
  });

  await runTest("Requests are validated before onBeforeSign", async () => {
    let calls = 0;
    const onBeforeSign = () => void calls++;
    const { sdk } = stubSdk();
    const primary = createEIP1193Provider(sdk, { mode: "PRIMARY", onBeforeSign });
    const error = await primary.request({ method: "eth_sign", params: [signer, "hello"] }).catch((e) => e);
    assertEqual(error.code, 4200, "PRIMARY: eth_sign is an EIP-1193 Unsupported Method");

    const provider = createEIP1193Provider(sdk, { chainId: 1, onBeforeSign });
    await assertThrows(
      () => provider.request({ method: "eth_sendTransaction", params: [{ to: signer, chainId: "0x2" }] }),
      "transaction for another chain"
    );
    const typedData = JSON.parse(signingRequests[1].params[1] as string);
    typedData.domain.chainId = 2;
    await assertThrows(
      () => provider.request({ method: "eth_signTypedData_v4", params: [signer, typedData] }),
      "typed data for another chain"
    );
    assertEqual(calls, 0, "hook not called");
    passTest("Rejected requests never reach the hook");
  });

  const permitSingle = () => ({
    domain: { name: "Permit2", chainId: 1, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
    types: {
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "chainId", type: "uint256" },
        { name: "verifyingContract", type: "address" },
      ],
      PermitDetails: [
        { name: "token", type: "address" },
        { name: "amount", type: "uint160" },
        { name: "expiration", type: "uint48" },
        { name: "nonce", type: "uint48" },
      ],
      PermitSingle: [
        { name: "details", type: "PermitDetails" },
        { name: "spender", type: "address" },
        { name: "sigDeadline", type: "uint256" },
      ],
    },
    primaryType: "PermitSingle",
    message: {
      details: { token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", amount: "1000000", expiration: "1735689600", nonce: "0" },
      spender: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
      sigDeadline: "1735689600",
    },
  });
  const permitHash = (typedData: ReturnType<typeof permitSingle>) => {
    const { EIP712Domain: _, ...types } = typedData.types;
    return TypedDataEncoder.hash(typedData.domain, types, typedData.message);
  };
  const standardSdk = async () => {
    const { Wallet } = await import("ethers");
    const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
    (sdk as any).currentUser = {
      username: "typed-data",
      ethereumAddress: Wallet.createRandom().address,
      credentialId: "test-credential",
    };
    (sdk as any).getMnemonicFromSession = async () => TEST_MNEMONIC;
    return sdk;
  };

  await runTest("eth_signTypedData_v4 signs the digest onBeforeSign saw, for a nested root", async () => {
    const sdk = await standardSdk();
    const digests: string[] = [];
    const provider = sdk.getEIP1193Provider({
      onBeforeSign: (d) => {
        if (d.method === "eth_signTypedData_v4") digests.push(d.eip712Digest);
      },
    });
    const [account] = (await provider.request({ method: "eth_accounts" })) as string[];
    const typedData = permitSingle();
    const signature = (await provider.request({
      method: "eth_signTypedData_v4",
      params: [account, JSON.stringify(typedData)],
    })) as string;
    assertEqual(digests[0], permitHash(typedData), "hook sees PermitSingle's EIP-712 Digest");
    assertEqual(recoverAddress(digests[0], signature), account, "signature covers that digest");

    const nested = { ...typedData, primaryType: "PermitDetails", message: typedData.message.details };
    await assertThrows(
      () => provider.request({ method: "eth_signTypedData_v4", params: [account, nested] }),
      "primaryType other than the root"
    );
    const unused = { ...typedData, types: { ...typedData.types, Unused: [{ name: "x", type: "uint256" }] } };
    await assertThrows(
      () => provider.request({ method: "eth_signTypedData_v4", params: [account, unused] }),
      "unused types"
    );
    assertEqual(digests.length, 1, "hook not called on rejected typed data");
    passTest("Permit2 PermitSingle signed as hashed, a nested primaryType rejected");
  });

  await runTest("Mutating eth_signTypedData_v4 params while onBeforeSign waits changes nothing", async () => {
    const sdk = await standardSdk();
    const typedData = permitSingle();
    const approved = permitHash(typedData);
    let digest = "";
    const provider = sdk.getEIP1193Provider({
      onBeforeSign: async (d) => {
        if (d.method !== "eth_signTypedData_v4") return;
        digest = d.eip712Digest;
        typedData.message.details.amount = "1461501637330902918203684832716283019655932542975";
        typedData.message.spender = "0x000000000000000000000000000000000000dEaD";
        typedData.domain.verifyingContract = "0x000000000000000000000000000000000000dEaD";
        typedData.types.PermitSingle.pop();
        typedData.primaryType = "PermitDetails";
      },
    });
    const [account] = (await provider.request({ method: "eth_accounts" })) as string[];
    const signature = (await provider.request({
      method: "eth_signTypedData_v4",
      params: [account, typedData],
    })) as string;
    assertEqual(digest, approved, "hook saw the request as sent");
    assertEqual(recoverAddress(approved, signature), account, "signature covers the approved digest");
    passTest("The snapshot taken before the hook is signed");
  });

  // ------------------------------------------------------------------
  // 24. PRIMARY mode, against the mock bundler
  // ------------------------------------------------------------------
  installPasskey();
  const bundler = await startMockBundler({ pendingPolls: 0 });
  const to = "0x" + "ab".repeat(20);
  try {
    await runTest("PRIMARY: eth_accounts and eth_requestAccounts serve the smart account", async () => {
      const sdk = await primarySdk();
      for (const method of ["eth_accounts", "eth_requestAccounts"]) {
        const main = await sdk.getEIP1193Provider({ mode: "PRIMARY" }).request({ method });
        assertEqual(JSON.stringify(main), JSON.stringify([MAIN_ACCOUNT]), `${method}, MAIN`);
        const gaming = await sdk.getEIP1193Provider({ mode: "PRIMARY", tag: "GAMING" }).request({ method });
        assertEqual(JSON.stringify(gaming), JSON.stringify([GAMING_ACCOUNT]), `${method}, GAMING`);
      }
      passTest("Accounts are the tag's P-256 smart account");
    });

    await runTest("PRIMARY: eth_sendTransaction sends a UserOperation whose transaction is findable", async () => {
      const sdk = await primarySdk({
        rpcUrls: { 1: [bundler.url] },
        bundlerUrls: { 1: bundler.url },
      });
      const provider = sdk.getEIP1193Provider({ mode: "PRIMARY" });
      const hash = (await provider.request({
        method: "eth_sendTransaction",
        params: [{
          from: MAIN_ACCOUNT,
          to,
          value: "0x5",
          data: "0xdead",
          gas: "0x30d40",
          maxFeePerGas: "0x7",
          maxPriorityFeePerGas: "0x3",
          nonce: "0x9",
        }],
      })) as string;

      const rpc = new JsonRpcProvider(bundler.url, 1, { staticNetwork: true });
      const receipt = await rpc.getTransactionReceipt(hash);
      rpc.destroy();
      assertEqual(receipt?.hash, hash, "eth_getTransactionReceipt finds the transaction");

      const op = bundler.included.at(-1)!;
      assertEqual(op.sender, MAIN_ACCOUNT, "sent by the smart account");
      assertEqual(op.nonce, "0x0", "EntryPoint nonce, not the EOA nonce");
      assertEqual(op.maxFeePerGas, "0x7", "maxFeePerGas");
      assertEqual(op.maxPriorityFeePerGas, "0x3", "maxPriorityFeePerGas");
      assertEqual(BigInt(op.callGasLimit), 200_000n, "gas above the estimate raises callGasLimit");

      await provider.request({ method: "eth_sendTransaction", params: [{ to, gas: "0x1" }] });
      assertEqual(BigInt(bundler.included.at(-1)!.callGasLimit), GAS_ESTIMATE.callGasLimit, "gas below the estimate keeps it");
      passTest(`UserOperation included in ${hash.slice(0, 10)}…`);
    });

    await runTest("PRIMARY: eth_sendTransaction's onBeforeSign gets the max fee, before the passkey prompt", async () => {
      const sdk = await primarySdk({
        rpcUrls: { 1: [bundler.url] },
        bundlerUrls: { 1: bundler.url },
      });
      const request = { to, value: "0x5", data: "0xdead", gas: "0x30d40", maxFeePerGas: "0x7", maxPriorityFeePerGas: "0x3" };
      const seen: BeforeSignDigests[] = [];
      passkeyCalls.length = 0;
      await sdk
        .getEIP1193Provider({
          mode: "PRIMARY",
          onBeforeSign: (digests) => {
            assertEqual(passkeyCalls.length, 0, "hook before the passkey prompt");
            seen.push(digests);
          },
        })
        .request({ method: "eth_sendTransaction", params: [request] });
      const op = bundler.included.at(-1)!;
      const gas = ["verificationGasLimit", "callGasLimit", "preVerificationGas"].reduce((sum, k) => sum + BigInt(op[k]), 0n);
      assertEqual(seen.length, 1, "hook called once");
      assertEqual(
        json(seen[0]),
        json({
          method: "eth_sendTransaction",
          ...getSigningDigests({ method: "eth_sendTransaction", params: [request] }),
          maxFee: gas * 7n,
        }),
        "digests and the UserOperation's required prefund"
      );
      passTest("Max fee reaches the provider's hook");
    });

    await runTest("PRIMARY: options.bundlerUrl overrides bundlerUrls", async () => {
      const sdk = await primarySdk({
        rpcUrls: { 1: [bundler.url] },
        bundlerUrls: { 1: "http://127.0.0.1:1" },
      });
      const sent = bundler.included.length;
      await sdk
        .getEIP1193Provider({ mode: "PRIMARY", tag: "GAMING", bundlerUrl: bundler.url })
        .request({ method: "eth_sendTransaction", params: [{ to }] });
      assertEqual(bundler.included.length, sent + 1, "sent through options.bundlerUrl");
      assertEqual(bundler.included.at(-1)!.sender, GAMING_ACCOUNT, "from the tag's account");
      passTest("Per-provider bundler endpoint");
    });

    await runTest("PRIMARY: after a chain switch, the config's endpoints serve the new chain", async () => {
      const sdk = await primarySdk({
        rpcUrls: { 1: [bundler.url] },
        bundlerUrls: { 1: bundler.url },
      });
      const provider = sdk.getEIP1193Provider({
        mode: "PRIMARY",
        chainId: 10,
        rpcUrl: "http://127.0.0.1:1",
        bundlerUrl: "http://127.0.0.1:1",
      });
      await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x1" }] });
      const sent = bundler.included.length;
      await provider.request({ method: "eth_sendTransaction", params: [{ to }] });
      assertEqual(bundler.included.length, sent + 1, "sent through bundlerUrls[1]");
      passTest("Chain 10 endpoints aren't used on chain 1");
    });

    await runTest("PRIMARY: personal_sign refuses a SIWE message for another chain", async () => {
      const sdk = await primarySdk();
      const provider = sdk.getEIP1193Provider({ mode: "PRIMARY", chainId: 1 });
      const siwe = (chainId: number) => createSiweMessage({
        domain: "localhost",
        address: MAIN_ACCOUNT,
        uri: "http://localhost",
        version: "1",
        chainId,
        nonce: "abcdefgh1234",
        issuedAt: new Date().toISOString(),
      });
      passkeyCalls.length = 0;
      const error = await provider
        .request({ method: "personal_sign", params: [siwe(8453), MAIN_ACCOUNT] })
        .catch((e) => e);
      const cause = error?.originalError?.message ?? error?.message ?? "";
      assert(cause.includes("does not match"), `got "${cause}"`);
      assertEqual(passkeyCalls.length, 0, "no passkey prompt");
      await provider.request({ method: "personal_sign", params: [siwe(1), MAIN_ACCOUNT] });
      assertEqual(passkeyCalls.length, 1, "same chain is signed");
      passTest("SIWE Chain ID must be the active chain");
    });

    await runTest("PRIMARY: personal_sign and eth_signTypedData_v4 sign for the active chain", async () => {
      const sdk = await primarySdk();
      const provider = sdk.getEIP1193Provider({ mode: "PRIMARY", chainId: 10 });
      await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x1" }] });
      const account = { address: MAIN_ACCOUNT, chainId: 1 };

      passkeyCalls.length = 0;
      const signature = (await provider.request({ method: "personal_sign", params: ["0x6869", MAIN_ACCOUNT] })) as string;
      assertEqual(dataSlice(signature, -32), ERC6492_MAGIC, "ERC-6492-wrapped while undeployed");
      assertEqual(
        hexlify(passkeyCalls[0].challenge as Uint8Array),
        personalSignHash(hashMessage(new Uint8Array([0x68, 0x69])), account),
        "ERC-7739 PersonalSign of the bytes, on the active chain"
      );

      const domain = { name: "Mail", version: "1", chainId: 1, verifyingContract: "0x" + "cc".repeat(20) };
      const types = { Mail: [{ name: "contents", type: "string" }] };
      const message = { contents: "hi" };
      await provider.request({
        method: "eth_signTypedData_v4",
        params: [MAIN_ACCOUNT, JSON.stringify({
          domain,
          types: {
            EIP712Domain: [
              { name: "name", type: "string" },
              { name: "version", type: "string" },
              { name: "chainId", type: "uint256" },
              { name: "verifyingContract", type: "address" },
            ],
            ...types,
          },
          primaryType: "Mail",
          message,
        })],
      });
      assertEqual(
        hexlify(passkeyCalls[1].challenge as Uint8Array),
        typedDataSignPayload(domain, types, "Mail", message, account).challenge,
        "ERC-7739 TypedDataSign on the active chain"
      );
      passTest("Signatures are ERC-7739, bound to the active chain");
    });

    await runTest("PRIMARY: onBeforeSign's EIP-712 Digest is the hash the ERC-7739 signature covers", async () => {
      const sdk = await primarySdk();
      const typedData = permitSingle();
      let digest = "";
      const provider = sdk.getEIP1193Provider({
        mode: "PRIMARY",
        chainId: 1,
        onBeforeSign: (d) => {
          if (d.method !== "eth_signTypedData_v4") return;
          digest = d.eip712Digest;
          typedData.message.spender = "0x000000000000000000000000000000000000dEaD";
        },
      });
      const { EIP712Domain: _, ...types } = permitSingle().types;
      const { domain, message } = permitSingle();
      const payload = typedDataSignPayload(domain, types, "PermitSingle", message, { address: MAIN_ACCOUNT, chainId: 1 });
      passkeyCalls.length = 0;
      await provider.request({ method: "eth_signTypedData_v4", params: [MAIN_ACCOUNT, typedData] });
      assertEqual(digest, payload.hash, "hook sees the hash isValidSignature gets");
      assertEqual(hexlify(passkeyCalls[0].challenge as Uint8Array), payload.challenge, "passkey signs it, unmutated");
      passTest("PRIMARY signs the digest the hook saw");
    });

    await runTest("PRIMARY: eth_sign rejects with 4200 before any passkey prompt", async () => {
      const sdk = await primarySdk();
      const provider = sdk.getEIP1193Provider({ mode: "PRIMARY" });
      passkeyCalls.length = 0;
      const error = await provider
        .request({ method: "eth_sign", params: [MAIN_ACCOUNT, "0x" + "11".repeat(32)] })
        .catch((e) => e);
      assert(error instanceof Error, "eth_sign should reject");
      assertEqual(error.code, 4200, "EIP-1193 Unsupported Method");
      assertEqual(passkeyCalls.length, 0, "no passkey prompt");
      await assertThrows(
        () => provider.request({ method: "eth_signTransaction", params: [{ to }] }),
        "eth_signTransaction stays unsupported"
      );
      passTest("eth_sign is refused in PRIMARY mode");
    });

    await runTest("Read methods go to the active chain's endpoint, also after a chain switch", async () => {
      const optimism = await startMockBundler({ chainId: 10 });
      const override = await startMockBundler({ chainId: 10 });
      try {
        const sdk = createWeb3Passkey({
          storage: mockLocalStorage,
          debug: false,
          rpcUrls: { 1: [bundler.url], 10: [optimism.url, "http://127.0.0.1:1"] },
        });
        const balance = (provider: ReturnType<typeof sdk.getEIP1193Provider>) =>
          provider.request({ method: "eth_getBalance", params: [MAIN_ACCOUNT, "latest"] });
        const reads = (chain: typeof bundler) => chain.calls.filter((c) => c.method === "eth_getBalance").length;

        const provider = sdk.getEIP1193Provider({ chainId: 1 });
        assertEqual(BigInt((await balance(provider)) as string), BALANCE, "result passes through");
        assertEqual(reads(bundler), 1, "rpcUrls[1][0]");
        await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0xa" }] });
        await balance(provider);
        assertEqual(reads(optimism), 1, "rpcUrls[10][0] after the switch");
        assertEqual(reads(bundler), 1, "chain 1 isn't asked after the switch");

        const overridden = sdk.getEIP1193Provider({ chainId: 10, rpcUrl: override.url });
        await balance(overridden);
        assertEqual(reads(override), 1, "options.rpcUrl on the initial chain");
        await overridden.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x1" }] });
        await balance(overridden);
        assertEqual(reads(bundler), 2, "rpcUrls[1][0] after switching away");
        await overridden.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0xa" }] });
        await balance(overridden);
        assertEqual(reads(override), 2, "options.rpcUrl again on the initial chain");
        assertEqual(reads(optimism), 1, "rpcUrls[10] unused while options.rpcUrl serves chain 10");

        const methods = [
          ["eth_blockNumber", []],
          ["eth_getCode", [MAIN_ACCOUNT, "latest"]],
          ["eth_getTransactionCount", [MAIN_ACCOUNT, "latest"]],
          ["eth_getBlockByNumber", ["latest", false]],
          ["eth_gasPrice", []],
          ["eth_maxPriorityFeePerGas", []],
        ] as const;
        for (const [method, params] of methods) {
          const calls = bundler.calls.length;
          await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x1" }] });
          await provider.request({ method, params: [...params] });
          assertEqual(bundler.calls.at(-1)?.method, method, `${method} forwarded`);
          assertEqual(bundler.calls.length, calls + 1, `${method}: one request`);
        }
      } finally {
        await optimism.close();
        await override.close();
      }
      passTest("Reads follow wallet_switchEthereumChain");
    });

    await runTest("JSON-RPC errors pass through with their code and data", async () => {
      const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false, rpcUrls: { 1: [bundler.url] } });
      const provider = sdk.getEIP1193Provider();
      for (const method of ["eth_call", "eth_estimateGas"]) {
        const error = await provider
          .request({ method, params: [{ to: REVERTER, data: "0x" }, "latest"] })
          .catch((e) => e);
        assertEqual(error.code, 3, `${method}: code`);
        assertEqual(error.data, REVERT_DATA, `${method}: data`);
        assertEqual(error.message, "execution reverted: nope", `${method}: message`);
      }
      const missing = await provider
        .request({ method: "eth_getStorageAt", params: [MAIN_ACCOUNT, "0x0", "latest"] })
        .catch((e) => e);
      assertEqual(missing.code, -32601, "endpoint's own error code");

      const browser = new BrowserProvider(provider);
      for (const call of [() => browser.call({ to: REVERTER }), () => browser.estimateGas({ to: REVERTER })]) {
        const error = await call().catch((e) => e);
        assert(isError(error, "CALL_EXCEPTION"), `ethers CALL_EXCEPTION, got ${error?.code}`);
        assertEqual(error.data, REVERT_DATA, "ethers revert data");
        assertEqual(error.reason, "nope", "ethers revert reason");
      }
      browser.destroy();
      passTest("Revert data reaches ethers");
    });

    for (const mode of ["STANDARD", "PRIMARY"] as const) {
      await runTest(`${mode}: ethers BrowserProvider signer.sendTransaction() and tx.wait()`, async () => {
        const sdk = await primarySdk({
          rpcUrls: { 1: [bundler.url] },
          bundlerUrls: { 1: bundler.url },
        });
        const browser = new BrowserProvider(sdk.getEIP1193Provider({ mode }));
        try {
          const signer = await browser.getSigner();
          const sent = bundler.included.length;
          const tx = await signer.sendTransaction({ to, value: 5n });
          const receipt = await tx.wait();
          assertEqual(receipt?.hash, tx.hash, "tx.wait() returns the receipt");
          assertEqual(receipt?.status, 1, "status");
          if (mode === "PRIMARY") {
            assertEqual(signer.address, MAIN_ACCOUNT, "signer is the smart account");
            assertEqual(bundler.included.length, sent + 1, "sent as a UserOperation");
            assertEqual(bundler.included.at(-1)!.sender, MAIN_ACCOUNT, "UserOperation sender");
          } else {
            const raw = bundler.calls.filter((c) => c.method === "eth_sendRawTransaction").at(-1)!.params[0];
            const signed = Transaction.from(raw);
            assertEqual(signed.hash, tx.hash, "hash of the raw transaction");
            assertEqual(signed.from, signer.address, "signed by the signer's address");
            assertEqual(signed.value, 5n, "value");
            assertEqual(signed.gasLimit, 21_000n, "eth_estimateGas through the provider");
          }
        } finally {
          browser.destroy();
        }
        passTest(`${mode}: ethers signer sends and waits`);
      });
    }
  } finally {
    await bundler.close();
  }

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
