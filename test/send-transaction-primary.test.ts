/**
 * PRIMARY mode sendTransaction (#297): the passkey's P-256 smart account
 * sends EntryPoint v0.9 UserOperations through a bundler, here the in-process
 * mock of test/fixtures/mock-bundler.ts
 *
 * Onchain validation of SDK-made UserOperations is in
 * contracts/test/W3pkAccountUserOp.t.sol
 */

import assert from "node:assert";
import { AbiCoder, Interface, JsonRpcProvider, concat, keccak256 } from "ethers";
import { GAMING_ACCOUNT, MAIN_ACCOUNT, QX, QY, installPasskey, passkeyCalls, primarySdk } from "./fixtures/passkey-signer";
import {
  BASE_FEE,
  GAS_ESTIMATE,
  PAYMASTER,
  PRIORITY_FEE,
  REVERT_DATA,
  type MockBundler,
  startMockBundler,
} from "./fixtures/mock-bundler";
import { W3PK_ACCOUNT_FACTORY } from "../src/wallet/smart-account";
import { UserRejectedRequestError, getSigningDigests, type TransactionRequest } from "../src/index";
import {
  P256_PRECOMPILE_GAS,
  P256_SOLIDITY_GAS,
  PAYMASTER_SIG_MAGIC,
  encodeExecute,
  getUserOperationHash,
  paymasterAndDataHash,
  type UserOperation,
} from "../src/wallet/user-operation";

const coder = AbiCoder.defaultAbiCoder();
const account = new Interface(["function execute(bytes32 mode, bytes executionCalldata)"]);
const factory = new Interface(["function createAccount(bytes32 qx, bytes32 qy, string tag) returns (address)"]);
const RECIPIENT = "0x" + "ab".repeat(20);
const TOKEN = "0x" + "cd".repeat(20);

async function rejection(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    return (error as Error).message;
  }
  throw new Error("expected a rejection");
}

async function withBundler(
  options: Parameters<typeof startMockBundler>[0],
  run: (bundler: MockBundler) => Promise<void>
) {
  const bundler = await startMockBundler({ pendingPolls: 0, ...options });
  try {
    await run(bundler);
  } finally {
    await bundler.close();
  }
}

const config = (bundler: MockBundler, extra: object = {}) => ({
  rpcUrls: { [bundler.chainId]: [bundler.url] },
  bundlerUrls: { [bundler.chainId]: bundler.url },
  ...extra,
});

async function runTests() {
  console.log("\n📦 PRIMARY mode sendTransaction tests\n");
  installPasskey();

  console.log("Test 1: first transaction deploys the account, and returns a findable transaction hash");
  await withBundler({ pendingPolls: 1 }, async (bundler) => {
    const sdk = await primarySdk(config(bundler));
    passkeyCalls.length = 0;
    const result = await sdk.sendTransaction({ to: RECIPIENT, value: 5n, data: "0xdead", chainId: 1 }, { mode: "PRIMARY" });

    assert.strictEqual(result.from, MAIN_ACCOUNT);
    assert.strictEqual(result.mode, "PRIMARY");
    assert.strictEqual(result.tag, "MAIN");
    assert.strictEqual(result.chainId, 1);
    assert.notStrictEqual(result.hash, result.userOpHash, "hash is the transaction's, not the userOpHash");

    const [op] = bundler.included;
    assert.strictEqual(op.sender, MAIN_ACCOUNT);
    assert.strictEqual(op.nonce, "0x0");
    assert.strictEqual(op.factory, W3PK_ACCOUNT_FACTORY);
    assert.deepStrictEqual(
      [...factory.decodeFunctionData("createAccount", op.factoryData)],
      [QX, QY, "MAIN"],
      "factoryData deploys this account"
    );
    const [mode, executionCalldata] = account.decodeFunctionData("execute", op.callData);
    assert.strictEqual(mode, "0x" + "00".repeat(32), "single call mode");
    assert.strictEqual(executionCalldata, concat([RECIPIENT, coder.encode(["uint256"], [5n]), "0xdead"]));

    assert.strictEqual(passkeyCalls.length, 1, "one passkey assertion");
    assert.strictEqual(Buffer.from(passkeyCalls[0].challenge as Uint8Array).toString("hex"), result.userOpHash!.slice(2));
    assert.strictEqual(BigInt(op.verificationGasLimit), GAS_ESTIMATE.verificationGasLimit + P256_PRECOMPILE_GAS);
    assert.strictEqual(BigInt(op.callGasLimit), GAS_ESTIMATE.callGasLimit);
    assert.strictEqual(BigInt(op.preVerificationGas), GAS_ESTIMATE.preVerificationGas);
    assert.strictEqual(BigInt(op.maxPriorityFeePerGas), PRIORITY_FEE, "fees from the chain RPC");
    assert.strictEqual(BigInt(op.maxFeePerGas), 2n * BASE_FEE + PRIORITY_FEE);
    assert.strictEqual(op.paymaster, undefined, "no paymaster: the account pays");

    const provider = new JsonRpcProvider(bundler.url, 1, { staticNetwork: true });
    const receipt = await provider.getTransactionReceipt(result.hash);
    provider.destroy();
    assert.strictEqual(receipt?.hash, result.hash, "eth_getTransactionReceipt finds it");
    assert(bundler.deployed.has(MAIN_ACCOUNT.toLowerCase()), "account deployed");
    console.log("✅ First transaction deploys the account");

    console.log("\nTest 2: next transaction has no factory and the next nonce");
    await sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY" });
    assert.strictEqual(bundler.included[1].factory, undefined);
    assert.strictEqual(bundler.included[1].factoryData, undefined);
    assert.strictEqual(bundler.included[1].nonce, "0x1");
    console.log("✅ Deployed account sends without factory");
  });

  console.log("\nTest 3: an array of transactions is one ERC-7579 batch");
  await withBundler({}, async (bundler) => {
    const sdk = await primarySdk(config(bundler));
    const approve = "0x095ea7b3" + "00".repeat(64);
    await sdk.sendTransaction(
      [
        { to: TOKEN, data: approve, chainId: 1 },
        { to: RECIPIENT, value: 7n, chainId: 1 },
      ],
      { mode: "PRIMARY" }
    );
    assert.strictEqual(bundler.included.length, 1, "one UserOperation");
    const [mode, executionCalldata] = account.decodeFunctionData("execute", bundler.included[0].callData);
    assert.strictEqual(mode, "0x01" + "00".repeat(31), "batch call mode, revert on failure");
    const [executions] = coder.decode(["tuple(address,uint256,bytes)[]"], executionCalldata);
    assert.deepStrictEqual(
      executions.map((e: any) => [e[0].toLowerCase(), e[1], e[2]]),
      [
        [TOKEN, 0n, approve],
        [RECIPIENT, 7n, "0x"],
      ]
    );
    console.log("✅ Batched calls in one UserOperation");
  });

  console.log("\nTest 4: ERC-7677 paymaster sponsors the gas");
  await withBundler({ paymasterData: "0xc0ffee" }, async (bundler) => {
    const sdk = await primarySdk(config(bundler, { paymasterUrl: bundler.url }));
    passkeyCalls.length = 0;
    const result = await sdk.sendTransaction(
      { to: RECIPIENT, chainId: 1 },
      { mode: "PRIMARY", paymasterContext: { policy: "allow" } }
    );
    const [op] = bundler.included;
    assert.strictEqual(op.paymaster, PAYMASTER);
    assert.strictEqual(op.paymasterData, "0xc0ffee", "final paymaster data is sent");
    assert.strictEqual(BigInt(op.paymasterVerificationGasLimit), GAS_ESTIMATE.paymasterVerificationGasLimit);
    assert.strictEqual(BigInt(op.paymasterPostOpGasLimit), 20_000n, "postOp gas limit from the stub");
    const methods = bundler.calls.map((c) => c.method);
    assert(methods.indexOf("pm_getPaymasterStubData") < methods.indexOf("eth_estimateUserOperationGas"));
    assert(methods.indexOf("eth_estimateUserOperationGas") < methods.indexOf("pm_getPaymasterData"));
    const stub = bundler.calls.find((c) => c.method === "pm_getPaymasterStubData")!;
    assert.strictEqual(stub.params[2], "0x1", "chain ID as hex");
    assert.deepStrictEqual(stub.params[3], { policy: "allow" }, "context forwarded");
    assert.strictEqual(passkeyCalls.length, 1);
    assert.strictEqual(
      Buffer.from(passkeyCalls[0].challenge as Uint8Array).toString("hex"),
      result.userOpHash!.slice(2),
      "the passkey signs over the final paymaster data"
    );

    const denied = await rejection(
      sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY", paymasterContext: { policy: "deny" } })
    );
    assert(denied.includes("not sponsored"), denied);
    console.log("✅ Paymaster sponsors the UserOperation");
  });

  console.log("\nTest 5: isFinal stub data skips pm_getPaymasterData");
  await withBundler({ isFinal: true, paymasterData: "0x0000" }, async (bundler) => {
    const sdk = await primarySdk(config(bundler));
    await sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY", paymasterUrl: bundler.url });
    assert(!bundler.calls.some((c) => c.method === "pm_getPaymasterData"));
    assert.strictEqual(bundler.included[0].paymasterData, "0x0000");
    console.log("✅ isFinal honored");
  });

  console.log("\nTest 6: without the P-256 precompile, verification gas covers the Solidity verifier");
  await withBundler({ precompile: false }, async (bundler) => {
    const sdk = await primarySdk(config(bundler));
    await sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY" });
    assert.strictEqual(
      BigInt(bundler.included[0].verificationGasLimit),
      GAS_ESTIMATE.verificationGasLimit + P256_SOLIDITY_GAS
    );
    console.log("✅ Solidity verifier gas added");
  });

  console.log("\nTest 7: endpoints, tags and overrides");
  await withBundler({}, async (bundler) => {
    const sdk = await primarySdk({ rpcUrls: { 1: [bundler.url] }, bundlerUrls: { 1: "http://127.0.0.1:1" } });
    const result = await sdk.sendTransaction(
      { to: RECIPIENT, chainId: 1, maxFeePerGas: 7n, maxPriorityFeePerGas: 3n, gasLimit: 1n, nonce: 9 },
      { mode: "PRIMARY", tag: "GAMING", bundlerUrl: bundler.url }
    );
    assert.strictEqual(result.from, GAMING_ACCOUNT, "per-call bundlerUrl, tag selects the account");
    assert.strictEqual(result.tag, "GAMING");
    const [op] = bundler.included;
    assert.strictEqual(op.maxFeePerGas, "0x7");
    assert.strictEqual(op.maxPriorityFeePerGas, "0x3");
    assert.strictEqual(op.nonce, "0x0", "nonce from the EntryPoint");
    assert.strictEqual(BigInt(op.callGasLimit), GAS_ESTIMATE.callGasLimit, "a gasLimit below the estimate is raised to it");
    assert(!bundler.calls.some((c) => c.method === "eth_getBlockByNumber"), "no fee lookup with both fees set");
    assert.deepStrictEqual([...factory.decodeFunctionData("createAccount", op.factoryData)], [QX, QY, "GAMING"]);

    await sdk.sendTransaction(
      [
        { to: RECIPIENT, chainId: 1, gasLimit: 60_000n },
        { to: TOKEN, chainId: 1, gasLimit: 50_000n },
        { to: TOKEN, chainId: 1 },
      ],
      { mode: "PRIMARY", tag: "GAMING", bundlerUrl: bundler.url }
    );
    assert.strictEqual(BigInt(bundler.included.at(-1)!.callGasLimit), 110_000n, "gasLimits above the estimate are summed");
    console.log("✅ Per-call bundler, fee and gas overrides");
  });

  console.log("\nTest 8: missing endpoints and invalid input fail before the passkey prompt");
  {
    const sdk = await primarySdk({ rpcUrls: { 1: ["http://127.0.0.1:1"] } });
    passkeyCalls.length = 0;
    const noBundler = await rejection(sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY" }));
    assert(noBundler.includes("bundlerUrls"), noBundler);
    const noRpc = await rejection(
      sdk.sendTransaction({ to: RECIPIENT, chainId: 10 }, { mode: "PRIMARY", bundlerUrl: "http://127.0.0.1:1" })
    );
    assert(noRpc.includes("rpcUrls"), noRpc);
    const mixed = await rejection(
      sdk.sendTransaction([{ to: RECIPIENT, chainId: 1 }, { to: RECIPIENT, chainId: 10 }], { mode: "PRIMARY" })
    );
    assert(mixed.includes("same chain"), mixed);
    const fees = await rejection(
      sdk.sendTransaction(
        [{ to: RECIPIENT, chainId: 1, maxFeePerGas: 1n }, { to: RECIPIENT, chainId: 1 }],
        { mode: "PRIMARY" }
      )
    );
    assert(fees.includes("maxFeePerGas"), fees);
    const empty = await rejection(sdk.sendTransaction([], { mode: "PRIMARY" }));
    assert(empty.includes("No transaction"), empty);
    const eoaBatch = await rejection(sdk.sendTransaction([{ to: RECIPIENT, chainId: 1 }], { mode: "STANDARD" }));
    assert(eoaBatch.includes("Only PRIMARY mode"), eoaBatch);
    assert.strictEqual(passkeyCalls.length, 0, "no passkey prompt");
    console.log("✅ Clear errors");
  }

  console.log("\nTest 9: a reverted UserOperation throws with its revert reason");
  const reason = "0x08c379a0" + coder.encode(["string"], ["insufficient balance"]).slice(2);
  await withBundler({ revert: reason }, async (bundler) => {
    const sdk = await primarySdk(config(bundler));
    const message = await rejection(sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY" }));
    assert(message.includes("reverted") && message.includes("insufficient balance"), message);
    console.log("✅ Revert reason surfaced");
  });

  console.log("\nTest 10: a UserOperation never included times out");
  await withBundler({ neverInclude: true }, async (bundler) => {
    const sdk = await primarySdk(config(bundler));
    const start = Date.now();
    const message = await rejection(
      sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY", timeout: 1500 })
    );
    assert(message.includes("not included after 1500 ms"), message);
    assert(Date.now() - start < 5000);
    console.log("✅ Timeout");
  });

  console.log("\nTest 11: failed receipt polls are retried, and a lone maxFeePerGas caps the priority fee");
  await withBundler({ failingPolls: 2 }, async (bundler) => {
    const sdk = await primarySdk(config(bundler));
    const result = await sdk.sendTransaction({ to: RECIPIENT, chainId: 1, maxFeePerGas: 1n }, { mode: "PRIMARY" });
    assert.strictEqual(bundler.transactions.has(result.hash), true);
    assert.strictEqual(bundler.included[0].maxFeePerGas, "0x1");
    assert.strictEqual(bundler.included[0].maxPriorityFeePerGas, "0x1");
    const above = await rejection(
      sdk.sendTransaction({ to: RECIPIENT, chainId: 1, maxFeePerGas: 1n, maxPriorityFeePerGas: 2n }, { mode: "PRIMARY" })
    );
    assert(above.includes("above maxFeePerGas"), above);
    console.log("✅ Retried polls, capped priority fee");
  });

  console.log("\nTest 12: the userOpHash leaves out a paymaster signature, keeping the magic");
  {
    const op: UserOperation = {
      sender: MAIN_ACCOUNT,
      nonce: 0n,
      callData: encodeExecute([{ to: RECIPIENT }]),
      callGasLimit: 1n,
      verificationGasLimit: 2n,
      preVerificationGas: 3n,
      maxFeePerGas: 4n,
      maxPriorityFeePerGas: 5n,
      paymaster: PAYMASTER,
      paymasterVerificationGasLimit: 6n,
      paymasterPostOpGasLimit: 7n,
      paymasterData: "0x1234",
      signature: "0x",
    };
    const signed = (signature: string) => ({
      ...op,
      paymasterData: concat(["0x1234", signature, "0x" + ((signature.length - 2) / 2).toString(16).padStart(4, "0"), PAYMASTER_SIG_MAGIC]),
    });
    const a = getUserOperationHash(signed("0xaaaa"), 1);
    const b = getUserOperationHash(signed("0xbbbbbbbb"), 1);
    assert.strictEqual(a, b, "the paymaster signature is not signed by the account");
    assert.notStrictEqual(a, getUserOperationHash(op, 1), "the magic is");
    const paymasterAndData = concat([PAYMASTER, "0x" + "00".repeat(15) + "06", "0x" + "00".repeat(15) + "07", "0x1234"]);
    assert.strictEqual(
      paymasterAndDataHash(concat([paymasterAndData, "0xaaaa", "0x0002", PAYMASTER_SIG_MAGIC])),
      keccak256(concat([paymasterAndData, PAYMASTER_SIG_MAGIC]))
    );
    assert.notStrictEqual(getUserOperationHash(op, 1), getUserOperationHash(op, 10), "bound to the chain");
    console.log("✅ v0.9 paymaster signature hashing");
  }

  console.log("\nTest 13: concurrent sends from one account land one after another, with nonces 0 and 1");
  await withBundler({ pendingPolls: 2 }, async (bundler) => {
    const sdk = await primarySdk(config(bundler));
    const [a, b] = await Promise.all([
      sdk.sendTransaction({ to: RECIPIENT, value: 1n, chainId: 1 }, { mode: "PRIMARY" }),
      sdk.sendTransaction({ to: RECIPIENT, value: 2n, chainId: 1 }, { mode: "PRIMARY" }),
    ]);
    assert.deepStrictEqual(bundler.included.map((op) => op.nonce), ["0x0", "0x1"]);
    assert.strictEqual(bundler.included[0].factory, W3PK_ACCOUNT_FACTORY, "the first send deploys the account");
    assert.strictEqual(bundler.included[1].factory, undefined, "the second doesn't");
    assert.notStrictEqual(a.hash, b.hash);
    const methods = bundler.calls.map((c) => c.method);
    const sends = methods.flatMap((m, i) => (m === "eth_sendUserOperation" ? [i] : []));
    const lastPoll = methods.lastIndexOf("eth_getUserOperationReceipt", sends[1]);
    assert(lastPoll > sends[0], "the second is sent after the first is included");
    assert.strictEqual((sdk as any).primarySends.size, 0, "the queue is cleaned up");
    console.log("✅ Concurrent sends serialized");
  });

  console.log("\nTest 14: a failed send doesn't block the next");
  await withBundler({}, async (bundler) => {
    const sdk = await primarySdk(config(bundler, { paymasterUrl: bundler.url }));
    const [denied, sent] = await Promise.allSettled([
      sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY", paymasterContext: { policy: "deny" } }),
      sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY" }),
    ]);
    assert.strictEqual(denied.status, "rejected");
    assert.strictEqual(sent.status, "fulfilled");
    assert.deepStrictEqual(bundler.included.map((op) => op.nonce), ["0x0"]);
  });
  await withBundler({ revert: REVERT_DATA }, async (bundler) => {
    const sdk = await primarySdk(config(bundler));
    const results = await Promise.allSettled([
      sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY" }),
      sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY" }),
    ]);
    assert.deepStrictEqual(results.map((r) => r.status), ["rejected", "rejected"], "both revert");
    assert.deepStrictEqual(bundler.included.map((op) => op.nonce), ["0x0", "0x1"], "both are included");
    console.log("✅ Failed sends don't block the queue");
  });

  console.log("\nTest 15: other tags and chains aren't queued behind a pending send");
  await withBundler({ neverInclude: true }, async (stuck) => {
    await withBundler({ chainId: 10 }, async (other) => {
      const sdk = await primarySdk({
        rpcUrls: { 1: [stuck.url], 10: [other.url] },
        bundlerUrls: { 1: stuck.url, 10: other.url },
      });
      const userOpsSent = () => stuck.calls.filter((c) => c.method === "eth_sendUserOperation").length;
      let mainPending = true;
      let sentBeforeTimeout = 0;
      const main = rejection(
        sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY", timeout: 1500 }).finally(() => {
          mainPending = false;
          sentBeforeTimeout = userOpsSent();
        })
      );
      const gaming = rejection(
        sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY", tag: "GAMING", timeout: 1500 })
      );
      const result = await sdk.sendTransaction({ to: RECIPIENT, chainId: 10 }, { mode: "PRIMARY" });
      assert(mainPending, "chain 10 lands while chain 1 is pending");
      assert.strictEqual(result.from, MAIN_ACCOUNT);
      assert((await main).includes("not included"));
      assert((await gaming).includes("not included"));
      assert.strictEqual(sentBeforeTimeout, 2, "GAMING was sent while MAIN was pending");
      console.log("✅ Queues are per tag and chain");
    });
  });

  console.log("\nTest 16: onBeforeSign is awaited with the digests before the passkey signs");
  await withBundler({}, async (bundler) => {
    const sdk = await primarySdk(config(bundler));
    const approve = "0x095ea7b3" + "00".repeat(64);
    const txs: TransactionRequest[] = [
      { to: TOKEN, data: approve, chainId: 1 },
      { to: RECIPIENT, value: 7n, chainId: 1 },
    ];
    const expected = txs.map((tx) => ({
      method: "eth_sendTransaction",
      ...getSigningDigests({ method: "eth_sendTransaction", params: [tx] }),
    }));
    passkeyCalls.length = 0;
    let seen: unknown;
    await sdk.sendTransaction(txs[1], {
      mode: "PRIMARY",
      onBeforeSign: (digests) => {
        seen = digests;
        assert.strictEqual(passkeyCalls.length, 0, "hook before the passkey prompt");
      },
    });
    assert.deepStrictEqual(seen, expected[1], "one transaction, one digests object");
    assert.strictEqual(passkeyCalls.length, 1);

    await sdk.sendTransaction(txs, {
      mode: "PRIMARY",
      onBeforeSign: async (digests) => {
        seen = digests;
        txs[1].value = 9n;
        txs.push({ to: TOKEN, data: "0x", chainId: 1 });
      },
    });
    assert.deepStrictEqual(seen, expected, "an array of transactions, an array of digests");
    const [, executionCalldata] = account.decodeFunctionData("execute", bundler.included[1].callData);
    const [executions] = coder.decode(["tuple(address,uint256,bytes)[]"], executionCalldata);
    assert.deepStrictEqual(
      executions.map((e: any) => [e[0].toLowerCase(), e[1], e[2]]),
      [
        [TOKEN, 0n, approve],
        [RECIPIENT, 7n, "0x"],
      ],
      "the copy taken before the hook is sent"
    );
    console.log("✅ onBeforeSign approves PRIMARY sends");
  });

  console.log("\nTest 17: onBeforeSign cancels a PRIMARY send before the passkey prompt");
  await withBundler({}, async (bundler) => {
    const sdk = await primarySdk(config(bundler));
    const cancel = new Error("cancelled");
    const cancels = [
      { hook: () => false, cause: undefined },
      { hook: () => { throw cancel; }, cause: cancel },
      { hook: () => Promise.reject(cancel), cause: cancel },
    ];
    passkeyCalls.length = 0;
    for (const { hook, cause } of cancels) {
      const error = await sdk
        .sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY", onBeforeSign: hook })
        .catch((e) => e);
      assert(error instanceof UserRejectedRequestError, `UserRejectedRequestError, got ${error}`);
      assert.strictEqual(error.code, 4001);
      assert.strictEqual(error.cause, cause, "the hook's error as cause");
    }
    assert.strictEqual(passkeyCalls.length, 0, "no passkey prompt");
    assert(!bundler.calls.some((c) => c.method === "eth_sendUserOperation"), "nothing sent");

    await sdk.sendTransaction({ to: RECIPIENT, chainId: 1 }, { mode: "PRIMARY" });
    assert.strictEqual(bundler.included[0].nonce, "0x0", "a cancel doesn't block the queue");
    console.log("✅ onBeforeSign cancels PRIMARY sends");
  });

  console.log("\n🎉 All PRIMARY mode sendTransaction tests passed!\n");
}

runTests().catch((error) => {
  console.error("❌ Test failed:", error);
  process.exit(1);
});
