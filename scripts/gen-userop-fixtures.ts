/**
 * Writes contracts/test/fixtures/userop.json: PRIMARY mode UserOperations
 * made and signed by the SDK with the software passkey of
 * test/fixtures/passkey-signer.ts, sent to the mock bundler of
 * test/fixtures/mock-bundler.ts. contracts/test/W3pkAccountUserOp.t.sol runs
 * them through the EntryPoint v0.9.
 *
 *   pnpm tsx scripts/gen-userop-fixtures.ts
 *
 * test/userop-fixtures.test.ts fails if the file is out of date.
 */

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { concat } from "ethers";
import { installPasskey, primarySdk } from "../test/fixtures/passkey-signer";
import { startMockBundler } from "../test/fixtures/mock-bundler";
import { PAYMASTER_SIG_MAGIC } from "../src/wallet/user-operation";

export const FIXTURES_PATH = resolve(fileURLToPath(import.meta.url), "../../contracts/test/fixtures/userop.json");

const CHAIN_ID = 1;
export const RECIPIENT = "0x000000000000000000000000000000000000bEEF";
export const OTHER_RECIPIENT = "0x000000000000000000000000000000000000cafE";
/** forge etches code that always reverts here */
export const REVERTER = "0x000000000000000000000000000000000000dEaD";
/** paymasterData ending with a paymaster signature (`0xaaaa`), which the userOpHash leaves out */
const SIGNED_PAYMASTER_DATA = concat(["0x1234", "0xaaaa", "0x0002", PAYMASTER_SIG_MAGIC]);

const GAS = {
  preVerificationGas: 60_000n,
  verificationGasLimit: 500_000n,
  callGasLimit: 200_000n,
  paymasterVerificationGasLimit: 50_000n,
};

export async function generateFixtures(): Promise<string> {
  installPasskey();
  const ops: Record<string, Record<string, string> & { userOpHash?: string }> = {};

  const bundler = await startMockBundler({ chainId: CHAIN_ID, pendingPolls: 0, gasEstimate: GAS });
  try {
    const sdk = await primarySdk({
      rpcUrls: { [CHAIN_ID]: [bundler.url] },
      bundlerUrls: { [CHAIN_ID]: bundler.url },
    });
    const send = async (name: string, txs: Parameters<typeof sdk.sendTransaction>[0]) => {
      const { userOpHash } = await sdk.sendTransaction(txs, { mode: "PRIMARY" });
      ops[name] = { ...bundler.included[bundler.included.length - 1], userOpHash: userOpHash! };
    };
    await send("deploy", { to: RECIPIENT, value: 1000n, chainId: CHAIN_ID });
    await send("batch", [
      { to: RECIPIENT, value: 1n, chainId: CHAIN_ID },
      { to: OTHER_RECIPIENT, value: 2n, data: "0x1234", chainId: CHAIN_ID },
    ]);
    await send("revertingBatch", [
      { to: RECIPIENT, value: 5n, chainId: CHAIN_ID },
      { to: REVERTER, chainId: CHAIN_ID },
    ]);
  } finally {
    await bundler.close();
  }

  const sponsored = await startMockBundler({
    chainId: CHAIN_ID,
    pendingPolls: 0,
    gasEstimate: GAS,
    paymasterData: SIGNED_PAYMASTER_DATA,
  });
  try {
    const sdk = await primarySdk({
      rpcUrls: { [CHAIN_ID]: [sponsored.url] },
      bundlerUrls: { [CHAIN_ID]: sponsored.url },
      paymasterUrl: sponsored.url,
    });
    const { userOpHash } = await sdk.sendTransaction({ to: RECIPIENT, chainId: CHAIN_ID }, { mode: "PRIMARY" });
    ops.paymaster = { ...sponsored.included[0], userOpHash: userOpHash! };
  } finally {
    await sponsored.close();
  }

  const fixtures = {
    chainId: CHAIN_ID,
    // forge's vm.parseJson needs every field present: empty fields as "0x"
    ...Object.fromEntries(
      Object.entries(ops).map(([name, op]) => [
        name,
        {
          factory: "0x0000000000000000000000000000000000000000",
          factoryData: "0x",
          paymaster: "0x0000000000000000000000000000000000000000",
          paymasterData: "0x",
          paymasterVerificationGasLimit: "0x0",
          paymasterPostOpGasLimit: "0x0",
          ...op,
        },
      ])
    ),
  };
  return JSON.stringify(fixtures, null, 2) + "\n";
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  generateFixtures().then((fixtures) => {
    writeFileSync(FIXTURES_PATH, fixtures);
    console.log(`Wrote ${FIXTURES_PATH}`);
  });
}
