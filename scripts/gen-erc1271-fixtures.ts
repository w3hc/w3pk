/**
 * Writes contracts/test/fixtures/erc1271.json: PRIMARY mode signatures made by
 * the SDK with the software passkey of test/fixtures/passkey-signer.ts, which
 * contracts/test/W3pkAccountSdkSignatures.t.sol verifies onchain
 *
 *   pnpm tsx scripts/gen-erc1271-fixtures.ts
 *
 * test/erc1271-fixtures.test.ts fails if the file is out of date.
 */

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { TypedDataEncoder, hashMessage } from "ethers";
import { installPasskey, primarySdk } from "../test/fixtures/passkey-signer";

export const FIXTURES_PATH = resolve(fileURLToPath(import.meta.url), "../../contracts/test/fixtures/erc1271.json");

const CHAIN_ID = 1;
const MESSAGE = "Hello, Web3!";
const DOMAIN = {
  name: "Mail",
  version: "1",
  chainId: CHAIN_ID,
  verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
};
const TYPES = {
  Person: [
    { name: "name", type: "string" },
    { name: "wallet", type: "address" },
  ],
  Mail: [
    { name: "from", type: "Person" },
    { name: "contents", type: "string" },
  ],
};
const MAIL = { from: { name: "Alice", wallet: "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa" }, contents: "Hello" };

export async function generateFixtures(): Promise<string> {
  installPasskey();
  const undeployed = await primarySdk();
  const deployed = await primarySdk();
  (deployed as any).isDeployed = async () => true;

  const typedData = {
    mode: "PRIMARY" as const,
    signingMethod: "EIP712" as const,
    eip712Domain: DOMAIN,
    eip712Types: TYPES,
    eip712PrimaryType: "Mail",
  };

  const fixtures = {
    chainId: CHAIN_ID,
    personalSign: {
      hash: hashMessage(MESSAGE),
      signature: (await deployed.signMessage(MESSAGE, { mode: "PRIMARY", chainId: CHAIN_ID })).signature,
      signature6492: (await undeployed.signMessage(MESSAGE, { mode: "PRIMARY", chainId: CHAIN_ID })).signature,
    },
    typedData: {
      hash: TypedDataEncoder.hash(DOMAIN, TYPES, MAIL),
      signature: (await deployed.signMessage(JSON.stringify(MAIL), typedData)).signature,
      signature6492: (await undeployed.signMessage(JSON.stringify(MAIL), typedData)).signature,
    },
  };
  return JSON.stringify(fixtures, null, 2) + "\n";
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  generateFixtures().then((fixtures) => {
    writeFileSync(FIXTURES_PATH, fixtures);
    console.log(`Wrote ${FIXTURES_PATH}`);
  });
}
