/**
 * Checks on every target chain, over public RPCs, that `W3pkAccountFactory` is
 * deployed at `W3PK_ACCOUNT_FACTORY`, that its `implementation()` is the
 * expected address, and that the implementation's ERC-1167 clone init code
 * hash is `W3PK_ACCOUNT_INIT_CODE_HASH`
 *
 *   pnpm check:deployments
 *
 * Run by hand after a deployment, not in CI. Exits with 1 if a chain fails.
 */

import { Contract, JsonRpcProvider, concat, getCreateAddress, keccak256 } from "ethers";
import { W3PK_ACCOUNT_FACTORY, W3PK_ACCOUNT_INIT_CODE_HASH } from "../src/wallet/smart-account";

const CHAINS: { name: string; chainId: number; rpcUrl: string }[] = [
  { name: "Ethereum", chainId: 1, rpcUrl: "https://ethereum-rpc.publicnode.com" },
  { name: "OP Mainnet", chainId: 10, rpcUrl: "https://mainnet.optimism.io" },
  { name: "Base", chainId: 8453, rpcUrl: "https://mainnet.base.org" },
  { name: "Arbitrum One", chainId: 42161, rpcUrl: "https://arb1.arbitrum.io/rpc" },
  { name: "Sepolia", chainId: 11155111, rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com" },
  { name: "OP Sepolia", chainId: 11155420, rpcUrl: "https://sepolia.optimism.io" },
  { name: "Base Sepolia", chainId: 84532, rpcUrl: "https://sepolia.base.org" },
  { name: "Arbitrum Sepolia", chainId: 421614, rpcUrl: "https://sepolia-rollup.arbitrum.io/rpc" },
];

/** The factory creates the implementation in its constructor, at `CREATE` nonce 1 */
const EXPECTED_IMPLEMENTATION = getCreateAddress({ from: W3PK_ACCOUNT_FACTORY, nonce: 1 });

function cloneInitCodeHash(implementation: string): string {
  return keccak256(
    concat(["0x3d602d80600a3d3981f3363d3d373d3d3d363d73", implementation, "0x5af43d82803e903d91602b57fd5bf3"])
  );
}

async function check({ chainId, rpcUrl }: (typeof CHAINS)[number]): Promise<string[]> {
  const provider = new JsonRpcProvider(rpcUrl, chainId, { staticNetwork: true });
  if ((await provider.getCode(W3PK_ACCOUNT_FACTORY)) === "0x") return ["factory not deployed"];
  const errors: string[] = [];
  const factory = new Contract(W3PK_ACCOUNT_FACTORY, ["function implementation() view returns (address)"], provider);
  const implementation: string = await factory.implementation();
  if (implementation !== EXPECTED_IMPLEMENTATION) errors.push(`implementation() is ${implementation}`);
  if ((await provider.getCode(implementation)) === "0x") errors.push("implementation not deployed");
  const hash = cloneInitCodeHash(implementation);
  if (hash !== W3PK_ACCOUNT_INIT_CODE_HASH) errors.push(`clone init code hash is ${hash}`);
  return errors;
}

async function main(): Promise<void> {
  console.log(`factory              ${W3PK_ACCOUNT_FACTORY}`);
  console.log(`implementation       ${EXPECTED_IMPLEMENTATION}`);
  console.log(`clone init code hash ${W3PK_ACCOUNT_INIT_CODE_HASH}\n`);

  const results = await Promise.all(
    CHAINS.map((chain) => check(chain).catch((error: Error) => [`RPC error: ${error.message}`]))
  );
  CHAINS.forEach(({ name, chainId }, i) => {
    const errors = results[i];
    const label = `${name} (${chainId})`.padEnd(28);
    console.log(`${errors.length ? "FAIL" : "ok  "} ${label}${errors.join("; ")}`);
  });
  if (results.some((errors) => errors.length)) process.exit(1);
}

main();
