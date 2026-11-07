# w3pk contracts

`W3pkAccount`, the ERC-4337 account a `PRIMARY` passkey owns, and `W3pkAccountFactory`, which creates the implementation in its constructor and deploys each account as an ERC-1167 clone. See [EIP-7951.md](../docs/EIP-7951.md#primary-smart-account).

```sh
forge build
forge test
forge fmt --check
```

## Deploying to a network

The factory goes through the deterministic deployment proxy (`0x4e59b44847b379578588920cA78FbF26c0B4956C`, salt 1), so it lands at the same address on every chain, and the implementation with it:

| | |
|---|---|
| Factory | `0xe341d909A1D7dEeec787796b8d305c064aEB5181` (`W3PK_ACCOUNT_FACTORY`) |
| Implementation | `0x289b99F5EfFE4b5aF6DBc3f3501881C98aF2740C` |

Any change to the contracts, the compiler settings in `foundry.toml` or the OpenZeppelin version changes both addresses and `W3PK_ACCOUNT_INIT_CODE_HASH`. Deploy the bytecode as it is.

### Prerequisites

- [Foundry](https://getfoundry.sh) (`forge`, `cast`)
- `contracts/.env`, copied from [`.env.example`](./.env.example): the chain's `*_RPC_URL`, `DEPLOYER_PRIVATE_KEY` and `ETHERSCAN_API_KEY`. One [Etherscan V2](https://docs.etherscan.io/etherscan-v2) key covers every chain. `.env` is gitignored

The chain needs the deterministic deployment proxy (`cast code 0x4e59b44847b379578588920cA78FbF26c0B4956C --rpc-url <url>` isn't `0x`) and Cancun's opcodes: the bytecode uses `PUSH0` and `MCOPY`, nothing newer.

### Funding the deployer

The deployment is one transaction of about 4.33M gas, plus the L1 data fee on rollups. forge checks the balance against its gas limit (the estimate × 1.3) times its max fee (about twice the gas price), so fund the deployer with about `4.33M × 1.3 × 2 × gas price`, with headroom: around 0.002 ETH on Ethereum and 0.0005 ETH or less on OP Mainnet, Base and Arbitrum. Check the balance and the cost first:

```sh
cast balance -e <deployer> --rpc-url <url>
forge script script/Deploy.s.sol --rpc-url <chain>
```

Without `--broadcast`, the script only simulates and prints the addresses it would deploy to and the estimated cost.

### Deploying

```sh
cd contracts
set -a && . ./.env && set +a
forge script script/Deploy.s.sol --rpc-url <chain> --broadcast --verify
```

- `--rpc-url <chain>`: an alias from `[rpc_endpoints]` in `foundry.toml`, such as `base_sepolia`
- `--broadcast`: sends the transaction, signed with `DEPLOYER_PRIVATE_KEY`
- `--verify`: verifies both contracts on Etherscan, with the key from the chain's `[etherscan]` entry

The script is idempotent: if the factory already has code, it sends nothing and only prints the chain ID, the factory and implementation addresses and the clone init code hash, which must match `W3PK_ACCOUNT_FACTORY` and `W3PK_ACCOUNT_INIT_CODE_HASH` in [`src/wallet/smart-account.ts`](../src/wallet/smart-account.ts).

If Etherscan refuses the verification (its free tier doesn't cover every chain), verify on [Sourcify](https://sourcify.dev), which Etherscan also reads:

```sh
forge verify-contract 0xe341d909A1D7dEeec787796b8d305c064aEB5181 src/W3pkAccountFactory.sol:W3pkAccountFactory --chain <chain id> --verifier sourcify
forge verify-contract 0x289b99F5EfFE4b5aF6DBc3f3501881C98aF2740C src/W3pkAccount.sol:W3pkAccount --chain <chain id> --verifier sourcify
```

### Why the script calls the proxy directly

`Deploy.s.sol` calls the proxy with `salt ‖ creationCode` instead of `new W3pkAccountFactory{salt: SALT}()`. On OP Mainnet and OP Sepolia, forge 1.9 ran the `new` as a CREATE2 from the deployer itself, not through the proxy, which would have put the factory at `0x9804f0776e4dbf1F326dd8432fbbF8a97c6b6253`, an address the SDK doesn't know. The direct call lands at the same address everywhere, and the script reverts if the factory has no code afterwards.

### Adding a chain

1. In `foundry.toml`, add the alias to `[rpc_endpoints]` and `[etherscan]`, with the chain ID:

   ```toml
   [rpc_endpoints]
   base_sepolia = "${BASE_SEPOLIA_RPC_URL}"

   [etherscan]
   base_sepolia = { key = "${ETHERSCAN_API_KEY}", chain = 84532 }
   ```

2. Add `BASE_SEPOLIA_RPC_URL=` to `.env.example` and set it in `.env`
3. In [`scripts/check-deployments.ts`](../scripts/check-deployments.ts), add the chain to `ALL_CHAINS` with a public RPC, or once deployed, set its `deployed` to `true`
4. Deploy, then add the chain to the deployment table in [EIP-7951.md](../docs/EIP-7951.md#primary-smart-account)

### Checking

```sh
pnpm check:deployments
```

From the repository root, over public RPCs: for every chain with `deployed: true`, the chain ID, that the factory has code, that `implementation()` is `0x289b99F5EfFE4b5aF6DBc3f3501881C98aF2740C` with code, and that its clone init code hash is `W3PK_ACCOUNT_INIT_CODE_HASH`. Every row must read `ok`.
