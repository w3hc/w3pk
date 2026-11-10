import type {
  EIP1193ProviderInterface,
  EIP1193ProviderOptions,
  ProviderConnectInfo,
  ProviderMessage,
  ProviderRpcError,
} from "../../src/index";

declare const provider: EIP1193ProviderInterface;

const onAccounts = (accounts: string[]) => accounts;
provider.on("accountsChanged", onAccounts);
provider.removeListener("accountsChanged", onAccounts);
provider.on("chainChanged", (chainId: string) => chainId);
provider.on("connect", (info: ProviderConnectInfo) => info.chainId);
provider.on("disconnect", (error: ProviderRpcError) => error.code);
provider.on("message", (message: ProviderMessage) => message.type);
provider.on("chainChanged", () => {});

// @ts-expect-error accountsChanged passes string[]
provider.on("accountsChanged", (accounts: number[]) => accounts);
// @ts-expect-error not an EIP-1193 event
provider.on("unknownEvent", () => {});

const onBeforeSign: EIP1193ProviderOptions["onBeforeSign"] = async (digests) => {
  if (digests.method === "eth_sendTransaction") {
    digests.calldataDigest satisfies string;
    digests.value satisfies bigint;
    // @ts-expect-error transactions have no EIP-712 Digest
    digests.eip712Digest;
  } else if (digests.method === "eth_signTypedData_v4") {
    digests.domainHash satisfies string;
  } else {
    digests.erc191Digest satisfies string;
  }
};
onBeforeSign;
