/**
 * EIP-7702 Support (Internal Module)
 *
 * EIP-7702 introduces "Set EOA Account Code" functionality,
 * allowing externally owned accounts (EOAs) to temporarily act as smart contracts.
 *
 * This module is for internal use by the SDK.
 * Access via: w3pk.supportsEIP7702(chainId)
 */

/**
 * Chains whose public RPC endpoints passed the EIP-7702 probe below on
 * 2026-11-11 (315 chains): every chain on https://chainid.network/chains.json,
 * up to 10 HTTPS endpoints each without an API key, an endpoint counting only
 * when its eth_chainId matched. Chains that answered on no endpoint are left
 * out, and get probed through the app's rpcUrls instead. Method adapted from
 * https://github.com/w3hc/eip7702-playground/blob/main/eip7702_scanner.sh
 */
const EIP7702_SUPPORTED_CHAINS = new Set([
  1, 7, 8, 10, 12, 17, 25, 40, 41, 42, 51, 56, 71, 95, 97, 100, 130, 133, 137,
  138, 143, 146, 151, 153, 159, 169, 177, 196, 209, 215, 219, 247, 248, 252,
  254, 287, 288, 291, 338, 360, 362, 395, 432, 434, 466, 480, 488, 545, 550,
  587, 648, 680, 681, 714, 723, 739, 743, 747, 784, 869, 917, 919, 957, 988,
  1001, 1019, 1020, 1030, 1050, 1116, 1155, 1247, 1270, 1301, 1315, 1328,
  1329, 1394, 1514, 1597, 1612, 1625, 1672, 1729, 1740, 1750, 1829, 1868,
  1874, 1875, 1946, 1952, 1962, 1983, 1989, 2017, 2020, 2035, 2201, 2345,
  2383, 2523, 2583, 2679, 2800, 2818, 2967, 3045, 3111, 3223, 3282, 3330,
  3343, 3377, 3502, 4000, 4114, 4153, 4201, 4217, 4221, 4326, 4352, 4460,
  4646, 4663, 4801, 4888, 5000, 5003, 5031, 5042, 5069, 5115, 5371, 5373,
  5424, 5550, 5858, 6122, 6292, 6343, 6497, 6498, 7368, 7560, 7667, 7676,
  7741, 7777, 8217, 8283, 8453, 8472, 9009, 9372, 9745, 9746, 10088, 10143,
  10200, 11011, 12216, 13373, 13579, 14601, 16602, 16661, 19480, 19998, 20010,
  20011, 20261, 20310, 20678, 20993, 21000, 21211, 22028, 25363, 26514, 28882,
  30303, 31611, 31612, 33139, 33431, 33979, 34443, 36900, 38833, 38836, 39815,
  42161, 42170, 42220, 42431, 43111, 43522, 46630, 47763, 48359, 48900, 50000,
  50002, 50312, 55377, 55378, 57073, 59141, 59144, 60808, 61564, 64327, 66666,
  69000, 69420, 72957, 77410, 80002, 80069, 80094, 80451, 81224, 84532, 88882,
  88888, 91342, 97476, 97477, 97741, 98866, 98867, 98875, 99110, 99801, 99901,
  99999, 101089, 127001, 138565, 139420, 153871, 167000, 167013, 179170,
  181228, 190415, 193939, 221978, 224422, 240241, 271828, 274630, 274663,
  286623, 323432, 355110, 421614, 450815, 482120, 485590, 511111, 560048,
  612044, 612055, 685685, 685689, 713715, 737373, 743111, 747474, 763373,
  770101, 787878, 797290, 808813, 812242, 821207, 838838, 853211, 886699,
  1212111, 1658000, 2019775, 2651420, 3441006, 5042002, 5318007, 5734951,
  6281971, 6985385, 7080969, 7777777, 11142220, 11155111, 11155420, 11155931,
  12227332, 13600000, 13863860, 18896214, 18896215, 20260532, 42424242,
  61022448, 77777777, 188962142, 999999999, 1213549903, 1313161555,
  1313161567, 1313161573, 1313161911, 1415006552,
]);

const PROBE_ADDRESS = "0xdeadbeef00000000000000000000000000000000";

/** eth_estimateGas from and to PROBE_ADDRESS, with `code` set on it by a state override */
function estimateWithCode(code: string, data: string) {
  return {
    jsonrpc: "2.0",
    id: 1,
    method: "eth_estimateGas",
    params: [
      { from: PROBE_ADDRESS, to: PROBE_ADDRESS, data, value: "0x0" },
      "latest",
      { [PROBE_ADDRESS]: { code } },
    ],
  };
}

// PUSH1 0 PUSH1 0 REVERT: fails wherever the override is applied
const REVERTING = estimateWithCode("0x60006000fd", "0x");
// A delegation designator to the ecrecover precompile: the call succeeds
// under EIP-7702, and fails on the undefined 0xef opcode without it
const DELEGATED = estimateWithCode(
  "0xef01000000000000000000000000000000000000000001",
  `0x${"00".repeat(63)}01${"00".repeat(64)}`
);

async function rpc(rpcUrl: string, body: object, timeout: number): Promise<{ result?: unknown }> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Test an RPC endpoint for EIP-7702 support: the endpoint must apply state
 * overrides (a reverting override fails), and a call into an account
 * delegated with an EIP-7702 designator must succeed
 * @internal
 */
async function testRPCForEIP7702(rpcUrl: string, timeout: number = 10000): Promise<boolean> {
  try {
    const [reverting, delegated] = await Promise.all([
      rpc(rpcUrl, REVERTING, timeout),
      rpc(rpcUrl, DELEGATED, timeout),
    ]);
    return reverting.result === undefined && delegated.result !== undefined;
  } catch {
    return false;
  }
}

/**
 * Check if a network supports EIP-7702: the static list first, then a
 * probe of the given endpoints (the app's `rpcUrls`), never public ones
 * @internal
 */
export async function supportsEIP7702(
  chainId: number,
  endpoints: string[],
  options?: {
    maxEndpoints?: number;
    timeout?: number;
  }
): Promise<boolean> {
  if (EIP7702_SUPPORTED_CHAINS.has(chainId)) {
    return true;
  }

  const maxEndpoints = options?.maxEndpoints || 3;
  const timeout = options?.timeout || 10000;

  for (const endpoint of endpoints.slice(0, maxEndpoints)) {
    if (await testRPCForEIP7702(endpoint, timeout)) {
      return true;
    }
  }
  return false;
}

// Export EIP-7702 utility functions
export {
  encodeEIP7702AuthorizationMessage,
  hashEIP7702AuthorizationMessage,
  verifyEIP7702Authorization,
} from "./utils";
