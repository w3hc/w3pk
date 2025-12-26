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
 * EIP-7702 supported chain IDs (329 chains as of December 2024)
 * Source: https://github.com/w3hc/eip7702-playground
 */
const EIP7702_SUPPORTED_CHAINS = new Set([
  1, 10, 8453, 42161, 57073, 100, 42220, 137, 42, 15, 40, 41, 44, 46, 47, 50,
  51, 56, 61, 71, 82, 83, 95, 97, 112, 123, 130, 146, 151, 153, 171, 180, 183,
  185, 195, 215, 228, 247, 248, 252, 261, 267, 291, 293, 311, 332, 336, 395,
  401, 416, 466, 480, 488, 510, 545, 634, 647, 648, 747, 831, 919, 938, 945,
  957, 964, 970, 980, 995, 997, 1001, 1003, 1024, 1030, 1114, 1125, 1135, 1149,
  1188, 1284, 1285, 1287, 1300, 1301, 1315, 1337, 1338, 1339, 1424, 1514, 1687,
  1727, 1729, 1740, 1750, 1829, 1868, 1946, 1961, 1962, 1969, 1989, 1995, 2017,
  2020, 2031, 2043, 2109, 2241, 2340, 2345, 2440, 2522, 2559, 2649, 3068, 3109,
  3338, 3502, 3799, 3888, 3889, 4000, 4048, 4078, 4162, 4201, 4202, 4460, 4488,
  4661, 4689, 4690, 4888, 5000, 5003, 5124, 5234, 5330, 5424, 5522, 6283, 6342,
  6398, 6678, 6806, 6934, 6942, 6969, 7117, 7171, 7200, 7208, 7368, 7518, 7668,
  7672, 7744, 7771, 7869, 7897, 8008, 8118, 8217, 8408, 8700, 8726, 8727, 8844,
  8880, 8881, 8882, 8889, 9372, 9496, 9700, 9745, 9746, 9899, 9990, 9996, 10011,
  10085, 10143, 10200, 11221, 11501, 11504, 11891, 13370, 14853, 16602, 16661,
  17000, 18880, 18881, 19991, 21000, 21816, 21912, 25327, 32323, 33401, 34443,
  41923, 42170, 43111, 44787, 47805, 48898, 48900, 49049, 49088, 50000, 50312,
  53302, 53456, 53457, 55244, 56288, 59141, 60808, 60850, 62320, 62850, 64002,
  71402, 72080, 73114, 73115, 75338, 78281, 80002, 80008, 80069, 80094, 80451,
  80931, 84532, 88899, 91342, 92278, 94524, 96970, 97476, 97477, 98985, 100021,
  100501, 101010, 102030, 102031, 102032, 112358, 120893, 121212, 121213,
  121214, 121215, 129399, 161803, 175188, 192940, 193939, 198989, 212013,
  222222, 240241, 325000, 355110, 355113, 421614, 555777, 560048, 656476,
  713715, 743111, 747474, 763373, 763375, 777777, 806582, 808813, 810180,
  839999, 888991, 2019775, 2222222, 4278608, 5734951, 6666689, 6985385, 7080969,
  7777777, 9999999, 11142220, 11155111, 11155420, 11155931, 16969696, 19850818,
  20180427, 20250825, 28122024, 34949059, 37084624, 52164803, 61022448,
  79479957, 96969696, 420420421, 420420422, 888888888, 974399131, 999999999,
  1020352220, 1273227453, 1313161560, 1350216234, 1380996178, 1417429182,
  1444673419, 1482601649, 1564830818, 2046399126, 11297108099, 11297108109,
  88153591557, 123420000220, 123420001114,
]);

/**
 * Test an RPC endpoint for EIP-7702 support using eth_estimateGas
 * Based on: https://github.com/w3hc/eip7702-playground/blob/main/eip7702_scanner.sh
 * @internal
 */
async function testRPCForEIP7702(
  rpcUrl: string,
  timeout: number = 10000
): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "eth_estimateGas",
        params: [
          {
            from: "0xdeadbeef00000000000000000000000000000000",
            to: "0xdeadbeef00000000000000000000000000000000",
            data: "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            value: "0x0",
          },
          "latest",
          {
            "0xdeadbeef00000000000000000000000000000000": {
              code: "0xef01000000000000000000000000000000000000000001",
            },
          },
        ],
        id: 1,
      }),
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return false;
    }

    const data = await response.json();

    // Check for error messages that indicate no EIP-7702 support
    if (data.error) {
      const errorMsg = (data.error.message || "").toLowerCase();

      // These errors indicate the RPC doesn't support EIP-7702
      const unsupportedErrors = [
        "unsupported",
        "not supported",
        "unknown",
        "invalid",
        "unrecognized",
        "does not support",
        "not implemented",
      ];

      return !unsupportedErrors.some((err) => errorMsg.includes(err));
    }

    // If we got a result (even an estimate), EIP-7702 is supported
    return data.result !== undefined;
  } catch (error) {
    // Network errors, timeouts, etc. don't necessarily mean no support
    return false;
  }
}

/**
 * Check if a network supports EIP-7702
 * First checks cached list, then performs RPC test if not found
 * @internal
 */
export async function supportsEIP7702(
  chainId: number,
  getEndpointsFn: (chainId: number) => Promise<string[]>,
  options?: {
    maxEndpoints?: number;
    timeout?: number;
  }
): Promise<boolean> {
  // First, check the cached list
  if (EIP7702_SUPPORTED_CHAINS.has(chainId)) {
    return true;
  }

  // Not in cached list, perform RPC test
  const maxEndpoints = options?.maxEndpoints || 3;
  const timeout = options?.timeout || 10000;

  try {
    // Get RPC endpoints for this chain
    const endpoints = await getEndpointsFn(chainId);

    if (endpoints.length === 0) {
      return false;
    }

    // Test up to maxEndpoints
    const endpointsToTest = endpoints.slice(0, maxEndpoints);

    for (const endpoint of endpointsToTest) {
      const supported = await testRPCForEIP7702(endpoint, timeout);

      if (supported) {
        return true;
      }
    }

    return false;
  } catch (error) {
    return false;
  }
}

// Export external wallet utilities
export {
  requestExternalWalletAuthorization,
  getDefaultProvider,
  detectWalletProvider,
  supportsEIP7702Authorization,
} from "./external-wallet";
export type { EIP1193Provider } from "./external-wallet";

// Export EIP-7702 utility functions
export {
  encodeEIP7702AuthorizationMessage,
  hashEIP7702AuthorizationMessage,
  verifyEIP7702Authorization,
} from "./utils";
