/**
 * External Wallet Integration Tests (EIP-7702)
 *
 * Tests for integrating external wallets (MetaMask, Rabby, hardware wallets, etc.)
 * with W3PK for EIP-7702 authorizations.
 */

import { mockLocalStorage } from "./setup";
import {
  createWeb3Passkey,
  requestExternalWalletAuthorization,
  getDefaultProvider,
  detectWalletProvider,
  supportsEIP7702Authorization,
} from "../src/index";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  failTest,
  logDetail,
} from "./test-utils";

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

async function runTests() {
  startTestSuite("External Wallet Integration (EIP-7702)");

  await runTest("exports are available", async () => {
    assert(
      typeof requestExternalWalletAuthorization === "function",
      "requestExternalWalletAuthorization should be exported"
    );
    assert(
      typeof getDefaultProvider === "function",
      "getDefaultProvider should be exported"
    );
    assert(
      typeof detectWalletProvider === "function",
      "detectWalletProvider should be exported"
    );
    assert(
      typeof supportsEIP7702Authorization === "function",
      "supportsEIP7702Authorization should be exported"
    );
    passTest("All exports available");
  });

  await runTest("SDK method exists", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    assert(
      typeof sdk.requestExternalWalletDelegation === "function",
      "requestExternalWalletDelegation method should exist on SDK"
    );
    passTest("SDK method available");
  });

  await runTest("getDefaultProvider returns null in Node.js", async () => {
    const provider = getDefaultProvider();
    assert(
      provider === null,
      "Should return null in Node.js environment (no window.ethereum)"
    );
    passTest("Returns null in Node.js as expected");
  });

  await runTest("requestExternalWalletDelegation requires authentication", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    try {
      await sdk.requestExternalWalletDelegation({
        chainId: 1,
        nonce: 0n,
      });
      failTest("Should have thrown an error");
    } catch (error) {
      const errMsg = (error as Error).message;
      logDetail(`Error: ${errMsg}`);

      assert(
        errMsg.includes("Must be authenticated") ||
          errMsg.includes("No external wallet provider"),
        "Should throw authentication or provider error"
      );
      passTest("Correctly requires authentication");
    }
  });

  await runTest("Mock provider interface", async () => {
    // Create mock EIP-1193 provider
    const mockProvider = {
      request: async ({ method, params }: { method: string; params?: any[] }) => {
        if (method === "eth_requestAccounts") {
          return ["0x1234567890123456789012345678901234567890"];
        }
        if (method === "eth_sign" || method === "personal_sign") {
          // Return mock signature
          return "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        }
        return null;
      },
    };

    assert(
      typeof mockProvider.request === "function",
      "Mock provider should have request method"
    );

    const accounts = await mockProvider.request({
      method: "eth_requestAccounts",
    });

    assert(
      Array.isArray(accounts) && accounts.length > 0,
      "Mock provider should return accounts"
    );

    logDetail(`Mock provider working: ${accounts[0]}`);
    passTest("Mock provider interface works");
  });

  await runTest("detectWalletProvider with mock", async () => {
    const mockMetaMask = { isMetaMask: true };
    const mockRabby = { isRabby: true };
    const mockUnknown = {};

    const metaMaskName = detectWalletProvider(mockMetaMask as any);
    const rabbyName = detectWalletProvider(mockRabby as any);
    const unknownName = detectWalletProvider(mockUnknown as any);

    assert(metaMaskName === "MetaMask", "Should detect MetaMask");
    assert(rabbyName === "Rabby", "Should detect Rabby");
    assert(unknownName === "Unknown Wallet", "Should detect unknown wallet");

    logDetail(`MetaMask: ${metaMaskName}`);
    logDetail(`Rabby: ${rabbyName}`);
    logDetail(`Unknown: ${unknownName}`);

    passTest("Wallet detection works");
  });

  await runTest("supportsEIP7702Authorization basic check", async () => {
    const mockProvider = {
      request: async ({ method }: { method: string }) => {
        if (method === "eth_accounts") {
          return ["0x1234567890123456789012345678901234567890"];
        }
        return null;
      },
    };

    const supported = await supportsEIP7702Authorization(mockProvider as any);

    assert(
      typeof supported === "boolean",
      "Should return boolean"
    );

    logDetail(`Supports EIP-7702: ${supported}`);
    passTest("Support check works");
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error("Test suite failed:", error);
  process.exit(1);
});
