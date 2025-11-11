/**
 * EIP-7702 signAuthorization method tests
 */

import { mockLocalStorage } from "./setup";
import { createWeb3Passkey } from "../src/index";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  logDetail,
  logInfo,
  skipTest,
  assert,
} from "./test-utils";

async function runTests() {
  startTestSuite("EIP-7702 signAuthorization Tests");

  await runTest("signAuthorization method exists", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    assert(
      typeof sdk.signAuthorization === "function",
      "signAuthorization method should exist on SDK"
    );
    passTest("signAuthorization method is available");
  });

  await runTest("signAuthorization without authentication fails", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    try {
      await sdk.signAuthorization({
        contractAddress: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
        chainId: 11155111,
      });
      throw new Error("Should have thrown an error");
    } catch (error) {
      const errMsg = (error as Error).message;
      const causeMsg = (error as any).cause?.message || "";
      logDetail(`Error: ${errMsg}`);
      if (causeMsg) {
        logDetail(`Cause: ${causeMsg}`);
      }

      // Check if error relates to authentication (could be wrapped)
      const fullError = errMsg + " " + causeMsg;
      assert(
        fullError.includes("authenticated") ||
        fullError.includes("Must be authenticated") ||
        errMsg.includes("Failed to sign authorization"),
        `Should require authentication or fail appropriately, got: ${errMsg}`
      );
      passTest("Correctly requires authentication before signing");
    }
  });

  await runTest("signAuthorization returns correct structure", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    try {
      // Try to register (will fail in Node.js but that's okay)
      await sdk.register({ username: "test-eip7702" });
    } catch (error) {
      const errMsg = (error as Error).message;
      if (errMsg.includes("WebAuthn")) {
        skipTest("WebAuthn requires browser environment");
        logInfo("Structure validation requires browser environment");
        return;
      }
      throw error;
    }

    // If we get here (browser environment), test the signature
    try {
      const authorization = await sdk.signAuthorization({
        contractAddress: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
        chainId: 11155111,
        nonce: 0n,
      });

      // Verify structure
      assert(typeof authorization === "object", "Should return an object");
      assert(typeof authorization.chainId === "bigint", "chainId should be bigint");
      assert(typeof authorization.address === "string", "address should be string");
      assert(typeof authorization.nonce === "bigint", "nonce should be bigint");
      assert(typeof authorization.yParity === "number", "yParity should be number");
      assert(typeof authorization.r === "string", "r should be string");
      assert(typeof authorization.s === "string", "s should be string");

      // Verify values
      assert(authorization.chainId === 11155111n, "chainId should match input");
      assert(authorization.nonce === 0n, "nonce should match input");
      assert(authorization.address.startsWith("0x"), "address should be hex");
      assert(authorization.r.startsWith("0x"), "r should be hex");
      assert(authorization.s.startsWith("0x"), "s should be hex");
      assert(
        authorization.yParity === 0 || authorization.yParity === 1,
        "yParity should be 0 or 1"
      );

      passTest("Authorization signature has correct structure");
      logDetail(`Chain ID: ${authorization.chainId}`);
      logDetail(`Address: ${authorization.address}`);
      logDetail(`Nonce: ${authorization.nonce}`);
      logDetail(`yParity: ${authorization.yParity}`);
      logDetail(`r: ${authorization.r.substring(0, 20)}...`);
      logDetail(`s: ${authorization.s.substring(0, 20)}...`);
    } catch (error) {
      const errMsg = (error as Error).message;
      if (errMsg.includes("session")) {
        skipTest("Session management requires WebAuthn");
        logInfo("Full signature test requires browser environment");
      } else {
        throw error;
      }
    }
  });

  await runTest("signAuthorization with default parameters", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    try {
      await sdk.register({ username: "test-defaults" });
    } catch (error) {
      const errMsg = (error as Error).message;
      if (errMsg.includes("WebAuthn")) {
        skipTest("WebAuthn requires browser environment");
        logInfo("Default parameters test requires browser environment");
        return;
      }
      throw error;
    }

    try {
      // Test with minimal parameters (should use defaults)
      const authorization = await sdk.signAuthorization({
        contractAddress: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
      });

      // Should default to chainId 1 (mainnet) and nonce 0
      assert(authorization.chainId === 1n, "Should default to mainnet (chainId 1)");
      assert(authorization.nonce === 0n, "Should default to nonce 0");

      passTest("Default parameters applied correctly");
      logDetail(`Default chain ID: ${authorization.chainId}`);
      logDetail(`Default nonce: ${authorization.nonce}`);
    } catch (error) {
      const errMsg = (error as Error).message;
      if (errMsg.includes("session")) {
        skipTest("Session management requires WebAuthn");
        logInfo("Default parameters test requires browser environment");
      } else {
        throw error;
      }
    }
  });

  await runTest("signAuthorization with different chain IDs", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    try {
      await sdk.register({ username: "test-chains" });
    } catch (error) {
      const errMsg = (error as Error).message;
      if (errMsg.includes("WebAuthn")) {
        skipTest("WebAuthn requires browser environment");
        logInfo("Multi-chain test requires browser environment");
        return;
      }
      throw error;
    }

    try {
      const testChains = [
        { id: 1, name: "Ethereum Mainnet" },
        { id: 11155111, name: "Sepolia" },
        { id: 8453, name: "Base" },
        { id: 42161, name: "Arbitrum One" },
      ];

      for (const { id, name } of testChains) {
        const authorization = await sdk.signAuthorization({
          contractAddress: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
          chainId: id,
        });

        assert(
          authorization.chainId === BigInt(id),
          `Chain ID should match for ${name}`
        );
        logDetail(`✓ ${name} (${id}): ${authorization.chainId}`);
      }

      passTest("Multiple chain IDs handled correctly");
    } catch (error) {
      const errMsg = (error as Error).message;
      if (errMsg.includes("session")) {
        skipTest("Session management requires WebAuthn");
        logInfo("Multi-chain test requires browser environment");
      } else {
        throw error;
      }
    }
  });

  await runTest("signAuthorization with privateKey parameter", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    try {
      await sdk.register({ username: "test-private-key" });
    } catch (error) {
      const errMsg = (error as Error).message;
      if (errMsg.includes("WebAuthn")) {
        skipTest("WebAuthn requires browser environment");
        logInfo("privateKey test requires browser environment");
        return;
      }
      throw error;
    }

    try {
      // Derive a wallet to get a private key
      const { deriveWalletFromMnemonic, generateBIP39Wallet } = await import("../src/index");
      const { mnemonic } = generateBIP39Wallet();

      // Get private key at index 5
      const derived = deriveWalletFromMnemonic(mnemonic, 5);

      // Test with default address (should use index 0)
      const auth0 = await sdk.signAuthorization({
        contractAddress: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
        chainId: 11155111,
      });

      logDetail(`Default address: ${auth0.address}`);

      // Test with specific privateKey (from derived address or stealth address)
      const auth1 = await sdk.signAuthorization({
        contractAddress: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
        chainId: 11155111,
        privateKey: derived.privateKey, // Use derived private key
      });

      assert(
        auth1.address.toLowerCase() === derived.address.toLowerCase(),
        "Should use address derived from provided private key"
      );

      passTest("privateKey parameter works correctly");
      logDetail(`Derived address: ${auth1.address}`);
    } catch (error) {
      const errMsg = (error as Error).message;
      if (errMsg.includes("session")) {
        skipTest("Session management requires WebAuthn");
        logInfo("privateKey test requires browser environment with proper wallet setup");
      } else {
        throw error;
      }
    }
  });

  logInfo("Note: Full WebAuthn-based tests require a browser environment");
  logInfo("Run tests in browser using a test runner like Vitest or Playwright");
  endTestSuite();
}

runTests().catch(console.error);
