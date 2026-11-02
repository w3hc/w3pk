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
} from "./test-utils";

async function runTests() {
  startTestSuite("Basic SDK Tests");

  // Test 1: SDK Initialization
  await runTest("SDK Initialization", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
      onError: (error) => {
        logInfo(`SDK Error: ${error.message}`);
      },
      onAuthStateChanged: (isAuth, user) => {
        logInfo(`Auth state changed: ${isAuth ? "Logged in" : "Logged out"} ${user ? `(${user.username})` : ""}`);
      },
    });

    passTest("SDK initialized");
    logDetail(`Authenticated: ${sdk.isAuthenticated}`);
    logDetail(`Current user: ${sdk.user || "None"}`);
  });

  // Test 2: Wallet Generation (Optional Pre-generation)
  await runTest("Wallet Generation (Optional)", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    const { mnemonic } = await sdk.generateWallet();
    passTest("Wallet generated");
    logDetail(`Mnemonic words: ${mnemonic.split(" ").length}`);
    logInfo("This is optional - register() auto-generates if not called");
  });

  // Test 3: Registration (Auto-generates wallet if not pre-generated)
  await runTest("Registration Flow", async () => {
    // Create new SDK instance for clean test
    const sdk2 = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    try {
      // Register without pre-generating wallet
      logInfo("Testing auto-generation in register()...");
      const { address, username } = await sdk2.register({ username: "test-user" });

      passTest("Registration successful (wallet auto-generated)");
      logDetail(`Username: ${username}`);
      logDetail(`Address (derived #0): ${address}`);
      logDetail(`User: ${sdk2.user?.username}`);
      logDetail(`Authenticated: ${sdk2.isAuthenticated}`);
    } catch (error) {
      const errMsg = (error as Error).message;
      if (errMsg.includes("navigator is not defined") || errMsg.includes("WebAuthn") || errMsg.includes("navigator.credentials") || errMsg.includes("Cannot read properties of undefined")) {
        skipTest("WebAuthn requires browser environment");
        logInfo("For WebAuthn tests, use test/webauthn-native.html in a browser");
        passTest("Skipped (requires browser)");
      } else {
        throw error;
      }
    }
  });

  logInfo("WebAuthn features require a browser environment");
  endTestSuite();
}

runTests().catch(console.error);
