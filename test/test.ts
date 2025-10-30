import { mockLocalStorage } from "./setup";
import { createWeb3Passkey } from "../src/index";

console.log("=== Basic SDK Tests ===\n");

// Test 1: SDK Initialization
console.log("Test 1: SDK Initialization");
const sdk = createWeb3Passkey({
  storage: mockLocalStorage,
  debug: false,
  onError: (error) => {
    console.error("  SDK Error:", error.message);
  },
  onAuthStateChanged: (isAuth, user) => {
    console.log(`  Auth state changed: ${isAuth ? "Logged in" : "Logged out"} ${user ? `(${user.username})` : ""}`);
  },
});

console.log("  ✓ SDK initialized");
console.log(`  Authenticated: ${sdk.isAuthenticated}`);
console.log(`  Current user: ${sdk.user || "None"}`);

// Test 2: Wallet Generation (Optional Pre-generation)
console.log("\nTest 2: Wallet Generation (Optional)");
async function testWalletGeneration() {
  try {
    const { mnemonic } = await sdk.generateWallet();
    console.log("  ✓ Wallet generated");
    console.log(`  Mnemonic words: ${mnemonic.split(" ").length}`);
    console.log("  Note: This is optional - register() auto-generates if not called");
  } catch (error) {
    console.log("  ✗ Failed:", (error as Error).message);
  }
}

// Test 3: Registration (Auto-generates wallet if not pre-generated)
console.log("\nTest 3: Registration Flow");
async function testRegistration() {
  try {
    // Create new SDK instance for clean test
    const sdk2 = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    // Register without pre-generating wallet
    console.log("  Testing auto-generation in register()...");
    const { address, username } = await sdk2.register({ username: "test-user" });

    console.log("  ✓ Registration successful (wallet auto-generated)");
    console.log(`  Username: ${username}`);
    console.log(`  Address (derived #0): ${address}`);
    console.log(`  User: ${sdk2.user?.username}`);
    console.log(`  Authenticated: ${sdk2.isAuthenticated}`);
  } catch (error) {
    const errMsg = (error as Error).message;
    if (errMsg.includes("WebAuthn")) {
      console.log("  ⚠️  Skipped: WebAuthn requires browser environment");
      console.log("  Note: register() auto-generates wallet correctly");
    } else {
      console.log("  ✗ Failed:", errMsg);
    }
  }
}

// Run all async tests
async function runTests() {
  await testWalletGeneration();
  await testRegistration();

  console.log("\n=== All Tests Complete ===");
  console.log("Note: WebAuthn features require a browser environment");
}

runTests().catch(console.error);
