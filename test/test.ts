import { createWeb3Passkey, Web3Passkey } from "w3pk";

// Test 1: Create SDK instance
const sdk = createWeb3Passkey({
  apiBaseUrl: "http://localhost:3000",
  debug: true,
  onError: (error) => {
    console.error("SDK Error:", error.message);
  },
  onAuthStateChanged: (isAuth, user) => {
    console.log("Auth changed:", isAuth, user?.username);
  },
});

console.log("SDK initialized successfully");
console.log("Is authenticated:", sdk.isAuthenticated);
console.log("Current user:", sdk.user);
console.log("SDK version:", sdk.version);

// Test 2: Generate wallet (async)
async function testWallet() {
  try {
    const wallet = await sdk.generateWallet();
    console.log("Wallet generated:");
    console.log("  Address:", wallet.address);
    console.log("  Mnemonic:", wallet.mnemonic);
  } catch (error) {
    console.error("Wallet generation failed:", error);
  }
}

// Run async test
testWallet();
