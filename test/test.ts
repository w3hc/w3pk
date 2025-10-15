import { createWeb3Passkey, Web3Passkey } from "../src/index";

// Mock IndexedDB for Node.js test environment
(global as any).indexedDB = {
  open: () => {
    const request: any = {
      result: {
        objectStoreNames: { contains: () => false },
        createObjectStore: () => ({}),
        transaction: () => ({
          objectStore: () => ({
            put: () => ({ onsuccess: null, onerror: null }),
            get: () => ({ onsuccess: null, onerror: null }),
            delete: () => ({ onsuccess: null, onerror: null }),
          })
        })
      },
      onsuccess: null,
      onerror: null,
      onupgradeneeded: null
    };
    // Simulate success
    setTimeout(() => {
      if (request.onupgradeneeded) request.onupgradeneeded();
      if (request.onsuccess) request.onsuccess();
    }, 0);
    return request;
  }
};

// Mock localStorage for Node.js
(global as any).localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
  clear: () => {},
  length: 0,
  key: () => null
};

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
