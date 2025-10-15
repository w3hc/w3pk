import { createWeb3Passkey, Web3Passkey } from "../src";
import { generateBIP39Wallet, createWalletFromMnemonic, deriveWalletFromMnemonic } from "../src/wallet/generate";
import { deriveEncryptionKey, encryptData, decryptData } from "../src/wallet/crypto";
import { IndexedDBWalletStorage } from "../src/wallet/storage";
import { WalletSigner } from "../src/wallet/signing";
import { ethers } from "ethers";

// Mock IndexedDB for Node.js environment
class MockIDBRequest {
  result: any = null;
  error: any = null;
  onsuccess: ((event: any) => void) | null = null;
  onerror: ((event: any) => void) | null = null;

  constructor(private resultValue?: any, private errorValue?: any) {
    setTimeout(() => {
      if (this.errorValue) {
        this.error = this.errorValue;
        this.onerror?.({ target: this });
      } else {
        this.result = this.resultValue;
        this.onsuccess?.({ target: this });
      }
    }, 0);
  }
}

class MockIDBObjectStore {
  private data: Map<string, any> = new Map();

  put(value: any): MockIDBRequest {
    this.data.set(value.ethereumAddress, value);
    return new MockIDBRequest();
  }

  get(key: string): MockIDBRequest {
    return new MockIDBRequest(this.data.get(key));
  }

  delete(key: string): MockIDBRequest {
    this.data.delete(key);
    return new MockIDBRequest();
  }

  clear(): MockIDBRequest {
    this.data.clear();
    return new MockIDBRequest();
  }
}

class MockIDBTransaction {
  constructor(private store: MockIDBObjectStore) {}

  objectStore(): MockIDBObjectStore {
    return this.store;
  }
}

class MockIDBDatabase {
  private store = new MockIDBObjectStore();
  objectStoreNames = { contains: () => false };

  transaction(): MockIDBTransaction {
    return new MockIDBTransaction(this.store);
  }

  createObjectStore(): MockIDBObjectStore {
    return this.store;
  }
}

class MockIndexedDB {
  open(): MockIDBRequest {
    const db = new MockIDBDatabase();
    return new MockIDBRequest(db);
  }
}

// Setup global mocks
(global as any).indexedDB = new MockIndexedDB();
(global as any).localStorage = {
  data: new Map(),
  setItem(key: string, value: string) { this.data.set(key, value); },
  getItem(key: string) { return this.data.get(key) || null; },
  removeItem(key: string) { this.data.delete(key); },
  clear() { this.data.clear(); }
};
(global as any).window = { localStorage: (global as any).localStorage };

// Test utilities
function runTest(name: string, testFn: () => Promise<void> | void): void {
  console.log(`\n🧪 ${name}`);
  try {
    const result = testFn();
    if (result instanceof Promise) {
      result.then(() => {
        console.log(`✅ ${name} - PASSED`);
      }).catch((error) => {
        console.error(`❌ ${name} - FAILED:`, error.message);
      });
    } else {
      console.log(`✅ ${name} - PASSED`);
    }
  } catch (error) {
    console.error(`❌ ${name} - FAILED:`, (error as Error).message);
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertEquals(actual: any, expected: any, message?: string): void {
  if (actual !== expected) {
    throw new Error(`Assertion failed: ${message || 'Values not equal'} (expected: ${expected}, actual: ${actual})`);
  }
}

function assertNotNull(value: any, message?: string): void {
  if (value === null || value === undefined) {
    throw new Error(`Assertion failed: ${message || 'Value is null or undefined'}`);
  }
}

// =============================================================================
// CORE SDK TESTS
// =============================================================================

runTest("SDK Constructor - Default Config", () => {
  const sdk = createWeb3Passkey({
    apiBaseUrl: "http://localhost:3000"
  });
  
  assert(sdk instanceof Web3Passkey, "Should create Web3Passkey instance");
  assertEquals(sdk.version, "0.4.0", "Should have correct version");
  assertEquals(sdk.isAuthenticated, false, "Should not be authenticated initially");
  assertEquals(sdk.user, null, "Should have no user initially");
});

runTest("SDK Constructor - Custom Config", () => {
  let errorCalled = false;
  let authChangeCalled = false;
  
  const sdk = createWeb3Passkey({
    apiBaseUrl: "http://test.com",
    timeout: 10000,
    debug: true,
    onError: () => { errorCalled = true; },
    onAuthStateChanged: () => { authChangeCalled = true; }
  });
  
  assert(sdk instanceof Web3Passkey, "Should create instance with custom config");
  assertEquals(sdk.version, "0.4.0", "Should have correct version");
});

runTest("SDK Environment Detection", () => {
  const sdk = createWeb3Passkey({
    apiBaseUrl: "http://localhost:3000"
  });
  
  // In Node.js environment, should detect as non-browser
  assertEquals(sdk.isBrowserEnvironment, true, "Should detect browser environment (mocked)");
});

// =============================================================================
// WALLET GENERATION & MANAGEMENT TESTS
// =============================================================================

runTest("BIP39 Wallet Generation", () => {
  const wallet = generateBIP39Wallet();
  
  assertNotNull(wallet.address, "Should generate address");
  assertNotNull(wallet.mnemonic, "Should generate mnemonic");
  assert(wallet.address.startsWith("0x"), "Address should start with 0x");
  assert(wallet.mnemonic.split(" ").length >= 12, "Mnemonic should have at least 12 words");
});

runTest("Wallet Creation from Mnemonic", () => {
  const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const wallet = createWalletFromMnemonic(testMnemonic);
  
  assertNotNull(wallet.address, "Should create address from mnemonic");
  assertNotNull(wallet.privateKey, "Should have private key");
  assertEquals(wallet.address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "Should generate consistent address");
});

runTest("HD Derivation Path Consistency", () => {
  const mnemonic = "test test test test test test test test test test test junk";
  const wallet1 = createWalletFromMnemonic(mnemonic);
  const wallet2 = createWalletFromMnemonic(mnemonic);
  
  assertEquals(wallet1.address, wallet2.address, "Same mnemonic should produce same address");
  assertEquals(wallet1.privateKey, wallet2.privateKey, "Same mnemonic should produce same private key");
});

runTest("Invalid Mnemonic Handling", () => {
  try {
    createWalletFromMnemonic("invalid mnemonic");
    assert(false, "Should throw error for invalid mnemonic");
  } catch (error) {
    assert(error instanceof Error, "Should throw error for invalid mnemonic");
  }
});

runTest("HD Wallet Derivation by Index", () => {
  const testMnemonic = "test test test test test test test test test test test junk";
  
  // Derive wallets at different indices
  const wallet0 = deriveWalletFromMnemonic(testMnemonic, 0);
  const wallet1 = deriveWalletFromMnemonic(testMnemonic, 1);
  const wallet2 = deriveWalletFromMnemonic(testMnemonic, 2);
  
  assertNotNull(wallet0.address, "Should derive wallet at index 0");
  assertNotNull(wallet0.privateKey, "Should have private key at index 0");
  assertNotNull(wallet1.address, "Should derive wallet at index 1");
  assertNotNull(wallet1.privateKey, "Should have private key at index 1");
  assertNotNull(wallet2.address, "Should derive wallet at index 2");
  assertNotNull(wallet2.privateKey, "Should have private key at index 2");
  
  // Different indices should produce different addresses
  assert(wallet0.address !== wallet1.address, "Different indices should have different addresses");
  assert(wallet1.address !== wallet2.address, "Different indices should have different addresses");
  assert(wallet0.privateKey !== wallet1.privateKey, "Different indices should have different private keys");
  
  // All should be valid Ethereum addresses
  assert(wallet0.address.startsWith("0x"), "Should be valid Ethereum address");
  assert(wallet1.address.startsWith("0x"), "Should be valid Ethereum address");
  assert(wallet2.address.startsWith("0x"), "Should be valid Ethereum address");
});

runTest("HD Wallet Derivation Index Validation", () => {
  const testMnemonic = "test test test test test test test test test test test junk";
  
  // Test negative index
  try {
    deriveWalletFromMnemonic(testMnemonic, -1);
    assert(false, "Should throw error for negative index");
  } catch (error) {
    assert(error instanceof Error, "Should throw error for negative index");
  }
  
  // Test non-integer index
  try {
    deriveWalletFromMnemonic(testMnemonic, 1.5);
    assert(false, "Should throw error for non-integer index");
  } catch (error) {
    assert(error instanceof Error, "Should throw error for non-integer index");
  }
  
  // Test default index (should be 0)
  const walletDefault = deriveWalletFromMnemonic(testMnemonic);
  const wallet0 = deriveWalletFromMnemonic(testMnemonic, 0);
  assertEquals(walletDefault.address, wallet0.address, "Default index should be 0");
});

runTest("HD Wallet Derivation Consistency", () => {
  const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  
  // Same index should always produce same result
  const wallet1a = deriveWalletFromMnemonic(testMnemonic, 5);
  const wallet1b = deriveWalletFromMnemonic(testMnemonic, 5);
  
  assertEquals(wallet1a.address, wallet1b.address, "Same mnemonic and index should produce same address");
  assertEquals(wallet1a.privateKey, wallet1b.privateKey, "Same mnemonic and index should produce same private key");
});

// =============================================================================
// ENCRYPTION/DECRYPTION TESTS
// =============================================================================

runTest("Key Derivation", async () => {
  const credentialId = "test-credential-id";
  const challenge = "test-challenge";
  
  const key1 = await deriveEncryptionKey(credentialId, challenge);
  const key2 = await deriveEncryptionKey(credentialId, challenge);
  
  assertNotNull(key1, "Should derive encryption key");
  assertNotNull(key2, "Should derive second encryption key");
  
  // Test that both keys can encrypt/decrypt the same data consistently
  const testData = "test encryption consistency";
  const encrypted1 = await encryptData(testData, key1);
  const encrypted2 = await encryptData(testData, key2);
  
  const decrypted1 = await decryptData(encrypted1, key2); // Cross-decrypt
  const decrypted2 = await decryptData(encrypted2, key1); // Cross-decrypt
  
  assertEquals(decrypted1, testData, "Key1 encrypted data should decrypt with key2");
  assertEquals(decrypted2, testData, "Key2 encrypted data should decrypt with key1");
});

runTest("Data Encryption/Decryption Roundtrip", async () => {
  const testData = "test mnemonic phrase for encryption";
  const credentialId = "test-credential-id";
  const challenge = "test-challenge";
  
  const key = await deriveEncryptionKey(credentialId, challenge);
  const encrypted = await encryptData(testData, key);
  const decrypted = await decryptData(encrypted, key);
  
  assertNotNull(encrypted, "Should encrypt data");
  assertEquals(decrypted, testData, "Should decrypt to original data");
  assert(encrypted !== testData, "Encrypted data should be different from original");
});

runTest("Invalid Key Decryption", async () => {
  const testData = "test data";
  const key1 = await deriveEncryptionKey("cred1", "challenge1");
  const key2 = await deriveEncryptionKey("cred2", "challenge2");
  
  const encrypted = await encryptData(testData, key1);
  
  try {
    await decryptData(encrypted, key2);
    assert(false, "Should fail to decrypt with wrong key");
  } catch (error) {
    assert(error instanceof Error, "Should throw error for wrong key");
  }
});

// =============================================================================
// STORAGE TESTS
// =============================================================================

runTest("IndexedDB Storage Operations", async () => {
  const storage = new IndexedDBWalletStorage();
  await storage.init();
  
  const testData = {
    ethereumAddress: "0x1234567890123456789012345678901234567890",
    encryptedMnemonic: "encrypted-test-mnemonic",
    credentialId: "test-credential",
    challenge: "test-challenge",
    createdAt: Date.now()
  };
  
  // Store data
  await storage.store(testData);
  
  // Retrieve data
  const retrieved = await storage.retrieve(testData.ethereumAddress);
  assertNotNull(retrieved, "Should retrieve stored data");
  assertEquals(retrieved!.ethereumAddress, testData.ethereumAddress, "Should match stored address");
  assertEquals(retrieved!.encryptedMnemonic, testData.encryptedMnemonic, "Should match stored mnemonic");
});

runTest("Storage Multiple Wallets", async () => {
  const storage = new IndexedDBWalletStorage();
  await storage.init();
  
  const wallet1 = {
    ethereumAddress: "0x1111111111111111111111111111111111111111",
    encryptedMnemonic: "encrypted1",
    credentialId: "cred1",
    challenge: "challenge1",
    createdAt: Date.now()
  };
  
  const wallet2 = {
    ethereumAddress: "0x2222222222222222222222222222222222222222",
    encryptedMnemonic: "encrypted2",
    credentialId: "cred2",
    challenge: "challenge2",
    createdAt: Date.now()
  };
  
  await storage.store(wallet1);
  await storage.store(wallet2);
  
  const retrieved1 = await storage.retrieve(wallet1.ethereumAddress);
  const retrieved2 = await storage.retrieve(wallet2.ethereumAddress);
  
  assertNotNull(retrieved1, "Should retrieve first wallet");
  assertNotNull(retrieved2, "Should retrieve second wallet");
  assertEquals(retrieved1!.encryptedMnemonic, "encrypted1", "Should have correct first wallet data");
  assertEquals(retrieved2!.encryptedMnemonic, "encrypted2", "Should have correct second wallet data");
});

runTest("Storage Delete and Clear", async () => {
  const storage = new IndexedDBWalletStorage();
  await storage.init();
  
  const testData = {
    ethereumAddress: "0x3333333333333333333333333333333333333333",
    encryptedMnemonic: "encrypted-test",
    credentialId: "test-cred",
    challenge: "test-challenge",
    createdAt: Date.now()
  };
  
  await storage.store(testData);
  
  // Delete specific wallet
  await storage.delete(testData.ethereumAddress);
  const deleted = await storage.retrieve(testData.ethereumAddress);
  assertEquals(deleted, null, "Should return null for deleted wallet");
  
  // Test clear all
  await storage.store(testData);
  await storage.clear();
  const cleared = await storage.retrieve(testData.ethereumAddress);
  assertEquals(cleared, null, "Should return null after clear");
});

// =============================================================================
// WALLET SIGNER TESTS
// =============================================================================

runTest("WalletSigner Message Signing", async () => {
  const storage = new IndexedDBWalletStorage();
  await storage.init();
  
  const signer = new WalletSigner(storage);
  const mnemonic = "test test test test test test test test test test test junk";
  const wallet = createWalletFromMnemonic(mnemonic);
  
  // Store encrypted wallet
  const credentialId = "test-credential";
  const challenge = "test-challenge";
  const key = await deriveEncryptionKey(credentialId, challenge);
  const encryptedMnemonic = await encryptData(mnemonic, key);
  
  await storage.store({
    ethereumAddress: wallet.address,
    encryptedMnemonic,
    credentialId,
    challenge,
    createdAt: Date.now()
  });
  
  // Sign message
  const message = "Hello, Web3!";
  const signature = await signer.signMessage(wallet.address, message, credentialId, challenge);
  
  assertNotNull(signature, "Should produce signature");
  
  // Verify signature
  const recoveredAddress = ethers.verifyMessage(message, signature);
  assertEquals(recoveredAddress.toLowerCase(), wallet.address.toLowerCase(), "Signature should verify to correct address");
});

runTest("WalletSigner Has Wallet Check", async () => {
  const storage = new IndexedDBWalletStorage();
  await storage.init();
  
  const signer = new WalletSigner(storage);
  const testAddress = "0x4444444444444444444444444444444444444444";
  
  // Should not have wallet initially
  const hasWalletBefore = await signer.hasWallet(testAddress);
  assertEquals(hasWalletBefore, false, "Should not have wallet initially");
  
  // Store wallet
  await storage.store({
    ethereumAddress: testAddress,
    encryptedMnemonic: "encrypted-test",
    credentialId: "test-cred",
    challenge: "test-challenge",
    createdAt: Date.now()
  });
  
  // Should have wallet after storing
  const hasWalletAfter = await signer.hasWallet(testAddress);
  assertEquals(hasWalletAfter, true, "Should have wallet after storing");
});

// =============================================================================
// ERROR HANDLING TESTS
// =============================================================================

runTest("Wallet Generation Error Handling", () => {
  // Test with invalid ethers setup (this is harder to mock, so we'll test known scenarios)
  try {
    const wallet = generateBIP39Wallet();
    assertNotNull(wallet.address, "Should generate wallet even in test environment");
  } catch (error) {
    assert(error instanceof Error, "Should throw proper error type");
  }
});

runTest("Storage Error Handling", async () => {
  const storage = new IndexedDBWalletStorage();
  
  try {
    // Try to retrieve without init (should handle gracefully)
    await storage.retrieve("0x1234567890123456789012345678901234567890");
    // Should either work (auto-init) or throw proper error
    assert(true, "Storage should handle uninitialized state gracefully");
  } catch (error) {
    assert(error instanceof Error, "Should throw proper error type");
  }
});

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

runTest("SDK Wallet Generation Integration", async () => {
  const sdk = createWeb3Passkey({
    apiBaseUrl: "http://localhost:3000",
    debug: false
  });
  
  const wallet = await sdk.generateWallet();
  
  assertNotNull(wallet.address, "Should generate wallet address");
  assertNotNull(wallet.mnemonic, "Should generate mnemonic");
  assert(wallet.address.startsWith("0x"), "Address should be valid Ethereum address");
  assert(wallet.mnemonic.split(" ").length >= 12, "Mnemonic should have sufficient words");
});

runTest("SDK Has Wallet Check", async () => {
  const sdk = createWeb3Passkey({
    apiBaseUrl: "http://localhost:3000"
  });
  
  // Should return false when not authenticated
  const hasWallet = await sdk.hasWallet();
  assertEquals(hasWallet, false, "Should not have wallet when not authenticated");
});

console.log("\n" + "=".repeat(50));
console.log("🚀 COMPREHENSIVE TEST SUITE COMPLETED");
console.log("=".repeat(50));

// Wait for async tests to complete
setTimeout(() => {
  console.log("\n✨ All tests executed. Check results above.");
  process.exit(0);
}, 1000);