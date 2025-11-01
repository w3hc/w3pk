/**
 * Comprehensive SDK Tests
 * Tests low-level wallet utilities and SDK functionality
 */
import { mockLocalStorage } from "./setup";
import { createWeb3Passkey } from "../src/index";
import {
  generateBIP39Wallet,
  createWalletFromMnemonic,
  deriveWalletFromMnemonic,
} from "../src/wallet/generate";
import {
  deriveEncryptionKeyFromWebAuthn,
  encryptData,
  decryptData,
} from "../src/wallet/crypto";
import { ethers } from "ethers";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  logDetail,
  logInfo,
  assert,
  assertEqual,
} from "./test-utils";

async function runTests() {
  startTestSuite("Comprehensive SDK Tests");
  logInfo("Testing low-level wallet utilities and SDK features");

  // Test 1: Wallet Generation
  await runTest("Wallet Generation", async () => {
    const wallet = generateBIP39Wallet();
    passTest("BIP39 wallet generated");
    logDetail(`Address: ${wallet.address}`);
    logDetail(`Mnemonic words: ${wallet.mnemonic.split(" ").length}`);
  });

  // Test 2: Wallet Recovery
  await runTest("Wallet Recovery from Mnemonic", async () => {
    const originalWallet = generateBIP39Wallet();
    const recoveredWallet = createWalletFromMnemonic(originalWallet.mnemonic);

    assertEqual(
      recoveredWallet.address,
      originalWallet.address,
      "Addresses should match"
    );
    passTest("Wallet recovered successfully");
    logDetail(`Addresses match: ${recoveredWallet.address}`);
  });

  // Test 3: HD Wallet Derivation
  await runTest("HD Wallet Derivation", async () => {
    const wallet = generateBIP39Wallet();
    const derived0 = deriveWalletFromMnemonic(wallet.mnemonic, 0);
    const derived1 = deriveWalletFromMnemonic(wallet.mnemonic, 1);

    assert(
      derived0.address !== derived1.address,
      "Derived addresses should be different"
    );
    passTest("HD derivation working");
    logDetail(`Index 0: ${derived0.address}`);
    logDetail(`Index 1: ${derived1.address}`);
  });

  // Test 4: Encryption/Decryption with WebAuthn-Based Keys
  await runTest("Data Encryption/Decryption", async () => {
    const testData = "secret mnemonic phrase here";
    const credentialId = "test-credential-id";
    const publicKey = "test-public-key";

    // Derive key from WebAuthn credential metadata (secure method)
    const key = await deriveEncryptionKeyFromWebAuthn(credentialId, publicKey);
    const encrypted = await encryptData(testData, key);
    const decrypted = await decryptData(encrypted, key);

    assertEqual(decrypted, testData, "Decrypted data should match original");
    passTest("Encryption/decryption successful");
    logDetail(`Original length: ${testData.length}`);
    logDetail(`Encrypted length: ${encrypted.length}`);
    logDetail("Security: Key derived from WebAuthn credential");
    logDetail("Method: Authentication-gated encryption");
  });

  // Test 5: Encrypted Credential Storage (v0.7.5 fix)
  await runTest("Encrypted Credential Storage", async () => {
    const { CredentialStorage } = await import("../src/auth/storage");
    const storage = new CredentialStorage(mockLocalStorage);

    const testCredential = {
      id: "test-cred-123",
      publicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...", // Mock public key
      username: "alice",
      ethereumAddress: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
      createdAt: Date.now(),
      lastUsed: Date.now(),
    };

    // Save credential (should encrypt username/address)
    await storage.saveCredential(testCredential);

    // Retrieve credential (should decrypt)
    const retrieved = await storage.getCredentialById(testCredential.id);

    assert(retrieved !== null, "Credential should be retrieved");
    assertEqual(retrieved!.username, testCredential.username, "Username should match after decryption");
    assertEqual(retrieved!.ethereumAddress, testCredential.ethereumAddress, "Address should match after decryption");
    assertEqual(retrieved!.publicKey, testCredential.publicKey, "Public key should be stored and retrieved (v0.7.5 fix)");

    // Verify data is encrypted in storage
    const storageKeys = Object.keys(mockLocalStorage);
    const credentialKey = storageKeys.find(k => k.startsWith('w3pk_credential_') && k !== 'w3pk_credential_index');

    if (credentialKey) {
      const rawData = JSON.parse(mockLocalStorage[credentialKey]);
      assert(rawData.encryptedUsername !== undefined, "Username should be encrypted in storage");
      assert(rawData.encryptedAddress !== undefined, "Address should be encrypted in storage");
      assert(rawData.publicKey !== undefined, "Public key should be stored (required for key derivation)");
      assert(rawData.username === undefined, "Plaintext username should not exist");
      assert(rawData.ethereumAddress === undefined, "Plaintext address should not exist");
    }

    passTest("Encrypted storage verified (metadata encrypted, public key preserved)");
    logDetail("✓ Username encrypted in localStorage");
    logDetail("✓ Address encrypted in localStorage");
    logDetail("✓ Public key stored (v0.7.5 critical fix)");
    logDetail("✓ Decryption successful");
  });

  // Test 6: SDK Initialization
  await runTest("SDK Initialization", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    passTest("SDK initialized");
    logDetail(`Authenticated: ${sdk.isAuthenticated}`);
  });

  // Test 7: SDK with Stealth Addresses
  await runTest("SDK with Stealth Addresses", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      stealthAddresses: {},
    });

    passTest("SDK with stealth addresses initialized");
    logDetail(`Stealth module: ${sdk.stealth ? "Present" : "Not present"}`);
  });

  // Test 8: SDK with ZK Proofs
  await runTest("SDK with ZK Proofs", async () => {
    const zkSdk = createWeb3Passkey({
      storage: mockLocalStorage,
      zkProofs: {
        enabledProofs: ["membership", "threshold"],
      },
    });

    passTest("SDK with ZK proofs initialized");
    logDetail(`ZK module available: ${zkSdk.zk ? "Yes" : "No"}`);
  });

  // Test 9: Message Signing
  await runTest("Message Signing", async () => {
    const wallet = generateBIP39Wallet();
    const ethersWallet = createWalletFromMnemonic(wallet.mnemonic);
    const message = "Hello, Web3!";

    const signature = await ethersWallet.signMessage(message);
    const recovered = ethers.verifyMessage(message, signature);

    assertEqual(
      recovered.toLowerCase(),
      wallet.address.toLowerCase(),
      "Signature verification should succeed"
    );
    passTest("Message signing verified");
    logDetail(`Message: ${message}`);
    logDetail(`Signer: ${recovered}`);
  });

  // Test 10: Address Validation
  await runTest("Address Validation", async () => {
    const wallet = generateBIP39Wallet();
    const isValid = /^0x[a-fA-F0-9]{40}$/.test(wallet.address);

    assert(isValid, "Address should be valid Ethereum format");
    passTest("Valid Ethereum address format");
    logDetail(`Address: ${wallet.address}`);
  });

  logInfo("WebAuthn tests require a browser environment");
  logInfo("ZK proof tests require compiled circuits");
  endTestSuite();
}

runTests().catch(console.error);
