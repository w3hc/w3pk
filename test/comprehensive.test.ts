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
  deriveEncryptionKeyFromSignature,
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

  // Test 4: Encryption/Decryption with Signature-Based Keys
  await runTest("Data Encryption/Decryption", async () => {
    const testData = "secret mnemonic phrase here";
    const credentialId = "test-credential-id";

    // Simulate a WebAuthn signature (mock for testing)
    const mockSignature = crypto.getRandomValues(new Uint8Array(64)).buffer;

    const key = await deriveEncryptionKeyFromSignature(
      mockSignature,
      credentialId
    );
    const encrypted = await encryptData(testData, key);
    const decrypted = await decryptData(encrypted, key);

    assertEqual(decrypted, testData, "Decrypted data should match original");
    passTest("Encryption/decryption successful");
    logDetail(`Original length: ${testData.length}`);
    logDetail(`Encrypted length: ${encrypted.length}`);
    logDetail("Security: Key derived from WebAuthn signature");
    logDetail("Requires: Biometric/PIN authentication");
  });

  // Test 5: SDK Initialization
  await runTest("SDK Initialization", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    passTest("SDK initialized");
    logDetail(`Authenticated: ${sdk.isAuthenticated}`);
  });

  // Test 6: SDK with Stealth Addresses
  await runTest("SDK with Stealth Addresses", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      stealthAddresses: {},
    });

    passTest("SDK with stealth addresses initialized");
    logDetail(`Stealth module: ${sdk.stealth ? "Present" : "Not present"}`);
  });

  // Test 7: SDK with ZK Proofs
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

  // Test 8: Message Signing
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

  // Test 9: Address Validation
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
