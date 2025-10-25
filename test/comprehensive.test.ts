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
  deriveEncryptionKey,
  encryptData,
  decryptData,
} from "../src/wallet/crypto";
import { ethers } from "ethers";

console.log("=== Comprehensive SDK Tests ===\n");
console.log("Testing low-level wallet utilities and SDK features\n");

// Test 1: Wallet Generation
console.log("Test 1: Wallet Generation");
try {
  const wallet = generateBIP39Wallet();
  console.log("  ✓ BIP39 wallet generated");
  console.log(`  Address: ${wallet.address}`);
  console.log(`  Mnemonic words: ${wallet.mnemonic.split(" ").length}`);
} catch (error) {
  console.log("  ✗ Failed:", (error as Error).message);
}

// Test 2: Wallet Recovery
console.log("\nTest 2: Wallet Recovery from Mnemonic");
try {
  const originalWallet = generateBIP39Wallet();
  const recoveredWallet = createWalletFromMnemonic(originalWallet.mnemonic);

  if (recoveredWallet.address === originalWallet.address) {
    console.log("  ✓ Wallet recovered successfully");
    console.log(`  Addresses match: ${recoveredWallet.address}`);
  } else {
    console.log("  ✗ Address mismatch");
  }
} catch (error) {
  console.log("  ✗ Failed:", (error as Error).message);
}

// Test 3: HD Wallet Derivation
console.log("\nTest 3: HD Wallet Derivation");
try {
  const wallet = generateBIP39Wallet();
  const derived0 = deriveWalletFromMnemonic(wallet.mnemonic, 0);
  const derived1 = deriveWalletFromMnemonic(wallet.mnemonic, 1);

  if (derived0.address !== derived1.address) {
    console.log("  ✓ HD derivation working");
    console.log(`  Index 0: ${derived0.address}`);
    console.log(`  Index 1: ${derived1.address}`);
  } else {
    console.log("  ✗ Derived addresses are the same");
  }
} catch (error) {
  console.log("  ✗ Failed:", (error as Error).message);
}

// Test 4: Encryption/Decryption
console.log("\nTest 4: Data Encryption/Decryption");
async function testEncryption() {
  try {
    const testData = "secret mnemonic phrase here";
    const credentialId = "test-credential-id";
    const challenge = "test-challenge";

    const key = await deriveEncryptionKey(credentialId, challenge);
    const encrypted = await encryptData(testData, key);
    const decrypted = await decryptData(encrypted, key);

    if (decrypted === testData) {
      console.log("  ✓ Encryption/decryption successful");
      console.log(`  Original length: ${testData.length}`);
      console.log(`  Encrypted length: ${encrypted.length}`);
    } else {
      console.log("  ✗ Decrypted data doesn't match original");
    }
  } catch (error) {
    console.log("  ✗ Failed:", (error as Error).message);
  }
}

// Test 5: SDK Initialization
console.log("\nTest 5: SDK Initialization");
try {
  const sdk = createWeb3Passkey({
    storage: mockLocalStorage,
    debug: false,
  });

  console.log("  ✓ SDK initialized");
  console.log(`  Authenticated: ${sdk.isAuthenticated}`);
} catch (error) {
  console.log("  ✗ Failed:", (error as Error).message);
}

// Test 6: SDK with Stealth Addresses
console.log("\nTest 6: SDK with Stealth Addresses");
try {
  const sdk = createWeb3Passkey({
    storage: mockLocalStorage,
    stealthAddresses: {},
  });

  console.log("  ✓ SDK with stealth addresses initialized");
  console.log(`  Stealth module: ${sdk.stealth ? "Present" : "Not present"}`);
} catch (error) {
  console.log("  ✗ Failed:", (error as Error).message);
}

// Test 7: SDK with ZK Proofs
console.log("\nTest 7: SDK with ZK Proofs");
try {
  const zkSdk = createWeb3Passkey({
    storage: mockLocalStorage,
    zkProofs: {
      enabledProofs: ["membership", "threshold"],
    },
  });

  console.log("  ✓ SDK with ZK proofs initialized");
  console.log(`  ZK module available: ${zkSdk.zk ? "Yes" : "No"}`);
} catch (error) {
  console.log("  ✗ Failed:", (error as Error).message);
}

// Test 8: Wallet Signing
console.log("\nTest 8: Message Signing");
async function testSigning() {
  try {
    const wallet = generateBIP39Wallet();
    const ethersWallet = createWalletFromMnemonic(wallet.mnemonic);
    const message = "Hello, Web3!";

    const signature = await ethersWallet.signMessage(message);
    const recovered = ethers.verifyMessage(message, signature);

    if (recovered.toLowerCase() === wallet.address.toLowerCase()) {
      console.log("  ✓ Message signing verified");
      console.log(`  Message: ${message}`);
      console.log(`  Signer: ${recovered}`);
    } else {
      console.log("  ✗ Signature verification failed");
    }
  } catch (error) {
    console.log("  ✗ Failed:", (error as Error).message);
  }
}

// Test 9: Address Validation
console.log("\nTest 9: Address Validation");
try {
  const wallet = generateBIP39Wallet();
  const isValid = /^0x[a-fA-F0-9]{40}$/.test(wallet.address);

  if (isValid) {
    console.log("  ✓ Valid Ethereum address format");
    console.log(`  Address: ${wallet.address}`);
  } else {
    console.log("  ✗ Invalid address format");
  }
} catch (error) {
  console.log("  ✗ Failed:", (error as Error).message);
}

// Run async tests
async function runAsyncTests() {
  await testEncryption();
  await testSigning();

  console.log("\n=== All Tests Complete ===");
  console.log("Note: WebAuthn tests require a browser environment");
  console.log("Note: ZK proof tests require compiled circuits");
}

runAsyncTests().catch(console.error);
