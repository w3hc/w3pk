/**
 * EIP-7702 Authorization Example
 *
 * This example demonstrates how to use the signAuthorization method
 * to create gasless transactions with EIP-7702.
 *
 * Based on the Gov cross-chain governance integration guide.
 */

import { createWeb3Passkey } from "../src/index";

async function example() {
  // Initialize Web3Passkey SDK
  const sdk = createWeb3Passkey({
    debug: true,
  });

  // Step 1: Register or login
  console.log("Step 1: Authentication");
  // In a real app, you would call:
  // await sdk.register({ username: "alice" });
  // or
  // await sdk.login("alice");

  // Step 2: Sign an EIP-7702 authorization
  console.log("\nStep 2: Sign Authorization");

  const govContractAddress = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1";
  const chainId = 11155111; // Sepolia testnet

  try {
    // Option 1: Sign with default address (index 0)
    const authorization = await sdk.signAuthorization({
      contractAddress: govContractAddress,
      chainId: chainId,
      nonce: 0n, // Optional, defaults to 0
    });

    console.log("Authorization signed successfully!");
    console.log({
      chainId: authorization.chainId.toString(),
      address: authorization.address,
      nonce: authorization.nonce.toString(),
      yParity: authorization.yParity,
      r: authorization.r,
      s: authorization.s,
    });

    // Option 2: Sign with a specific derived address
    console.log("\nSigning with derived address:");
    const { deriveWalletFromMnemonic } = await import("w3pk");
    const mnemonic = "your mnemonic phrase here"; // Get from secure source
    const { privateKey: derivedKey } = deriveWalletFromMnemonic(mnemonic, 5);

    const authFromDerived = await sdk.signAuthorization({
      contractAddress: govContractAddress,
      chainId: chainId,
      privateKey: derivedKey, // Use derived private key
    });

    console.log("Authorization from derived address:", authFromDerived.address);

    // Option 3: Sign with a stealth address
    console.log("\nSigning with stealth address:");
    const { computeStealthPrivateKey } = await import("w3pk");
    const viewingKey = "0x...";
    const spendingKey = "0x...";
    const ephemeralPubKey = "0x..."; // From ERC-5564 announcement

    const stealthPrivKey = computeStealthPrivateKey(
      viewingKey,
      spendingKey,
      ephemeralPubKey
    );

    const authFromStealth = await sdk.signAuthorization({
      contractAddress: govContractAddress,
      chainId: chainId,
      privateKey: stealthPrivKey, // Use computed stealth private key
    });

    console.log("Authorization from stealth address:", authFromStealth.address);

    // Step 3: Use the authorization with ethers.js or viem
    console.log("\nStep 3: Submit Transaction");
    console.log("You can now use this authorization with ethers.js or viem:");

    console.log(`
// Example with viem:
import { walletClient, publicClient } from "./config";
import { encodeFunctionData } from "viem";
import { govAbi } from "./abis";

const hash = await walletClient.sendTransaction({
  to: "${govContractAddress}",
  data: encodeFunctionData({
    abi: govAbi,
    functionName: "propose",
    args: [targets, values, calldatas, description],
  }),
  authorizationList: [authorization],
});

await publicClient.waitForTransactionReceipt({ hash });
console.log("Proposal created! User paid 0 ETH.");
    `);

    console.log(`
// Example with ethers.js v6:
import { ethers } from "ethers";

const tx = await wallet.sendTransaction({
  to: "${govContractAddress}",
  data: iface.encodeFunctionData("propose", [
    targets,
    values,
    calldatas,
    description,
  ]),
  customData: {
    authorizationList: [authorization],
  },
});

await tx.wait();
console.log("Proposal created! User paid 0 ETH.");
    `);

  } catch (error) {
    console.error("Error:", error);
  }

  // Benefits of EIP-7702:
  console.log("\nBenefits of EIP-7702:");
  console.log("✅ User needs ZERO ETH in their wallet");
  console.log("✅ DAO treasury pays all gas costs");
  console.log("✅ Native protocol support (not a custom implementation)");
  console.log("✅ Works on 329+ EVM chains");
  console.log("✅ Simple user experience");
}

// Note: This example requires WebAuthn (browser environment)
if (typeof window !== "undefined") {
  example().catch(console.error);
} else {
  console.log("This example requires a browser environment with WebAuthn support");
  console.log("Please run this in a web application or use a test runner like Playwright");
}

export default example;
