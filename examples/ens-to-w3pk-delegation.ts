/**
 * ENS Account to w3pk Account Delegation (EIP-7702)
 *
 * This example demonstrates how users can sign an EIP-7702 authorization
 * from their ENS account (using MetaMask/Rabby) and delegate it to their
 * w3pk STANDARD+MAIN account.
 *
 * Use Case:
 * - User has existing ENS account with assets/identity
 * - User wants to use w3pk's WebAuthn security
 * - User delegates ENS account to w3pk account via EIP-7702
 * - User can now control ENS account with WebAuthn biometrics
 *
 * Benefits:
 * - Keep existing ENS identity and assets
 * - Upgrade to WebAuthn security (no seed phrases)
 * - ENS account acts as smart contract wallet
 * - Gasless transactions (sponsor can pay)
 */

import { createWeb3Passkey, requestExternalWalletAuthorization } from "../src/index";

async function basicExample() {
  console.log("=== Basic: ENS → w3pk Delegation ===\n");

  // Step 1: Create/login to w3pk account
  const w3pk = createWeb3Passkey({
    debug: true,
  });

  console.log("Step 1: Create w3pk account with WebAuthn");
  // In real app:
  // await w3pk.register({ username: "alice" });
  // or
  // await w3pk.login("alice");

  // For this example, we'll use a mock address
  const w3pkAddress = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"; // Your w3pk STANDARD+MAIN address
  console.log(`w3pk account created: ${w3pkAddress}\n`);

  // Step 2: Request MetaMask to sign EIP-7702 authorization
  console.log("Step 2: Request MetaMask to delegate ENS account to w3pk");

  try {
    // Option A: Use SDK convenience method (recommended)
    const authorization = await w3pk.requestExternalWalletDelegation({
      chainId: 1, // Ethereum mainnet
      nonce: 0n,
    });

    console.log("✅ Authorization signed!");
    console.log({
      chainId: authorization.chainId.toString(),
      delegateToAddress: authorization.address,
      nonce: authorization.nonce.toString(),
      signature: {
        yParity: authorization.yParity,
        r: authorization.r.substring(0, 10) + "...",
        s: authorization.s.substring(0, 10) + "...",
      },
    });

    // Step 3: Include authorization in first transaction
    console.log("\nStep 3: Include authorization in first transaction");
    console.log(`
// With viem:
import { walletClient } from 'viem';

const hash = await walletClient.sendTransaction({
  to: '${w3pkAddress}',
  value: 0n,
  authorizationList: [authorization], // Activates delegation
});

console.log("ENS account now delegates to w3pk account!");
    `);
  } catch (error) {
    console.error("Error:", error);
    console.log("\nNote: This example requires a browser with MetaMask installed");
  }
}

async function advancedExample() {
  console.log("\n\n=== Advanced: Direct API Usage ===\n");

  // For advanced users who want direct control

  const w3pk = createWeb3Passkey();

  // Step 1: Get w3pk account
  // await w3pk.register({ username: "bob" });
  const w3pkAddress = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1";

  // Step 2: Request authorization using direct API
  console.log("Using direct API for more control:");

  if (typeof window !== "undefined" && (window as any).ethereum) {
    const provider = (window as any).ethereum;

    // Option B: Use low-level API directly
    const authorization = await requestExternalWalletAuthorization(provider, {
      delegateToAddress: w3pkAddress,
      chainId: 1,
      nonce: 0n,
      accountIndex: 0, // Use first account from MetaMask
    });

    console.log("Authorization:", authorization);

    // Can now use with any Web3 library
    console.log(`
// With ethers.js:
import { ethers } from 'ethers';

const tx = await wallet.sendTransaction({
  to: '${w3pkAddress}',
  value: 0,
  customData: {
    authorizationList: [authorization],
  },
});

await tx.wait();
console.log("Delegation active!");
    `);
  } else {
    console.log("No ethereum provider found (requires browser environment)");
  }
}

async function multiAccountExample() {
  console.log("\n\n=== Multi-Account: Delegate Multiple ENS Accounts ===\n");

  const w3pk = createWeb3Passkey();
  // await w3pk.register({ username: "charlie" });
  const w3pkAddress = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1";

  console.log("Scenario: User has multiple MetaMask accounts");
  console.log("Goal: Delegate all of them to single w3pk account\n");

  if (typeof window !== "undefined" && (window as any).ethereum) {
    const provider = (window as any).ethereum;

    // Get all accounts
    const accounts = await provider.request({
      method: "eth_requestAccounts",
    });

    console.log(`Found ${accounts.length} accounts in MetaMask`);

    // Delegate each account
    const authorizations = [];

    for (let i = 0; i < accounts.length; i++) {
      console.log(`\nDelegating account ${i + 1}/${accounts.length}: ${accounts[i]}`);

      const auth = await requestExternalWalletAuthorization(provider, {
        delegateToAddress: w3pkAddress,
        chainId: 1,
        nonce: 0n,
        accountIndex: i, // Specify which account to sign with
      });

      authorizations.push(auth);
      console.log(`✅ Signed from ${accounts[i]}`);
    }

    console.log(`\n✅ All ${authorizations.length} accounts ready to delegate!`);
    console.log("Now send one transaction per account to activate delegation.");
  } else {
    console.log("No ethereum provider found (requires browser environment)");
  }
}

async function fullWorkflowExample() {
  console.log("\n\n=== Full Workflow: Real-World Usage ===\n");

  // Step 1: User registers w3pk account
  console.log("1️⃣  User registers w3pk account with biometrics");
  const w3pk = createWeb3Passkey({
    sessionDuration: 15, // 15 minute sessions
  });

  // In browser:
  // await w3pk.register({ username: "dao-voter" });
  const w3pkAddress = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1";
  console.log(`   ✅ w3pk account: ${w3pkAddress}\n`);

  // Step 2: User delegates ENS account to w3pk
  console.log("2️⃣  User delegates ENS account (MetaMask) → w3pk");
  // In browser:
  // const authorization = await w3pk.requestExternalWalletDelegation({
  //   chainId: 1,
  //   nonce: 0n,
  // });
  console.log("   ✅ EIP-7702 authorization signed\n");

  // Step 3: Activate delegation with first transaction
  console.log("3️⃣  Activate delegation (one-time setup)");
  console.log(`
   // Send transaction with authorization
   const hash = await walletClient.sendTransaction({
     to: '${w3pkAddress}',
     value: 0n,
     authorizationList: [authorization],
   });
   `);
  console.log("   ✅ Delegation activated!\n");

  // Step 4: Now ENS account is controlled by w3pk
  console.log("4️⃣  ENS account now controlled by w3pk WebAuthn");
  console.log("   • User signs transactions with biometrics (no MetaMask popup)");
  console.log("   • ENS identity preserved (keeps ENS name, assets, history)");
  console.log("   • Smart contract wallet features (batching, gasless, etc.)");
  console.log("   • Can revoke delegation anytime\n");

  // Step 5: Using the delegated account
  console.log("5️⃣  Usage examples:");
  console.log(`
   // Sign message with w3pk (controls ENS account)
   const signature = await w3pk.signMessage("Hello from ENS via w3pk!");

   // Send transaction from ENS account (via w3pk)
   await w3pk.sendTransaction({
     to: recipient,
     value: ethers.parseEther("0.1"),
   });

   // Vote in DAO (gasless!)
   const voteAuth = await w3pk.signAuthorization({
     contractAddress: govContract,
     chainId: 1,
   });
  `);

  console.log("\n🎉 Complete! User now has:");
  console.log("   • ENS identity (unchanged)");
  console.log("   • WebAuthn security (no seed phrases)");
  console.log("   • Smart contract wallet features");
  console.log("   • Gasless transaction support");
}

// Main
async function main() {
  const mode = process.argv[2] || "basic";

  switch (mode) {
    case "basic":
      await basicExample();
      break;
    case "advanced":
      await advancedExample();
      break;
    case "multi":
      await multiAccountExample();
      break;
    case "full":
      await fullWorkflowExample();
      break;
    default:
      console.log("Usage: tsx ens-to-w3pk-delegation.ts [basic|advanced|multi|full]");
      console.log("\nExamples:");
      console.log("  basic    - Simple ENS → w3pk delegation");
      console.log("  advanced - Direct API usage");
      console.log("  multi    - Delegate multiple accounts");
      console.log("  full     - Complete real-world workflow");
  }
}

// Run examples
if (typeof window !== "undefined") {
  // Browser environment
  main().catch(console.error);
} else {
  // Node environment - just show documentation
  console.log("╔════════════════════════════════════════════════════════════════╗");
  console.log("║  ENS Account → w3pk Account Delegation (EIP-7702)             ║");
  console.log("╚════════════════════════════════════════════════════════════════╝\n");

  console.log("This example requires a browser environment with:");
  console.log("  • MetaMask or Rabby wallet installed");
  console.log("  • An ENS account with funds");
  console.log("  • WebAuthn support (FaceID, TouchID, etc.)\n");

  console.log("To run this example:");
  console.log("  1. Create an HTML file that imports this module");
  console.log("  2. Serve it with: npx serve . -l 3000");
  console.log("  3. Open http://localhost:3000 in browser\n");

  console.log("Quick start:");
  console.log("  ```typescript");
  console.log("  import { createWeb3Passkey } from 'w3pk';");
  console.log("");
  console.log("  const w3pk = createWeb3Passkey();");
  console.log("  await w3pk.register({ username: 'alice' });");
  console.log("");
  console.log("  // Delegate MetaMask ENS account to w3pk");
  console.log("  const auth = await w3pk.requestExternalWalletDelegation({");
  console.log("    chainId: 1,");
  console.log("    nonce: 0n");
  console.log("  });");
  console.log("");
  console.log("  // Activate delegation");
  console.log("  await provider.request({");
  console.log("    method: 'eth_sendTransaction',");
  console.log("    params: [{");
  console.log("      to: w3pk.getAddress(),");
  console.log("      value: '0x0',");
  console.log("      authorizationList: [auth]");
  console.log("    }]");
  console.log("  });");
  console.log("  ```\n");

  console.log("Run specific examples:");
  console.log("  tsx ens-to-w3pk-delegation.ts basic");
  console.log("  tsx ens-to-w3pk-delegation.ts advanced");
  console.log("  tsx ens-to-w3pk-delegation.ts multi");
  console.log("  tsx ens-to-w3pk-delegation.ts full");
}

export default main;
