/**
 * EIP-7702 signAuthorization method tests
 */

import { mockLocalStorage } from "./setup";
import { Signature, Wallet, recoverAddress } from "ethers";
import {
  createWeb3Passkey,
  deriveWalletFromMnemonic,
  generateBIP39Wallet,
} from "../src/index";
import {
  hashEIP7702AuthorizationMessage,
  verifyEIP7702Authorization,
} from "../src/eip7702/utils";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  logDetail,
  assert,
  assertThrows,
} from "./test-utils";

const CONTRACT = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1";

/** An SDK with a signed-in user, without going through WebAuthn */
function authenticatedSdk() {
  const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false });
  (sdk as any).currentUser = {
    username: "eip7702",
    ethereumAddress: Wallet.createRandom().address,
    credentialId: "test-credential",
  };
  return sdk;
}

function recoverSigner(authorization: {
  chainId: bigint;
  address: string;
  nonce: bigint;
  yParity: number;
  r: string;
  s: string;
}): string {
  const hash = hashEIP7702AuthorizationMessage(
    authorization.chainId,
    authorization.address,
    authorization.nonce
  );
  return recoverAddress(hash, Signature.from(authorization));
}

async function runTests() {
  startTestSuite("EIP-7702 signAuthorization Tests");

  await runTest("signAuthorization method exists", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    assert(
      typeof sdk.signAuthorization === "function",
      "signAuthorization method should exist on SDK"
    );
    passTest("signAuthorization method is available");
  });

  await runTest("signAuthorization without authentication fails", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      debug: false,
    });

    let rejected: any;
    try {
      await sdk.signAuthorization({
        contractAddress: CONTRACT,
        chainId: 11155111,
        privateKey: Wallet.createRandom().privateKey,
      });
    } catch (error) {
      rejected = error;
    }

    assert(rejected, "Should have thrown an error");
    const cause = rejected.originalError?.message ?? "";
    logDetail(`Error: ${rejected.message} (${cause})`);
    assert(
      cause.includes("Must be authenticated"),
      `Should require authentication, got: ${rejected.message} (${cause})`
    );
    passTest("Correctly requires authentication before signing");
  });

  await runTest("signAuthorization returns correct structure", async () => {
    const signer = Wallet.createRandom();
    const authorization = await authenticatedSdk().signAuthorization({
      contractAddress: CONTRACT,
      chainId: 11155111,
      nonce: 0n,
      privateKey: signer.privateKey,
    });

    assert(typeof authorization.chainId === "bigint", "chainId should be bigint");
    assert(typeof authorization.nonce === "bigint", "nonce should be bigint");
    assert(authorization.chainId === 11155111n, "chainId should match input");
    assert(authorization.nonce === 0n, "nonce should match input");
    assert(
      authorization.address === CONTRACT.toLowerCase(),
      "address should be the delegated contract, not the signer"
    );
    assert(/^0x[0-9a-f]{64}$/.test(authorization.r), "r should be 32-byte hex");
    assert(/^0x[0-9a-f]{64}$/.test(authorization.s), "s should be 32-byte hex");
    assert(
      authorization.yParity === 0 || authorization.yParity === 1,
      "yParity should be 0 or 1"
    );

    passTest("Authorization signature has correct structure");
    logDetail(`r: ${authorization.r.substring(0, 20)}...`);
  });

  await runTest("signAuthorization with default parameters", async () => {
    const authorization = await authenticatedSdk().signAuthorization({
      contractAddress: CONTRACT,
      privateKey: Wallet.createRandom().privateKey,
    });

    assert(authorization.chainId === 1n, "Should default to mainnet (chainId 1)");
    assert(authorization.nonce === 0n, "Should default to nonce 0");
    passTest("Default parameters applied correctly");
  });

  await runTest("signAuthorization with different chain IDs and nonces", async () => {
    const sdk = authenticatedSdk();
    const signer = Wallet.createRandom();

    for (const [chainId, nonce] of [[1, 0n], [11155111, 1n], [8453, 7n], [42161, 2n ** 40n]] as const) {
      const authorization = await sdk.signAuthorization({
        contractAddress: CONTRACT,
        chainId,
        nonce,
        privateKey: signer.privateKey,
      });

      assert(authorization.chainId === BigInt(chainId), `chainId should be ${chainId}`);
      assert(authorization.nonce === nonce, `nonce should be ${nonce}`);
      assert(
        recoverSigner(authorization) === signer.address,
        `Signature for chain ${chainId} should recover to the signer`
      );
      logDetail(`✓ chain ${chainId}, nonce ${nonce}`);
    }

    passTest("Each chain ID and nonce is part of the signed message");
  });

  await runTest("signAuthorization signs with the given privateKey", async () => {
    const { mnemonic } = generateBIP39Wallet();
    const derived = deriveWalletFromMnemonic(mnemonic, 5);

    const authorization = await authenticatedSdk().signAuthorization({
      contractAddress: CONTRACT,
      chainId: 11155111,
      privateKey: derived.privateKey,
    });

    assert(
      recoverSigner(authorization) === derived.address,
      "Signature should recover to the address of the given private key"
    );
    assert(
      verifyEIP7702Authorization(
        authorization.chainId,
        CONTRACT,
        authorization.nonce,
        authorization,
        derived.address
      ),
      "verifyEIP7702Authorization should accept the signature"
    );

    passTest("privateKey parameter selects the signing key");
    logDetail(`Signer: ${derived.address}`);
  });

  await runTest("signAuthorization rejects an invalid privateKey", async () => {
    await assertThrows(
      () =>
        authenticatedSdk().signAuthorization({
          contractAddress: CONTRACT,
          privateKey: "0x1234",
        }),
      "Should reject a malformed private key"
    );
    passTest("Invalid private key rejected");
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
