/**
 * EIP-7702 signAuthorization method tests
 */

import { mockLocalStorage } from "./setup";
import { Signature, Wallet, recoverAddress } from "ethers";
import { createWeb3Passkey } from "../src/index";
import {
  hashEIP7702AuthorizationMessage,
  verifyEIP7702Authorization,
} from "../src/eip7702/utils";
import { getOriginSpecificAddress } from "../src/wallet/origin-derivation";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  logDetail,
  assert,
} from "./test-utils";

const CONTRACT = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1";
const MNEMONIC = "test test test test test test test test test test test junk";

/** An authenticated SDK with an active session, recording each mnemonic fetch's forceAuth and mode */
async function sessionSdk() {
  const sdk = authenticatedSdk();
  await (sdk as any).sessionManager.startSession(MNEMONIC, "test-credential");
  const forceAuthCalls: boolean[] = [];
  const modeCalls: string[] = [];
  (sdk as any).getMnemonicFromSession = async (forceAuth: boolean = false, mode: string = "STANDARD") => {
    forceAuthCalls.push(forceAuth);
    modeCalls.push(mode);
    return MNEMONIC;
  };
  return { sdk, forceAuthCalls, modeCalls };
}

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
    const { sdk } = await sessionSdk();
    const authorization = await sdk.signAuthorization({
      contractAddress: CONTRACT,
      chainId: 11155111,
      nonce: 0n,
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
    const { sdk } = await sessionSdk();
    const authorization = await sdk.signAuthorization({ contractAddress: CONTRACT });

    assert(authorization.chainId === 1n, "Should default to mainnet (chainId 1)");
    assert(authorization.nonce === 0n, "Should default to nonce 0");
    passTest("Default parameters applied correctly");
  });

  await runTest("signAuthorization with different chain IDs and nonces", async () => {
    const { sdk } = await sessionSdk();
    const signer = await getOriginSpecificAddress(MNEMONIC, window.location.origin, "STANDARD", "MAIN");

    for (const [chainId, nonce] of [[1, 0n], [11155111, 1n], [8453, 7n], [42161, 2n ** 40n]] as const) {
      const authorization = await sdk.signAuthorization({
        contractAddress: CONTRACT,
        chainId,
        nonce,
      });

      assert(authorization.chainId === BigInt(chainId), `chainId should be ${chainId}`);
      assert(authorization.nonce === nonce, `nonce should be ${nonce}`);
      assert(
        recoverSigner(authorization) === signer.address,
        `Signature for chain ${chainId} should recover to the signer`
      );
      assert(
        verifyEIP7702Authorization(
          authorization.chainId,
          CONTRACT,
          authorization.nonce,
          authorization,
          signer.address
        ),
        "verifyEIP7702Authorization should accept the signature"
      );
      logDetail(`✓ chain ${chainId}, nonce ${nonce}`);
    }

    passTest("Each chain ID and nonce is part of the signed message");
  });

  await runTest("signAuthorization ignores a caller-supplied privateKey", async () => {
    const { sdk, forceAuthCalls } = await sessionSdk();
    const other = Wallet.createRandom();
    const authorization = await sdk.signAuthorization({
      contractAddress: CONTRACT,
      privateKey: other.privateKey,
    } as any);
    const standard = await getOriginSpecificAddress(MNEMONIC, window.location.origin, "STANDARD", "MAIN");

    assert(recoverSigner(authorization) === standard.address, "Should sign with the origin-derived key");
    assert(forceAuthCalls[0] === true, "Should still require a fresh assertion");
    passTest("No key bypasses the passkey prompt");
  });

  await runTest("signAuthorization signs with the origin-derived key, not the master key", async () => {
    const master = Wallet.fromPhrase(MNEMONIC).address;

    for (const mode of ["STANDARD", "STRICT", "YOLO"] as const) {
      const { sdk } = await sessionSdk();
      const authorization = await sdk.signAuthorization(
        { contractAddress: CONTRACT, chainId: 11155111 },
        { mode, tag: "MAIN" }
      );
      const expected = await getOriginSpecificAddress(
        MNEMONIC,
        window.location.origin,
        mode,
        "MAIN"
      );
      const signer = recoverSigner(authorization);

      assert(signer === expected.address, `${mode}: should sign with the origin-derived address`);
      assert(signer !== master, `${mode}: must never sign with m/44'/60'/0'/0/0`);
      logDetail(`${mode}: ${signer}`);
    }

    const { sdk } = await sessionSdk();
    const defaults = await sdk.signAuthorization({ contractAddress: CONTRACT });
    const standard = await getOriginSpecificAddress(MNEMONIC, window.location.origin, "STANDARD", "MAIN");
    assert(
      recoverSigner(defaults) === standard.address,
      "Should default to the STANDARD MAIN wallet"
    );

    passTest("Delegations are signed with the origin-derived key");
  });

  await runTest("signAuthorization requires a fresh assertion even with an active session", async () => {
    const { sdk, forceAuthCalls, modeCalls } = await sessionSdk();
    assert((sdk as any).sessionManager.getMnemonic() === MNEMONIC, "Session should be active");

    await sdk.signAuthorization({ contractAddress: CONTRACT });
    await sdk.signAuthorization({ contractAddress: CONTRACT }, { mode: "YOLO" });

    assert(forceAuthCalls.length === 2, "Each call should fetch the mnemonic");
    assert(
      forceAuthCalls.every((forceAuth) => forceAuth === true),
      "Each call should bypass the session cache"
    );
    assert(
      modeCalls[0] === "STANDARD" && modeCalls[1] === "YOLO",
      "Each call should authenticate under its own mode"
    );
    passTest("Every signature needs a fresh passkey assertion");
  });

  await runTest("signAuthorization refuses PRIMARY mode", async () => {
    const { sdk, forceAuthCalls } = await sessionSdk();

    let rejected: any;
    try {
      await sdk.signAuthorization({ contractAddress: CONTRACT }, { mode: "PRIMARY" });
    } catch (error) {
      rejected = error;
    }

    assert(rejected, "Should have thrown an error");
    const cause = rejected.originalError?.message ?? "";
    assert(cause.includes("PRIMARY mode"), `Should name PRIMARY mode, got: ${cause}`);
    assert(forceAuthCalls.length === 0, "Should refuse before prompting for a passkey");
    passTest("PRIMARY mode refused");
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
