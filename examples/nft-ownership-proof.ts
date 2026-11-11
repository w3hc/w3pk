/**
 * NFT Ownership Proof Example
 *
 * Proves that you hold at least `minBalance` tokens of a collection (NFTs or
 * SBTs) without revealing which holder you are.
 *
 * Flow:
 * 1. Holder: get your holder commitment for the collection and register it
 *    with the address that holds the tokens
 * 2. Registrar: check each registration and balance, then publish the
 *    holders list ({ commitment, balance }) and its root
 * 3. Holder: prove from the published list, under the verifier's scope
 * 4. Verifier: check the proof and keep its nullifier, one per holder and scope
 *
 * The holder identity derives from the wallet in the session: no extra
 * passkey prompt once logged in.
 *
 * ⚠️ REQUIREMENTS:
 * ```bash
 * pnpm add snarkjs circomlibjs poseidon-lite @semaphore-protocol/identity
 * ```
 * and the compiled nft circuit (`pnpm build:zk`).
 *
 * @see https://github.com/w3hc/w3pk/blob/main/docs/ZK.md
 */

import { createWeb3Passkey } from "w3pk";
import {
  generateNFTOwnershipProofInputs,
  type NFTHolder,
} from "w3pk/zk/utils";

const COLLECTION = "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D";
// One proof per holder for this scope, e.g. a poll or an event id
const SCOPE = 2026n;

async function nftOwnershipProofExample() {
  console.log("🎨 NFT Ownership Proof Example\n");

  const w3pk = createWeb3Passkey();
  await w3pk.login();

  await w3pk.zk.registerCircuit("nft", {
    wasmPath: "/circuits/nft.wasm",
    zkeyPath: "/circuits/nft.zkey",
    verificationKey: await fetch("/circuits/nft.vkey.json").then((r) => r.json()),
  });

  console.log("1. Registering your holder commitment...");
  const commitment = await w3pk.zk.getNFTHolderCommitment(COLLECTION);
  const registration = await w3pk.signMessage(`w3pk NFT holder ${COLLECTION} ${commitment}`);
  console.log(`   ✅ Commitment ${commitment.substring(0, 20)}... signed by ${registration.address}`);
  // Send { commitment, signature, address } to the registrar

  console.log("\n2. Registrar publishes the holders list...");
  // The registrar checks each signature and on-chain balance, then publishes
  // the list. Mocked here with your commitment among others.
  const holders: NFTHolder[] = [
    { commitment: 111n, balance: 3n },
    { commitment, balance: 2n },
    { commitment: 333n, balance: 1n },
  ];

  console.log("\n3. Proving you hold at least 2 tokens...");
  const { nftProofInput } = await generateNFTOwnershipProofInputs(
    commitment,
    COLLECTION,
    holders,
    SCOPE,
    2n
  );
  const proof = await w3pk.zk.proveNFTOwnership(nftProofInput);
  console.log("   ✅ Proof generated");

  console.log("\n4. Verifying...");
  const isValid = await w3pk.zk.verifyNFTOwnership(
    proof,
    COLLECTION,
    nftProofInput.holdersRoot,
    SCOPE,
    2n
  );
  const nullifier = proof.publicSignals[0];
  console.log(isValid ? "   ✅ Valid" : "   ❌ Invalid");
  console.log(`   🔁 Nullifier ${nullifier.substring(0, 20)}...: refuse it if seen in this scope`);

  console.log("\n📢 Public: holders root, contract, minimum balance, scope, nullifier");
  console.log("🔒 Hidden: which holder you are, your address, your exact balance");
}

if (require.main === module) {
  nftOwnershipProofExample().catch(console.error);
}

export { nftOwnershipProofExample };
