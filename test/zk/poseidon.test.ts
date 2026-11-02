/**
 * Poseidon outputs as field elements, checked against circomlibjs's own
 * test vectors
 */

import { ZKProofModule } from "../../src/zk";
import {
  buildMerkleTree,
  buildNFTHoldersMerkleTree,
  generateMerkleProof,
} from "../../src/zk/utils";

const POSEIDON_1_2 =
  "7853200120776062878684798364095072458815029376092732009249414926327459813530";

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    console.log(`  ✅ ${message}`);
    passed++;
  } else {
    console.log(`  ❌ ${message}`);
    failed++;
  }
}

async function runTests() {
  console.log("\n==================================================");
  console.log("🧩 Poseidon Field Element Test");
  console.log("==================================================\n");

  const zk = new ZKProofModule();

  console.log("Test 1: createCommitment()");
  assert(
    (await zk.createCommitment(1n, 2n)) === POSEIDON_1_2,
    "createCommitment(1, 2) is poseidon([1, 2]) as a decimal string"
  );
  console.log("");

  console.log("Test 2: computeMerkleRoot()");
  assert(
    (await zk.computeMerkleRoot("1", [0], ["2"])) === POSEIDON_1_2,
    "left leaf hashes as poseidon([leaf, sibling])"
  );
  assert(
    (await zk.computeMerkleRoot("2", [1], ["1"])) === POSEIDON_1_2,
    "right leaf hashes as poseidon([sibling, leaf])"
  );
  console.log("");

  console.log("Test 3: buildMerkleTree()");
  assert((await buildMerkleTree(["1", "2"])).root === POSEIDON_1_2, "root of [1, 2] is poseidon([1, 2])");
  const { root, tree } = await buildMerkleTree(["123", "456", "789", "101112"]);
  for (let i = 0; i < 4; i++) {
    const { pathIndices, pathElements } = generateMerkleProof(tree, i);
    assert(
      (await zk.computeMerkleRoot(tree[0][i], pathIndices, pathElements)) === root,
      `computeMerkleRoot() matches buildMerkleTree() for leaf ${i}`
    );
  }
  console.log("");

  console.log("Test 4: buildNFTHoldersMerkleTree()");
  const { holderLeaves } = await buildNFTHoldersMerkleTree(["0x1"], "0x2");
  assert(holderLeaves[0] === POSEIDON_1_2, "holder leaf is poseidon([holder, contract])");
  console.log("");

  console.log("==================================================");
  console.log(`${failed === 0 ? "✅" : "❌"} Poseidon Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
