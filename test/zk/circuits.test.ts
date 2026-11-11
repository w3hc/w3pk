/**
 * membership.circom and nft.circom, compiled with circom.
 *
 * An honest 20-level path proves and verifies through proveMembership() and
 * proveNFTOwnership(). The forged leaf from audit H-2 sets pathIndices[0] to a
 * field element that is neither 0 nor 1, so that a leaf outside the tree
 * hashes to a real level-1 node. Each circuit is also compiled without its
 * bit constraint: the forged witness satisfies that copy, so the vector is a
 * real forgery, and fails the R1CS of the real circuit, so it is rejected by
 * the constraints and not only by the witness generator's asserts.
 *
 * The Groth16 setup uses a powers of tau with no contribution: test only.
 * Skipped when circom is missing, unless CI is set. CIRCOM overrides the
 * binary.
 */

import { spawnSync } from "child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { homedir, tmpdir } from "os";
import { join, resolve } from "path";
import { poseidon1, poseidon2 } from "poseidon-lite";
import { ZKProofModule } from "../../src/zk";

const ROOT = resolve(__dirname, "../..");
const CIRCUITS = join(ROOT, "src", "zk", "circuits");
const SNARKJS = join(ROOT, "node_modules", ".bin", "snarkjs");
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const LEVELS = 20;
const BIT_CONSTRAINT = /^\s*pathIndices\[i\] \* \(pathIndices\[i\] - 1\) === 0;\n/m;
const QUIET = { info() {}, warn() {}, debug() {}, error() {} };

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

function findCircom(): string | undefined {
  const candidates = process.env.CIRCOM
    ? [process.env.CIRCOM]
    : ["circom", join(homedir(), ".cargo", "bin", "circom")];
  return candidates.find((bin) => spawnSync(bin, ["--version"]).status === 0);
}

function run(bin: string, args: string[], cwd: string) {
  const { status, stdout, stderr } = spawnSync(bin, args, { cwd, encoding: "utf8" });
  if (status !== 0) throw new Error(`${bin} ${args.join(" ")} failed:\n${stdout}${stderr}`);
}

const mod = (a: bigint) => ((a % P) + P) % P;

function inv(a: bigint): bigint {
  let [result, base, e] = [1n, mod(a), P - 2n];
  while (e > 0n) {
    if (e & 1n) result = (result * base) % P;
    base = (base * base) % P;
    e >>= 1n;
  }
  return result;
}

function honestPath(leaf: bigint) {
  const pathElements = Array.from({ length: LEVELS }, (_, i) => BigInt(1000 + i));
  const pathIndices = Array.from({ length: LEVELS }, (_, i) => (i === 0 ? 0 : i % 2));
  let node = leaf;
  for (let i = 0; i < LEVELS; i++) {
    node = pathIndices[i] ? poseidon2([pathElements[i], node]) : poseidon2([node, pathElements[i]]);
  }
  return { pathElements, pathIndices, root: node };
}

/**
 * With selector s, the circuit hashes (cur + s(sib - cur), sib - s(sib - cur)).
 * Picking sib = a + b - cur and s = (a - cur) / (a + b - 2 cur) makes that
 * pair (a, b) for any cur, so `leaf` replaces the honest leaf `a` whose
 * sibling is `b`.
 */
function forgeFirstLevel(leaf: bigint, a: bigint, b: bigint, path: ReturnType<typeof honestPath>) {
  const sibling = mod(a + b - leaf);
  const selector = mod((a - leaf) * inv(a + b - 2n * leaf));
  return {
    pathElements: [sibling, ...path.pathElements.slice(1)].map(String),
    pathIndices: [selector, ...path.pathIndices.slice(1)].map(String),
  };
}

type Compiled = { r1cs: string; wasm: string };

function compile(dir: string, name: string, source: string, circom: string): Compiled {
  writeFileSync(join(dir, `${name}.circom`), source);
  run(circom, [`${name}.circom`, "--r1cs", "--wasm", "-l", join(ROOT, "node_modules"), "-o", "."], dir);
  return { r1cs: join(dir, `${name}.r1cs`), wasm: join(dir, `${name}_js`, `${name}.wasm`) };
}

function setup(dir: string, name: string, { r1cs, wasm }: Compiled, ptau: string) {
  const zkeyPath = join(dir, `${name}.zkey`);
  const vkeyPath = join(dir, `${name}.vkey.json`);
  run(SNARKJS, ["groth16", "setup", r1cs, ptau, zkeyPath], dir);
  run(SNARKJS, ["zkey", "export", "verificationkey", zkeyPath, vkeyPath], dir);
  return { wasmPath: wasm, zkeyPath, verificationKey: JSON.parse(readFileSync(vkeyPath, "utf8")) };
}

async function witnessError(snarkjs: any, input: object, circuit: Compiled, wtns: string) {
  try {
    await snarkjs.wtns.calculate(input, circuit.wasm, wtns);
  } catch (e) {
    return e as Error;
  }
  return undefined;
}

async function checkForgery(
  snarkjs: any,
  dir: string,
  name: string,
  real: Compiled,
  unconstrained: Compiled,
  input: object
) {
  const wtns = join(dir, `${name}-forged.wtns`);
  assert(
    /assert failed/i.test((await witnessError(snarkjs, input, real, wtns))?.message ?? ""),
    "the witness generator refuses the forged path"
  );
  assert(
    (await witnessError(snarkjs, input, unconstrained, wtns)) === undefined &&
      (await snarkjs.wtns.check(unconstrained.r1cs, wtns, QUIET)) === true,
    "without the bit constraint the forged witness is valid, so the vector is a real forgery"
  );
  const [a, b] = await Promise.all([snarkjs.r1cs.info(real.r1cs), snarkjs.r1cs.info(unconstrained.r1cs)]);
  assert(
    a.nVars === b.nVars && a.nConstraints === b.nConstraints + LEVELS,
    `the real circuit has the same wires and ${LEVELS} more constraints`
  );
  assert(
    (await snarkjs.wtns.check(real.r1cs, wtns, QUIET)) === false,
    "the real R1CS rejects the forged witness"
  );
}

async function runTests() {
  console.log("\n==================================================");
  console.log("🌳 Merkle Circuits Test");
  console.log("==================================================\n");

  const circom = findCircom();
  if (!circom) {
    if (process.env.CI) {
      console.log("  ❌ circom not found; CI must install it");
      process.exit(1);
    }
    console.log("  ⏭️  circom not found, skipping (set CIRCOM or add circom to PATH)");
    process.exit(0);
  }

  const snarkjs: any = await import("snarkjs");
  const dir = mkdtempSync(join(tmpdir(), "w3pk-circuits-"));
  try {
    const circuits: Record<string, { real: Compiled; unconstrained: Compiled }> = {};
    for (const name of ["membership", "nft"]) {
      const source = readFileSync(join(CIRCUITS, `${name}.circom`), "utf8");
      const stripped = source.replace(BIT_CONSTRAINT, "");
      if (stripped === source) throw new Error(`${name}.circom has no path index bit constraint`);
      circuits[name] = {
        real: compile(dir, name, source, circom),
        unconstrained: compile(dir, `${name}_unconstrained`, stripped, circom),
      };
    }

    run(SNARKJS, ["powersoftau", "new", "bn128", "14", "pot0.ptau"], dir);
    run(SNARKJS, ["powersoftau", "prepare", "phase2", "pot0.ptau", "pot.ptau"], dir);
    const ptau = join(dir, "pot.ptau");

    const zk = new ZKProofModule();
    zk.registerCircuit("membership", setup(dir, "membership", circuits.membership.real, ptau));
    zk.registerCircuit("nft", setup(dir, "nft", circuits.nft.real, ptau));

    console.log("Test 1: an honest membership proof verifies");
    const leaf = 111n;
    const path = honestPath(leaf);
    const root = path.root.toString();
    const membershipInput = {
      value: leaf.toString(),
      pathElements: path.pathElements.map(String),
      pathIndices: path.pathIndices,
      root,
    };
    const proof = await zk.proveMembership(membershipInput);
    assert(proof.publicSignals[1] === root, "the root is a public signal");
    assert(await zk.verifyMembership(proof, root), "verifyMembership() accepts the expected root");
    assert(!(await zk.verifyMembership(proof, "1")), "verifyMembership() refuses another root");
    console.log("");

    console.log("Test 2: a forged membership proof for a leaf outside the tree fails");
    const forged = forgeFirstLevel(999n, leaf, path.pathElements[0], path);
    const forgedInput = { value: "999", ...forged, root };
    let refused = false;
    try {
      await zk.proveMembership(forgedInput as any);
    } catch {
      refused = true;
    }
    assert(refused, "proveMembership() refuses the forged path");
    await checkForgery(snarkjs, dir, "membership", circuits.membership.real, circuits.membership.unconstrained, {
      leaf: "999",
      ...forged,
      root,
    });
    console.log("");

    console.log("Test 3: an honest NFT ownership proof verifies");
    const owner = "0x" + "11".repeat(20);
    const contract = "0x" + "22".repeat(20);
    const ownerHash = poseidon1([BigInt(owner)]);
    const contractHash = poseidon1([BigInt(contract)]);
    const nftLeaf = poseidon2([ownerHash, contractHash]);
    const nftPath = honestPath(nftLeaf);
    const nftRoot = nftPath.root.toString();
    const nftProof = await zk.proveNFTOwnership({
      ownerAddress: owner,
      contractAddress: contract,
      holderIndex: 0,
      pathElements: nftPath.pathElements.map(String),
      pathIndices: nftPath.pathIndices,
      holdersRoot: nftRoot,
      minBalance: 1n,
    });
    assert(
      nftProof.publicSignals[1] === nftRoot && nftProof.publicSignals[2] === contractHash.toString(),
      "the root and contract are public signals"
    );
    assert(await zk.verifyNFTOwnership(nftProof, contract, nftRoot, 1n), "verifyNFTOwnership() accepts it");
    assert(!(await zk.verifyNFTOwnership(nftProof, contract, "1", 1n)), "verifyNFTOwnership() refuses another root");
    console.log("");

    console.log("Test 4: a forged NFT ownership proof for a holder outside the tree fails");
    const attacker = "0x" + "33".repeat(20);
    const attackerHash = poseidon1([BigInt(attacker)]);
    const nftForged = forgeFirstLevel(poseidon2([attackerHash, contractHash]), nftLeaf, nftPath.pathElements[0], nftPath);
    refused = false;
    try {
      await zk.proveNFTOwnership({
        ownerAddress: attacker,
        contractAddress: contract,
        holderIndex: 0,
        holdersRoot: nftRoot,
        minBalance: 1n,
        ...(nftForged as any),
      });
    } catch {
      refused = true;
    }
    assert(refused, "proveNFTOwnership() refuses the forged path");
    await checkForgery(snarkjs, dir, "nft", circuits.nft.real, circuits.nft.unconstrained, {
      ownerAddress: attackerHash.toString(),
      ...nftForged,
      root: nftRoot,
      contractAddress: contractHash.toString(),
      minBalance: "1",
    });
    console.log("");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  console.log("==================================================");
  console.log(`${failed === 0 ? "✅" : "❌"} Merkle Circuits Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
