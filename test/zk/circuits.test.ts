/**
 * The circuits, compiled with circom.
 *
 * An honest 20-level path proves and verifies through proveMembership() and
 * proveNFTOwnership(), the NFT one built with the holder tree helpers. A
 * non-holder, an inflated balance, a wrapped minimum balance and a second
 * secret for the same commitment are refused, and the NFT proof's public
 * signals don't reveal the holder. The forged leaf from audit H-2 sets pathIndices[0] to a
 * field element that is neither 0 nor 1, so that a leaf outside the tree
 * hashes to a real level-1 node. Each circuit is also compiled without its
 * bit constraint: the forged witness satisfies that copy, so the vector is a
 * real forgery, and fails the R1CS of the real circuit, so it is rejected by
 * the constraints and not only by the witness generator's asserts.
 *
 * The membership nullifier is bound to a scope, 0 by default.
 * threshold.circom and range.circom prove and verify honest values, and refuse
 * comparator inputs of 2^128 or more, which their 252-bit comparators on
 * unchecked inputs accepted: each is also compiled as it was, and the same
 * witness satisfies that copy. The release check of compile-circuits.js
 * refuses a zkey with no phase-2 contribution, or with only a beacon.
 *
 * The Groth16 setup uses a powers of tau with no contribution: test only.
 * Skipped when circom is missing, unless CI is set. CIRCOM overrides the
 * binary.
 */

import { spawnSync } from "child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { homedir, tmpdir } from "os";
import { join, resolve } from "path";
import { Identity } from "@semaphore-protocol/identity";
import { poseidon2, poseidon3 } from "poseidon-lite";
import { ZKProofModule } from "../../src/zk";
import { checkReleaseZkey } from "../../scripts/compile-circuits.js";
import { generateNFTOwnershipProofInputs } from "../../src/zk/utils";

const ROOT = resolve(__dirname, "../..");
const CIRCUITS = join(ROOT, "src", "zk", "circuits");
const SNARKJS = join(ROOT, "node_modules", ".bin", "snarkjs");
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const L = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const LEVELS = 20;
const BIT_CONSTRAINT = /^[ \t]*pathIndices\[i\] \* \(pathIndices\[i\] - 1\) === 0;\n/m;
const RANGE_CHECK = /^[ \t]*component \w+ = Num2Bits\(128\);\n[ \t]*\w+\.in <== \w+;\n/gm;
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
function forgeFirstLevel(
  leaf: bigint,
  a: bigint,
  b: bigint,
  path: { pathElements: (bigint | string)[]; pathIndices: number[] }
) {
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

/** The messages along the error's originalError chain, or undefined if fn resolved. */
async function rejection(fn: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await fn();
  } catch (e) {
    const messages: string[] = [];
    for (let err: any = e; err; err = err.originalError) messages.push(String(err.message ?? err));
    return messages.join(" <- ");
  }
  return undefined;
}

const refusedByCircuit = (message: string | undefined) => /assert failed/i.test(message ?? "");

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
    refusedByCircuit(await rejection(() => snarkjs.wtns.calculate(input, real.wasm, wtns))),
    "the witness generator refuses the forged path"
  );
  assert(
    (await rejection(() => snarkjs.wtns.calculate(input, unconstrained.wasm, wtns))) === undefined &&
      (await snarkjs.wtns.check(unconstrained.r1cs, wtns, QUIET)) === true,
    "without the bit constraint the forged witness is valid, so the vector is a real forgery"
  );
  const [a, b] = await Promise.all([snarkjs.r1cs.info(real.r1cs), snarkjs.r1cs.info(unconstrained.r1cs)]);
  assert(
    a.nVars === b.nVars && a.nConstraints > b.nConstraints,
    "the real circuit has the same wires and more constraints"
  );
  assert(
    (await snarkjs.wtns.check(real.r1cs, wtns, QUIET)) === false,
    "the real R1CS rejects the forged witness"
  );
}

async function runTests() {
  console.log("\n==================================================");
  console.log("🌳 Circuits Test");
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

    const comparators: Record<string, { real: Compiled; unchecked: Compiled }> = {};
    for (const name of ["threshold", "range"]) {
      const source = readFileSync(join(CIRCUITS, `${name}.circom`), "utf8");
      const unchecked = source.replace(RANGE_CHECK, "").replace(/EqThan\(128\)/g, "EqThan(252)");
      if (unchecked === source || unchecked.includes("Num2Bits")) {
        throw new Error(`${name}.circom doesn't range-check its comparator inputs as expected`);
      }
      comparators[name] = {
        real: compile(dir, name, source, circom),
        unchecked: compile(dir, `${name}_unchecked`, unchecked, circom),
      };
    }

    run(SNARKJS, ["powersoftau", "new", "bn128", "15", "pot0.ptau"], dir);
    run(SNARKJS, ["powersoftau", "prepare", "phase2", "pot0.ptau", "pot.ptau"], dir);
    const ptau = join(dir, "pot.ptau");

    let holderKey = new Uint8Array(32);
    const zk = new ZKProofModule({ nftHolderKey: async () => holderKey.slice() });
    zk.registerCircuit("membership", setup(dir, "membership", circuits.membership.real, ptau));
    zk.registerCircuit("nft", setup(dir, "nft", circuits.nft.real, ptau));
    const rangeArtifacts = setup(dir, "range", comparators.range.real, ptau);
    zk.registerCircuit("threshold", setup(dir, "threshold", comparators.threshold.real, ptau));
    zk.registerCircuit("range", rangeArtifacts);

    console.log("Test 1: an honest membership proof verifies, its nullifier bound to the scope");
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
    assert(
      proof.publicSignals[2] === "0" && proof.publicSignals[0] === poseidon2([0n, leaf]).toString(),
      "without a scope, the scope is 0 and the nullifier Poseidon(0, leaf)"
    );
    const scoped = await zk.proveMembership({ ...membershipInput, scope: 7n });
    assert(
      scoped.publicSignals[2] === "7" && scoped.publicSignals[0] === poseidon2([7n, leaf]).toString(),
      "the nullifier is Poseidon(scope, leaf), the scope a public signal"
    );
    assert(scoped.publicSignals[0] !== proof.publicSignals[0], "another scope gives another nullifier");
    assert(await zk.verifyMembership(scoped, root, 7n), "verifyMembership() accepts the expected scope");
    assert(
      /not in the BN254 scalar field/.test((await rejection(() => zk.proveMembership({ ...membershipInput, scope: P }))) ?? ""),
      "proveMembership() refuses a scope outside the field"
    );
    assert(
      !(await zk.verifyMembership(scoped, root)) && !(await zk.verifyMembership(scoped, root, 8n)),
      "verifyMembership() refuses another scope"
    );
    console.log("");

    console.log("Test 2: a forged membership proof for a leaf outside the tree fails");
    const forged = forgeFirstLevel(999n, leaf, path.pathElements[0], path);
    const forgedInput = { value: "999", ...forged, root };
    assert(
      refusedByCircuit(await rejection(() => zk.proveMembership(forgedInput as any))),
      "proveMembership() refuses the forged path"
    );
    await checkForgery(snarkjs, dir, "membership", circuits.membership.real, circuits.membership.unconstrained, {
      leaf: "999",
      ...forged,
      root,
      scope: "0",
    });
    console.log("");

    console.log("Test 3: an honest NFT ownership proof from the holder tree helpers verifies");
    const contract = "0x" + "22".repeat(20);
    const scope = 42n;
    const keys = [1, 2, 3].map((i) => new Uint8Array(32).fill(i));
    const identities = keys.map((key) => new Identity(key));
    const balances = [2n, 3n, 1n];
    const holders = identities.map((id, i) => ({ commitment: id.commitment, balance: balances[i] }));
    holderKey = keys[0];
    assert(
      (await zk.getNFTHolderCommitment(contract)) === identities[0].commitment.toString(),
      "getNFTHolderCommitment() is the Semaphore commitment of the holder key"
    );
    const { nftProofInput, holderLeaves } = await generateNFTOwnershipProofInputs(
      identities[0].commitment,
      contract,
      holders,
      scope,
      2n
    );
    const nftRoot = nftProofInput.holdersRoot;
    assert(
      holderLeaves[0] === poseidon3([identities[0].commitment, BigInt(contract), 2n]).toString(),
      "the leaf is Poseidon(commitment, contract, balance)"
    );
    assert(
      nftProofInput.pathElements.length === LEVELS &&
        (await zk.computeMerkleRoot(holderLeaves[0], nftProofInput.pathIndices, nftProofInput.pathElements)) === nftRoot,
      "the helper's 20-level path leads to its root"
    );
    const nftProof = await zk.proveNFTOwnership(nftProofInput);
    assert(
      nftProof.publicSignals.slice(1).join() === [nftRoot, BigInt(contract), 2n, scope].join(),
      "the root, contract, minimum balance and scope are public signals"
    );
    assert(await zk.verifyNFTOwnership(nftProof, contract, nftRoot, 2n, scope), "verifyNFTOwnership() accepts it");
    assert(!(await zk.verifyNFTOwnership(nftProof, contract, "1", 2n, scope)), "verifyNFTOwnership() refuses another root");
    assert(!(await zk.verifyNFTOwnership(nftProof, contract, nftRoot, 2n, 43n)), "verifyNFTOwnership() refuses another scope");
    assert(
      !(await zk.verifyNFTOwnership(nftProof, contract, nftRoot, 3n, scope)),
      "verifyNFTOwnership() refuses a higher minimum balance"
    );
    console.log("");

    console.log("Test 4: the public signals don't reveal the holder");
    const secrets = identities.map((id) => id.secretScalar);
    const nullifier = BigInt(nftProof.publicSignals[0]);
    assert(nullifier === poseidon2([scope, secrets[0]]), "the nullifier is Poseidon(scope, secret)");
    const known = [
      ...holders.map((h) => h.commitment),
      ...holderLeaves.map(BigInt),
      ...secrets,
      ...holders.flatMap((h) => [poseidon2([scope, h.commitment]), poseidon2([h.commitment, scope])]),
      ...holderLeaves.flatMap((leaf) => [poseidon2([scope, BigInt(leaf)]), poseidon2([BigInt(leaf), scope])]),
    ].map(String);
    assert(
      nftProof.publicSignals.every((signal) => !known.includes(signal)),
      "no public signal is a commitment, a leaf, a secret, or a hash of one with the scope"
    );
    holderKey = keys[1];
    const { nftProofInput: otherInput } = await generateNFTOwnershipProofInputs(
      identities[1].commitment,
      contract,
      holders,
      scope,
      2n
    );
    const otherProof = await zk.proveNFTOwnership(otherInput);
    assert(
      otherProof.publicSignals.slice(1).join() === nftProof.publicSignals.slice(1).join() &&
        otherProof.publicSignals[0] !== nftProof.publicSignals[0],
      "another holder's proof differs only in its nullifier"
    );
    holderKey = keys[0];
    const rescoped = await zk.proveNFTOwnership({ ...nftProofInput, scope: 43n });
    assert(rescoped.publicSignals[0] !== nftProof.publicSignals[0], "another scope gives another nullifier");
    console.log("");

    console.log("Test 5: dishonest NFT witnesses are refused by the circuit");
    const nftWasm = circuits.nft.real.wasm;
    const witness = {
      secret: secrets[0].toString(),
      balance: "2",
      pathElements: nftProofInput.pathElements,
      pathIndices: nftProofInput.pathIndices.map(String),
      root: nftRoot,
      contractAddress: BigInt(contract).toString(),
      minBalance: "2",
      scope: scope.toString(),
    };
    const wtns = join(dir, "nft-dishonest.wtns");
    const refused = async (input: object) =>
      refusedByCircuit(await rejection(() => snarkjs.wtns.calculate(input, nftWasm, wtns)));
    assert(
      (await rejection(() => snarkjs.wtns.calculate(witness, nftWasm, wtns))) === undefined,
      "the honest witness is accepted"
    );
    const outsider = new Identity(new Uint8Array(32).fill(9));
    holderKey = new Uint8Array(32).fill(9);
    assert(
      refusedByCircuit(await rejection(() => zk.proveNFTOwnership(nftProofInput))),
      "proveNFTOwnership() refuses a non-holder using a holder's path"
    );
    assert(await refused({ ...witness, secret: outsider.secretScalar.toString() }), "a non-holder's secret is refused");
    assert(await refused({ ...witness, balance: "3", minBalance: "3" }), "a balance above the leaf's is refused");
    assert(await refused({ ...witness, minBalance: "3" }), "a minimum balance above the balance is refused");
    assert(await refused({ ...witness, minBalance: (P - 1n).toString() }), "a minimum balance wrapping the field is refused");
    assert(
      await refused({ ...witness, secret: (secrets[0] + L).toString() }),
      "secret + l, the same commitment with another nullifier, is refused"
    );
    console.log("");

    console.log("Test 6: a forged NFT ownership proof for a holder outside the tree fails");
    const attackerSecret = outsider.secretScalar;
    const attackerLeaf = poseidon3([outsider.commitment, BigInt(contract), 2n]);
    const nftForged = forgeFirstLevel(attackerLeaf, BigInt(holderLeaves[0]), BigInt(holderLeaves[1]), nftProofInput);
    assert(
      (await rejection(() => zk.proveNFTOwnership({ ...nftProofInput, ...(nftForged as any) }))) !== undefined,
      "proveNFTOwnership() refuses the forged path"
    );
    await checkForgery(snarkjs, dir, "nft", circuits.nft.real, circuits.nft.unconstrained, {
      ...witness,
      secret: attackerSecret.toString(),
      ...nftForged,
    });
    console.log("");

    const MAX = 2n ** 128n - 1n;
    const wtnsPath = join(dir, "comparator.wtns");
    const witnessAccepted = async (circuit: Compiled, input: object) =>
      (await rejection(() => snarkjs.wtns.calculate(input, circuit.wasm, wtnsPath))) === undefined &&
      (await snarkjs.wtns.check(circuit.r1cs, wtnsPath, QUIET)) === true;
    const witnessRefused = async (circuit: Compiled, input: object) =>
      refusedByCircuit(await rejection(() => snarkjs.wtns.calculate(input, circuit.wasm, wtnsPath)));
    const committed = (value: bigint, blinding: bigint) => ({
      value: value.toString(),
      blinding: blinding.toString(),
      commitment: poseidon2([value, blinding]).toString(),
    });

    console.log("Test 7: threshold proofs verify, and inputs of 2^128 or more are refused");
    const balance = committed(5000n, 77n);
    const thresholdProof = await zk.proveThreshold({
      value: 5000n,
      blinding: 77n,
      threshold: 1000n,
      commitment: balance.commitment,
    });
    assert(
      thresholdProof.publicSignals.join() === ["1000", balance.commitment].join(),
      "the public signals are [threshold, commitment]"
    );
    assert(await zk.verifyThreshold(thresholdProof, balance.commitment, 1000n), "verifyThreshold() accepts it");
    assert(!(await zk.verifyThreshold(thresholdProof, balance.commitment, 999n)), "verifyThreshold() refuses another threshold");
    assert(
      await witnessAccepted(comparators.threshold.real, { ...committed(MAX, 1n), threshold: MAX.toString() }),
      "value = threshold = 2^128 - 1 is accepted"
    );
    const lyingThreshold = { ...committed(0n, 1n), threshold: (P - 2n ** 252n + 1n).toString() };
    assert(
      await witnessAccepted(comparators.threshold.unchecked, lyingThreshold),
      "the unchecked 252-bit circuit accepts 0 >= p - 2^252 + 1"
    );
    assert(await witnessRefused(comparators.threshold.real, lyingThreshold), "the real circuit refuses it");
    assert(
      await witnessRefused(comparators.threshold.real, { ...committed(MAX + 1n, 1n), threshold: "0" }),
      "a value of 2^128 is refused"
    );
    console.log("");

    console.log("Test 8: range proofs verify, and inputs of 2^128 or more are refused");
    const age = committed(25n, 88n);
    const rangeProof = await zk.proveRange({ value: 25n, blinding: 88n, min: 18n, max: 65n, commitment: age.commitment });
    assert(
      rangeProof.publicSignals.join() === ["18", "65", age.commitment].join(),
      "the public signals are [min, max, commitment]"
    );
    assert(await zk.verifyRange(rangeProof, age.commitment, 18n, 65n), "verifyRange() accepts it");
    assert(!(await zk.verifyRange(rangeProof, age.commitment, 18n, 64n)), "verifyRange() refuses another max");
    assert(
      await witnessAccepted(comparators.range.real, { ...committed(MAX, 1n), min: MAX.toString(), max: MAX.toString() }),
      "value = min = max = 2^128 - 1 is accepted"
    );
    const lyingRange = { ...committed(P - 1n, 1n), min: (P - 2n ** 252n).toString(), max: "65" };
    assert(
      await witnessAccepted(comparators.range.unchecked, lyingRange),
      "the unchecked 252-bit circuit accepts p - 2^252 <= p - 1 <= 65"
    );
    assert(await witnessRefused(comparators.range.real, lyingRange), "the real circuit refuses it");
    assert(
      await witnessRefused(comparators.range.real, { ...committed(25n, 1n), min: "18", max: (MAX + 1n).toString() }),
      "a max of 2^128 is refused"
    );
    console.log("");

    console.log("Test 9: the release check refuses a zkey with no phase-2 contribution");
    const release = (zkey: string) => ({ r1cs: comparators.range.real.r1cs, ptau, zkey });
    const contributed = join(dir, "range_0001.zkey");
    const beaconOnly = join(dir, "range_beacon.zkey");
    const BEACON_HASH = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    run(SNARKJS, ["zkey", "contribute", rangeArtifacts.zkeyPath, contributed, "--name=test", "-e=test entropy"], dir);
    run(SNARKJS, ["zkey", "beacon", rangeArtifacts.zkeyPath, beaconOnly, BEACON_HASH, "10", "-n=beacon"], dir);
    assert(
      /no phase-2 contribution$/.test((await rejection(() => checkReleaseZkey(release(rangeArtifacts.zkeyPath)))) ?? ""),
      "a zkey straight from groth16 setup is refused"
    );
    assert(
      /no phase-2 contribution besides a beacon$/.test((await rejection(() => checkReleaseZkey(release(beaconOnly)))) ?? ""),
      "a zkey with only a beacon is refused"
    );
    assert(
      (await checkReleaseZkey(release(contributed))).map((c: { name?: string }) => c.name).join() === "test",
      "a zkey with a contribution is accepted"
    );
    assert(
      (await rejection(() => checkReleaseZkey({ ...release(contributed), r1cs: comparators.threshold.real.r1cs }))) !==
        undefined,
      "a contributed zkey for another circuit is refused"
    );
    console.log("");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  console.log("==================================================");
  console.log(`${failed === 0 ? "✅" : "❌"} Circuits Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
