#!/usr/bin/env node

/**
 * Compiles the Circom circuits and sets up their Groth16 keys.
 *
 *   node scripts/compile-circuits.js [--ptau <file>]             dev keys, test only
 *   node scripts/compile-circuits.js --release [--ptau <file>]   checks ceremony keys
 *
 * Dev mode writes zkeys/<name>_test_only.zkey straight from `groth16 setup`,
 * with no phase-2 contribution: anyone can redo that setup, learn its toxic
 * waste and prove anything, so artifacts.json marks these keys `testOnly`.
 * Without the ptau it compiles the circuits and skips the keys.
 *
 * Release mode creates no key. It takes zkeys/<name>_final.zkey from a phase-2
 * ceremony, refuses it unless it has at least one contribution that is not a
 * beacon, and checks it against the circuit and the ptau as `snarkjs zkey
 * verify` does. Any failure exits non-zero.
 *
 * The default ptau is Hermez's powersOfTau28_hez_final_15.ptau, enough for
 * 2^15 constraints, in this directory.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CIRCUITS_DIR = path.join(__dirname, '../src/zk/circuits');
const OUTPUT_DIR = path.join(__dirname, '../src/zk/templates');
const WASM_DIR = path.join(OUTPUT_DIR, 'wasm');
const ZKEY_DIR = path.join(OUTPUT_DIR, 'zkeys');
const DEFAULT_PTAU = path.join(__dirname, 'powersOfTau28_hez_final_15.ptau');
const PTAU_URL = 'https://circom.info/powersOfTau28_hez_final_15.ptau';

const CIRCUITS = ['membership', 'threshold', 'range', 'ownership', 'nft'];

const BEACON = 1;

/**
 * The phase-2 contributions recorded in a Groth16 zkey (section 10), oldest
 * first, as `{ type, name }`; type 1 is a beacon.
 */
function phase2Contributions(zkeyPath) {
  const fd = fs.openSync(zkeyPath, 'r');
  const read = (position, length) => {
    const buf = Buffer.alloc(length);
    if (fs.readSync(fd, buf, 0, length, position) !== length) throw new Error(`${zkeyPath} is truncated`);
    return buf;
  };
  let header, groth16, mpc;
  try {
    const start = read(0, 12);
    if (start.toString('latin1', 0, 4) !== 'zkey') throw new Error(`${zkeyPath} is not a zkey file`);
    const sections = new Map();
    let pos = 12;
    for (let i = start.readUInt32LE(8); i > 0; i--) {
      const section = read(pos, 12);
      const size = Number(section.readBigUInt64LE(4));
      sections.set(section.readUInt32LE(0), { pos: pos + 12, size });
      pos += 12 + size;
    }
    const load = (type, length) => sections.has(type) && read(sections.get(type).pos, length ?? sections.get(type).size);
    header = load(1, 4);
    groth16 = load(2, 4);
    mpc = load(10);
  } finally {
    fs.closeSync(fd);
  }
  if (!header || header.readUInt32LE(0) !== 1 || !groth16 || !mpc) {
    throw new Error(`${zkeyPath} is not a Groth16 zkey`);
  }

  // deltaAfter, g1_s and g1_sx in G1, g2_spx in G2, then a 64-byte transcript
  const n8q = groth16.readUInt32LE(0);
  const typeOffset = 3 * 2 * n8q + 4 * n8q + 64;
  const contributions = [];
  let at = 68;
  for (let i = mpc.readUInt32LE(64); i > 0; i--) {
    const type = mpc.readUInt32LE(at + typeOffset);
    const paramsLength = mpc.readUInt32LE(at + typeOffset + 4);
    const params = mpc.subarray(at + typeOffset + 8, at + typeOffset + 8 + paramsLength);
    const name = params[0] === 1 ? params.subarray(2, 2 + params[1]).toString('utf8') : undefined;
    contributions.push({ type, name });
    at += typeOffset + 8 + paramsLength;
  }
  return contributions;
}

/**
 * Refuses a zkey with no phase-2 contribution besides beacons, or one that
 * `zkey verify` rejects for this circuit and ptau. Returns its contributions.
 */
async function checkReleaseZkey({ r1cs, ptau, zkey }) {
  const contributions = phase2Contributions(zkey);
  if (!contributions.some((c) => c.type !== BEACON)) {
    throw new Error(`${zkey} has no phase-2 contribution${contributions.length ? ' besides a beacon' : ''}`);
  }
  const snarkjs = require('snarkjs');
  if (!(await snarkjs.zKey.verifyFromR1cs(r1cs, ptau, zkey))) {
    throw new Error(`${zkey} does not match ${r1cs} and ${ptau}`);
  }
  return contributions;
}

function parseArgs(argv) {
  const release = argv.includes('--release');
  const at = argv.indexOf('--ptau');
  if (at !== -1 && !argv[at + 1]) throw new Error('--ptau needs a file');
  return { release, ptau: at === -1 ? DEFAULT_PTAU : path.resolve(argv[at + 1]) };
}

function findCircom() {
  process.env.PATH = `${path.join(os.homedir(), '.cargo', 'bin')}${path.delimiter}${process.env.PATH}`;
  try {
    execFileSync('circom', ['--version'], { stdio: 'ignore' });
  } catch {
    throw new Error('circom not found. Install circom 2.x: https://docs.circom.io/getting-started/installation/');
  }
}

function compileCircuit(name) {
  console.log(`Compiling ${name}.circom`);
  execFileSync(
    'circom',
    [path.join(CIRCUITS_DIR, `${name}.circom`), '--r1cs', '--wasm', '--sym', '-o', OUTPUT_DIR, '-l', 'node_modules'],
    { stdio: 'inherit', cwd: path.join(__dirname, '..') }
  );
  fs.copyFileSync(path.join(OUTPUT_DIR, `${name}_js`, `${name}.wasm`), path.join(WASM_DIR, `${name}.wasm`));
  return path.join(OUTPUT_DIR, `${name}.r1cs`);
}

async function setupKey(name, r1cs, ptau, release) {
  const snarkjs = require('snarkjs');
  let zkey;
  if (release) {
    zkey = path.join(ZKEY_DIR, `${name}_final.zkey`);
    if (!fs.existsSync(zkey)) throw new Error(`${zkey} not found: run the phase-2 ceremony first`);
    const contributions = await checkReleaseZkey({ r1cs, ptau, zkey });
    console.log(`  ${contributions.length} phase-2 contribution(s), zkey verified`);
  } else {
    zkey = path.join(ZKEY_DIR, `${name}_test_only.zkey`);
    await snarkjs.zKey.newZKey(r1cs, ptau, zkey);
    console.log(`  ${path.basename(zkey)}: no phase-2 contribution, test only`);
  }
  const verificationKey = await snarkjs.zKey.exportVerificationKey(zkey);
  fs.writeFileSync(path.join(ZKEY_DIR, `${name}_verification_key.json`), JSON.stringify(verificationKey, null, 2));
  const relative = (p) => `./${path.relative(path.join(__dirname, '..'), p)}`;
  return {
    wasmPath: relative(path.join(WASM_DIR, `${name}.wasm`)),
    zkeyPath: relative(zkey),
    verificationKey,
    ...(release ? {} : { testOnly: true }),
  };
}

async function main() {
  const { release, ptau } = parseArgs(process.argv.slice(2));
  console.log(`=== w3pk circuits (${release ? 'release' : 'dev'}) ===`);

  const missingPtau = !fs.existsSync(ptau) && `${ptau} not found. Download it from ${PTAU_URL} or pass --ptau <file>`;
  if (missingPtau && release) throw new Error(missingPtau);

  findCircom();
  for (const dir of [OUTPUT_DIR, WASM_DIR, ZKEY_DIR]) fs.mkdirSync(dir, { recursive: true });

  const r1cs = Object.fromEntries(CIRCUITS.map((name) => [name, compileCircuit(name)]));

  if (missingPtau) {
    for (const name of CIRCUITS) {
      for (const file of [`${name}_test_only.zkey`, `${name}_verification_key.json`]) {
        fs.rmSync(path.join(ZKEY_DIR, file), { force: true });
      }
    }
    fs.rmSync(path.join(OUTPUT_DIR, 'artifacts.json'), { force: true });
    console.log(`${missingPtau}; skipping the proving keys and removing the old test-only ones`);
    return;
  }

  const artifacts = {};
  for (const name of CIRCUITS) {
    console.log(`Setting up ${name}`);
    artifacts[name] = await setupKey(name, r1cs[name], ptau, release);
  }
  fs.writeFileSync(path.join(OUTPUT_DIR, 'artifacts.json'), JSON.stringify(artifacts, null, 2));
  console.log(`Wrote artifacts.json${release ? '' : ' with test-only keys: never ship them'}`);
}

if (require.main === module) {
  main().then(
    () => process.exit(0),
    (error) => {
      console.error(`✗ ${error.message}`);
      process.exit(1);
    }
  );
}

module.exports = { phase2Contributions, checkReleaseZkey };
