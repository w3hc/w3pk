/**
 * NFT Ownership Proof Tests
 * Holder tree helpers, input validation and the holder identity derivation.
 * The proofs themselves run in test/zk/circuits.test.ts. The SDK test loads
 * w3pk/zk, so run `pnpm build` first.
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { Identity } from '@semaphore-protocol/identity';
import { poseidon2, poseidon3 } from 'poseidon-lite';
import { mockLocalStorage } from './setup';
import { Web3Passkey } from '../src/index';
import { bip39Seed } from '../src/core/mlkem';
import { ZKProofModule } from '../src/zk/index';
import { deriveNFTHolderKey } from '../src/zk/semaphore';
import {
  NFT_TREE_DEPTH,
  buildNFTHoldersMerkleTree,
  generateNFTOwnershipProofInputs,
  validateNFTOwnershipProofInputs,
} from '../src/zk/utils';
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  assert,
  assertEqual,
} from './test-utils';

const CONTRACT = '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D';
const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ORIGIN = 'http://localhost';
const identities = [1, 2, 3].map((i) => new Identity(new Uint8Array(32).fill(i)));
const holders = identities.map((id, i) => ({ commitment: id.commitment, balance: BigInt(i + 1) }));

async function rejects(fn: () => Promise<unknown> | unknown, pattern: RegExp): Promise<boolean> {
  try {
    await fn();
  } catch (error) {
    const messages: string[] = [];
    for (let err: any = error; err; err = err.originalError) messages.push(String(err.message));
    return pattern.test(messages.join(' <- '));
  }
  return false;
}

async function runNFTOwnershipTests() {
  startTestSuite('NFT Ownership Proof Tests');

  await runTest('Holders tree matches the circuit', async () => {
    const { root, tree, holderLeaves } = await buildNFTHoldersMerkleTree(holders, CONTRACT);
    assertEqual(tree.length, NFT_TREE_DEPTH + 1, 'Tree should have 21 levels');
    assertEqual(
      holderLeaves[0],
      poseidon3([holders[0].commitment, BigInt(CONTRACT), 1n]).toString(),
      'Leaf should be Poseidon(commitment, contract, balance)'
    );
    const [l0, l1, l2] = holderLeaves.map(BigInt);
    let node = poseidon2([poseidon2([l0, l1]), poseidon2([l2, 0n])]);
    let zero = poseidon2([0n, 0n]);
    for (let d = 2; d < NFT_TREE_DEPTH; d++) {
      zero = poseidon2([zero, zero]);
      node = poseidon2([node, zero]);
    }
    assertEqual(root, node.toString(), 'Root should pad empty leaves with 0');
    passTest('Holders tree built with 20 levels and zero padding');
  });

  await runTest('Proof inputs give the holder a 20-level path', async () => {
    const { nftProofInput, holderLeaves } = await generateNFTOwnershipProofInputs(
      identities[1].commitment,
      CONTRACT,
      holders,
      7n
    );
    assertEqual(nftProofInput.pathIndices.length, NFT_TREE_DEPTH, 'Path should have 20 indices');
    assertEqual(nftProofInput.pathIndices.slice(0, 3).join(), '1,0,0', 'Index 1 is the right child');
    assertEqual(nftProofInput.pathElements[0], holderLeaves[0], 'First sibling is leaf 0');
    assertEqual(nftProofInput.balance, 2n, 'Balance comes from the holder list');
    assertEqual(nftProofInput.scope, 7n, 'Scope is passed through');

    const zk = new ZKProofModule();
    const root = await zk.computeMerkleRoot(
      holderLeaves[1],
      nftProofInput.pathIndices,
      nftProofInput.pathElements
    );
    assertEqual(root, nftProofInput.holdersRoot, 'Path should lead to the root');
    validateNFTOwnershipProofInputs(nftProofInput);
    passTest('Inputs are valid and lead to the root');
  });

  await runTest('Helpers refuse bad holder lists', async () => {
    assert(
      await rejects(
        () => generateNFTOwnershipProofInputs(identities[0].commitment, CONTRACT, holders.slice(1), 1n),
        /not found in holders list/
      ),
      'Missing holder should be refused'
    );
    assert(
      await rejects(
        () => generateNFTOwnershipProofInputs(identities[0].commitment, CONTRACT, holders, 1n, 2n),
        /below the minimum/
      ),
      'Balance below the minimum should be refused'
    );
    assert(
      await rejects(() => buildNFTHoldersMerkleTree([holders[0], holders[0]], CONTRACT), /twice/),
      'Duplicate commitment should be refused'
    );
    assert(
      await rejects(
        () => buildNFTHoldersMerkleTree([{ commitment: 1n, balance: 1n << 64n }], CONTRACT),
        /2\^64/
      ),
      'Balance of 2^64 should be refused'
    );
    passTest('Bad holder lists refused');
  });

  await runTest('Validation refuses bad inputs', async () => {
    const { nftProofInput } = await generateNFTOwnershipProofInputs(
      identities[0].commitment,
      CONTRACT,
      holders,
      1n
    );
    const cases: [string, object, RegExp][] = [
      ['bad contract', { contractAddress: 'invalid' }, /contract address/],
      ['short path', { pathIndices: [0, 1], pathElements: ['1', '2'] }, /20 levels/],
      ['index 2', { pathIndices: [2, ...nftProofInput.pathIndices.slice(1)] }, /0 or 1/],
      ['balance below minimum', { minBalance: 2n }, /below the minimum/],
      ['scope outside the field', { scope: -1n }, /field/],
      ['minimum balance of 0', { minBalance: 0n }, /at least 1/],
    ];
    for (const [name, change, pattern] of cases) {
      assert(
        await rejects(() => validateNFTOwnershipProofInputs({ ...nftProofInput, ...change }), pattern),
        `Validation should refuse ${name}`
      );
    }
    passTest('Bad inputs refused');
  });

  await runTest('Holder key derivation', async () => {
    const seed = await bip39Seed(MNEMONIC);
    const key = deriveNFTHolderKey(seed, ORIGIN, CONTRACT);
    assertEqual(key.length, 32, 'Key should be 32 bytes');
    assertEqual(
      Buffer.from(deriveNFTHolderKey(seed, ORIGIN, CONTRACT.toLowerCase())).toString('hex'),
      Buffer.from(key).toString('hex'),
      'Contract address case should not matter'
    );
    assert(
      Buffer.from(deriveNFTHolderKey(seed, ORIGIN, '0x' + '11'.repeat(20))).toString('hex') !==
        Buffer.from(key).toString('hex'),
      'Another contract should give another key'
    );
    assert(
      Buffer.from(deriveNFTHolderKey(seed, 'https://example.com', CONTRACT)).toString('hex') !==
        Buffer.from(key).toString('hex'),
      'Another origin should give another key'
    );
    passTest('One holder key per origin and contract');
  });

  await runTest('Proving without a holder key fails before proving', async () => {
    const zk = new ZKProofModule();
    const { nftProofInput } = await generateNFTOwnershipProofInputs(
      identities[0].commitment,
      CONTRACT,
      holders,
      1n
    );
    assert(
      await rejects(() => zk.proveNFTOwnership(nftProofInput), /holder identity unavailable/),
      'proveNFTOwnership() should need a holder key'
    );
    passTest('Missing holder key refused');
  });

  await runTest('w3pk.zk derives the holder identity from the session wallet', async () => {
    (globalThis as any).window = {
      location: { hostname: 'localhost', origin: ORIGIN },
      localStorage: mockLocalStorage,
    };
    const w3pk = new Web3Passkey();
    await (w3pk as any).sessionManager.startSession(MNEMONIC, 'cred-id');

    const seed = await bip39Seed(MNEMONIC);
    const expected = new Identity(deriveNFTHolderKey(seed, ORIGIN, CONTRACT)).commitment.toString();
    assertEqual(
      await w3pk.zk.getNFTHolderCommitment(CONTRACT),
      expected,
      'Commitment should come from the session wallet'
    );
    passTest('Holder commitment derived from the session, no prompt');
  });

  endTestSuite();
}

async function main() {
  await runNFTOwnershipTests();
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

export { runNFTOwnershipTests };
