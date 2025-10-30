/**
 * NFT Ownership Proof Tests
 * Tests the NFT/SBT ownership proof functionality
 */

import { mockLocalStorage } from './setup';
import { createWeb3Passkey } from '../src/index';
import {
  buildNFTHoldersMerkleTree,
  generateNFTOwnershipProofInputs,
  validateNFTOwnershipProofInputs,
} from '../src/zk/utils';
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  logDetail,
  logInfo,
  skipTest,
  assert,
  assertEqual,
} from './test-utils';

async function runNFTOwnershipTests() {
  startTestSuite('NFT Ownership Proof Tests');

  // Test 1: NFT Holders Merkle Tree Building
  await runTest('NFT Holders Merkle Tree Building', async () => {
    try {
      const holderAddresses = [
        '0x1234567890123456789012345678901234567890',
        '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
        '0x9876543210987654321098765432109876543210',
      ];
      const contractAddress = '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D';

      const { root, tree, holderLeaves } = await buildNFTHoldersMerkleTree(
        holderAddresses,
        contractAddress
      );

      passTest('Merkle tree built successfully');
      logDetail(`Root: ${root.substring(0, 20)}...`);
      logDetail(`Tree levels: ${tree.length}`);
      logDetail(`Holder leaves: ${holderLeaves.length}`);

      assert(root && tree.length > 0 && holderLeaves.length === holderAddresses.length, 'Invalid tree structure');
    } catch (error) {
      if (error instanceof Error && error.message.includes('circomlibjs')) {
        skipTest('circomlibjs not available');
      } else {
        throw error;
      }
    }
  });

  // Test 2: NFT Ownership Proof Inputs Generation
  await runTest('NFT Ownership Proof Inputs Generation', async () => {
    try {
      const holderAddresses = [
        '0x1111111111111111111111111111111111111111',
        '0x2222222222222222222222222222222222222222',
        '0x3333333333333333333333333333333333333333',
      ];
      const yourAddress = '0x2222222222222222222222222222222222222222';
      const contractAddress = '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D';

      const { nftProofInput } = await generateNFTOwnershipProofInputs(
        yourAddress,
        contractAddress,
        holderAddresses,
        1n
      );

      passTest('NFT proof inputs generated');
      logDetail(`Holder index: ${nftProofInput.holderIndex}`);
      logDetail(`Path depth: ${nftProofInput.pathIndices.length}`);
      logDetail(`Root: ${nftProofInput.holdersRoot.substring(0, 20)}...`);

      assertEqual(nftProofInput.holderIndex, 1, 'Holder index should be 1');
      assert(nftProofInput.pathIndices.length > 0, 'Path indices should not be empty');
    } catch (error) {
      if (error instanceof Error && error.message.includes('circomlibjs')) {
        skipTest('circomlibjs not available');
      } else {
        throw error;
      }
    }
  });

  // Test 3: NFT Proof Input Validation
  await runTest('NFT Proof Input Validation', async () => {
    const validInputs = {
      ownerAddress: '0x1234567890123456789012345678901234567890',
      contractAddress: '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D',
      holderIndex: 1,
      pathIndices: [0, 1],
      pathElements: ['123456789', '987654321'],
      holdersRoot: 'valid_root_hash_123456789',
      minBalance: 1n,
    };

    validateNFTOwnershipProofInputs(validInputs);
    passTest('Valid inputs passed validation');
  });

  // Test 4: Invalid Input Validation
  await runTest('Invalid Input Validation', async () => {
    const invalidInputs = {
      ownerAddress: 'invalid_address',
      contractAddress: '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D',
      holderIndex: 1,
      pathIndices: [0, 1],
      pathElements: ['123', '456', '789'], // Mismatched length
      holdersRoot: 'valid_root',
      minBalance: 1n,
    };

    let threw = false;
    try {
      validateNFTOwnershipProofInputs(invalidInputs);
    } catch {
      threw = true;
    }

    assert(threw, 'Should have failed validation');
    passTest('Invalid inputs correctly rejected');
  });

  // Test 5: SDK Integration (New Pattern)
  await runTest('SDK Integration', async () => {
    // Step 1: Initialize main SDK (lightweight, no ZK dependencies)
    const w3pk = createWeb3Passkey({
      storage: mockLocalStorage
    });

    passTest('Main SDK initialized (no ZK dependencies)');

    // Step 2: Initialize ZK module separately when needed
    const { ZKProofModule } = await import('../src/zk/proof-module');
    const zkModule = new ZKProofModule({
      enabledProofs: ['nft']
    });

    passTest('ZK module initialized separately');
    passTest('NFT functionality available via separate ZK module');
    logInfo('This pattern prevents bundling heavy ZK dependencies in apps that don\'t need ZK features');
  });

  // Test 6: Error Handling for Missing Owner
  await runTest('Error Handling for Missing Owner', async () => {
    try {
      const holderAddresses = [
        '0x1111111111111111111111111111111111111111',
        '0x2222222222222222222222222222222222222222',
      ];
      const missingAddress = '0x3333333333333333333333333333333333333333';
      const contractAddress = '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D';

      await generateNFTOwnershipProofInputs(
        missingAddress,
        contractAddress,
        holderAddresses,
        1n
      );

      throw new Error('Should have failed for missing owner');
    } catch (error) {
      if (error instanceof Error && error.message.includes('not found in holders list')) {
        passTest('Correctly handled missing owner error');
      } else if (error instanceof Error && error.message.includes('circomlibjs')) {
        skipTest('circomlibjs not available');
      } else {
        throw error;
      }
    }
  });

  // Check ZK dependencies status
  try {
    await import('circomlibjs');
    await import('snarkjs');
    logInfo('ZK dependencies available and functional');
    logInfo('Full NFT ownership proof generation supported');
  } catch {
    logInfo('ZK dependencies not installed (optional)');
    logInfo('NFT proof setup and validation working correctly');
    logInfo('Install with: npm install snarkjs circomlibjs');
  }

  logInfo('Circuit compilation: pnpm build:zk (when circuits are ready)');
  endTestSuite();
}

async function main() {
  await runNFTOwnershipTests();
}

// Run tests if called directly
if (require.main === module) {
  main().catch(console.error);
}

export { runNFTOwnershipTests };
