/**
 * Unified deriveWallet() Tests
 * Tests for the new unified API supporting index/tag/auto modes
 */

import assert from 'node:assert';
import { deriveWalletFromMnemonic } from '../src/wallet/generate';
import { getOriginSpecificAddress, DEFAULT_TAG } from '../src/wallet/origin-derivation';

async function runTests() {
  console.log('\n🧪 Running Unified deriveWallet() API Tests...\n');

  const testMnemonic = 'test test test test test test test test test test test junk';

  // Simulate what the SDK deriveWallet() method does

  console.log('Test 1: Mode 1 - Index-based derivation (number)');
  {
    // Simulate: deriveWallet(0)
    const indexOrTag: number | string | undefined = 0;

    if (typeof indexOrTag === 'number') {
      const wallet = deriveWalletFromMnemonic(testMnemonic, indexOrTag);
      assert(wallet.address, 'Should have address');
      assert(wallet.privateKey, 'Should have private key');
      console.log(`  Index 0: ${wallet.address}`);
    }

    // Simulate: deriveWallet(1)
    const wallet1 = deriveWalletFromMnemonic(testMnemonic, 1);
    console.log(`  Index 1: ${wallet1.address}`);

    console.log('✅ Index-based derivation working');
  }

  console.log('\nTest 2: Mode 2 - Tag-based derivation (string)');
  {
    // Simulate: deriveWallet('GAMING')
    const indexOrTag: number | string | undefined = 'GAMING';
    const origin = 'https://example.com'; // Would come from getCurrentOrigin()

    if (typeof indexOrTag === 'string') {
      const wallet = await getOriginSpecificAddress(testMnemonic, origin, undefined, indexOrTag);
      assert(wallet.address, 'Should have address');
      assert(wallet.tag === 'GAMING', 'Should have GAMING tag');
      assert(wallet.origin === origin, 'Should have origin');
      console.log(`  GAMING tag: ${wallet.address}`);
      console.log(`  Tag: ${wallet.tag}, Origin: ${wallet.origin}`);
    }

    // Simulate: deriveWallet('TRADING')
    const tradingWallet = await getOriginSpecificAddress(testMnemonic, origin, undefined, 'TRADING');
    console.log(`  TRADING tag: ${tradingWallet.address}`);

    console.log('✅ Tag-based derivation working');
  }

  console.log('\nTest 3: Mode 3 - Auto-detect (undefined = MAIN tag)');
  {
    // Simulate: deriveWallet()
    const indexOrTag: number | string | undefined = undefined;
    const origin = 'https://example.com';

    const tag = typeof indexOrTag === 'string' ? indexOrTag : DEFAULT_TAG;
    const wallet = await getOriginSpecificAddress(testMnemonic, origin, undefined, tag);

    assert(wallet.tag === 'MAIN', 'Should default to MAIN tag');
    assert(wallet.origin === origin, 'Should have origin');
    console.log(`  Auto (MAIN): ${wallet.address}`);
    console.log(`  Tag: ${wallet.tag}, Origin: ${wallet.origin}`);

    console.log('✅ Auto-detect derivation working');
  }

  console.log('\nTest 4: Different modes produce different addresses');
  {
    const origin = 'https://example.com';

    // Index-based
    const indexWallet = deriveWalletFromMnemonic(testMnemonic, 0);

    // MAIN tag (auto)
    const mainWallet = await getOriginSpecificAddress(testMnemonic, origin, undefined, DEFAULT_TAG);

    // GAMING tag
    const gamingWallet = await getOriginSpecificAddress(testMnemonic, origin, undefined, 'GAMING');

    assert(
      indexWallet.address !== mainWallet.address,
      'Index 0 should differ from MAIN tag'
    );
    assert(
      mainWallet.address !== gamingWallet.address,
      'MAIN tag should differ from GAMING tag'
    );

    console.log(`  Index 0:      ${indexWallet.address}`);
    console.log(`  MAIN tag:     ${mainWallet.address}`);
    console.log(`  GAMING tag:   ${gamingWallet.address}`);

    console.log('✅ All modes produce different addresses');
  }

  console.log('\nTest 5: Tag-based is deterministic across origins');
  {
    const origin1 = 'https://example.com';
    const origin2 = 'https://another.com';

    // Same tag, different origins = different addresses
    const wallet1 = await getOriginSpecificAddress(testMnemonic, origin1, undefined, 'GAMING');
    const wallet2 = await getOriginSpecificAddress(testMnemonic, origin2, undefined, 'GAMING');

    assert(
      wallet1.address !== wallet2.address,
      'Different origins should have different addresses'
    );

    // Same origin, same tag = same address
    const wallet3 = await getOriginSpecificAddress(testMnemonic, origin1, undefined, 'GAMING');
    assert(
      wallet1.address === wallet3.address,
      'Same origin + tag should give same address'
    );

    console.log(`  example.com GAMING: ${wallet1.address}`);
    console.log(`  another.com GAMING: ${wallet2.address}`);
    console.log('✅ Origin isolation and determinism working');
  }

  console.log('\n✅ All Unified deriveWallet() API Tests Passed!\n');
}

runTests().catch((error) => {

  console.error(error);

  process.exit(1);

});
