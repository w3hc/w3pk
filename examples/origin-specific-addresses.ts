/**
 * Unified deriveWallet() API Example
 *
 * This example demonstrates the three modes of the unified deriveWallet() API:
 * 1. Classic index-based derivation
 * 2. Origin-specific with custom tags
 * 3. Auto-detect with MAIN tag
 */

import { deriveWalletFromMnemonic } from '../src/wallet/generate';
import { getOriginSpecificAddress, DEFAULT_TAG } from '../src/wallet/origin-derivation';

async function main() {
  const mnemonic = 'test test test test test test test test test test test junk';
  const origin = 'https://example.com'; // In browser, this comes from window.location.origin

  console.log('🔐 Unified deriveWallet() API Example\n');
  console.log(`Origin: ${origin}\n`);

  // Mode 1: Classic index-based derivation
  console.log('1️⃣  Mode 1: Classic index-based (number)');
  const wallet0 = deriveWalletFromMnemonic(mnemonic, 0);
  const wallet1 = deriveWalletFromMnemonic(mnemonic, 1);
  console.log(`   Index 0: ${wallet0.address}`);
  console.log(`   Index 1: ${wallet1.address}\n`);

  // Mode 2: Origin-specific with custom tag
  console.log('2️⃣  Mode 2: Origin-specific with custom tag (string)');
  const gamingWallet = await getOriginSpecificAddress(mnemonic, origin, 'GAMING');
  const tradingWallet = await getOriginSpecificAddress(mnemonic, origin, 'TRADING');
  const socialWallet = await getOriginSpecificAddress(mnemonic, origin, 'SOCIAL');

  console.log(`   GAMING:  ${gamingWallet.address}`);
  console.log(`   TRADING: ${tradingWallet.address}`);
  console.log(`   SOCIAL:  ${socialWallet.address}\n`);

  // Mode 3: Auto-detect with MAIN tag
  console.log('3️⃣  Mode 3: Auto-detect (no params = MAIN tag)');
  const mainWallet = await getOriginSpecificAddress(mnemonic, origin, DEFAULT_TAG);
  console.log(`   MAIN: ${mainWallet.address}`);
  console.log(`   Tag: ${mainWallet.tag}, Origin: ${mainWallet.origin}\n`);

  // Comparison
  console.log('📊 Address Comparison:');
  console.log(`   All three modes produce different addresses:`);
  console.log(`   Index 0:  ${wallet0.address}`);
  console.log(`   MAIN tag: ${mainWallet.address}`);
  console.log(`   GAMING:   ${gamingWallet.address}\n`);

  // Privacy across origins
  console.log('🔒 Privacy: Same tag, different origins');
  const origins = ['https://uniswap.org', 'https://opensea.io', 'https://aave.com'];

  for (const orig of origins) {
    const wallet = await getOriginSpecificAddress(mnemonic, orig, 'GAMING');
    const hostname = new URL(orig).hostname;
    console.log(`   ${hostname.padEnd(20)} → ${wallet.address}`);
  }

  console.log('\n✅ Benefits:');
  console.log('   • Simple API: deriveWallet() or deriveWallet("STANDARD", "TAG")');
  console.log('   • Privacy: Each origin gets unique addresses');
  console.log('   • Deterministic: Same origin + tag = same address');
  console.log('   • Flexible: Use tags for compartmentalization\n');
}

main().catch(console.error);
