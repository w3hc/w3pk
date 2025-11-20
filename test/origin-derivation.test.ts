/**
 * Origin-Specific Address Derivation Tests
 * Tests for tag-based origin address derivation
 */

import {
  getOriginSpecificAddress,
  deriveIndexFromOriginAndTag,
  normalizeOrigin,
  DEFAULT_TAG,
} from "../src/wallet/origin-derivation";

async function runTests() {
  console.log("\n🧪 Running Origin-Specific Address Derivation Tests...\n");

  const testMnemonic =
    "test test test test test test test test test test test junk";

  // Test 1: Basic domain derivation with default MAIN tag
  console.log("Test 1: Default MAIN tag derivation");
  {
    const origin = "https://example.com";
    const wallet = await getOriginSpecificAddress(testMnemonic, origin);

    console.assert(wallet.address, "Should have an address");
    console.assert(wallet.privateKey, "Should have a private key");
    console.assert(wallet.index >= 0, "Should have a valid index");
    console.assert(wallet.origin === origin, "Should preserve origin");
    console.assert(wallet.tag === DEFAULT_TAG, "Should use MAIN tag by default");

    console.log(`  Origin: ${wallet.origin}`);
    console.log(`  Tag: ${wallet.tag}`);
    console.log(`  Index: ${wallet.index}`);
    console.log(`  Address: ${wallet.address}`);
    console.log("✅ Default MAIN tag working correctly");
  }

  // Test 2: Different tags generate different addresses
  console.log("\nTest 2: Different tags for same origin");
  {
    const origin = "https://example.com";

    const mainWallet = await getOriginSpecificAddress(testMnemonic, origin);
    const gamingWallet = await getOriginSpecificAddress(
      testMnemonic,
      origin,
      "GAMING"
    );
    const simpleWallet = await getOriginSpecificAddress(
      testMnemonic,
      origin,
      "SIMPLE"
    );

    console.assert(
      mainWallet.address !== gamingWallet.address,
      "MAIN and GAMING should have different addresses"
    );
    console.assert(
      mainWallet.address !== simpleWallet.address,
      "MAIN and SIMPLE should have different addresses"
    );
    console.assert(
      gamingWallet.address !== simpleWallet.address,
      "GAMING and SIMPLE should have different addresses"
    );

    console.assert(
      mainWallet.index !== gamingWallet.index,
      "Different tags should have different indices"
    );

    console.log(`  MAIN address:   ${mainWallet.address}`);
    console.log(`  GAMING address: ${gamingWallet.address}`);
    console.log(`  SIMPLE address: ${simpleWallet.address}`);
    console.log("✅ Different tags generate different addresses");
  }

  // Test 3: Same origin and tag always produce same address
  console.log("\nTest 3: Deterministic derivation");
  {
    const origin = "https://example.com";
    const tag = "GAMING";

    const wallet1 = await getOriginSpecificAddress(testMnemonic, origin, tag);
    const wallet2 = await getOriginSpecificAddress(testMnemonic, origin, tag);

    console.assert(
      wallet1.address === wallet2.address,
      "Same origin and tag should produce same address"
    );
    console.assert(
      wallet1.privateKey === wallet2.privateKey,
      "Same origin and tag should produce same private key"
    );
    console.assert(
      wallet1.index === wallet2.index,
      "Same origin and tag should produce same index"
    );

    console.log(`  Address: ${wallet1.address}`);
    console.log("✅ Deterministic derivation working correctly");
  }

  // Test 4: Different origins generate different addresses
  console.log("\nTest 4: Different origins");
  {
    const wallet1 = await getOriginSpecificAddress(
      testMnemonic,
      "https://example.com"
    );
    const wallet2 = await getOriginSpecificAddress(
      testMnemonic,
      "https://another.com"
    );
    const wallet3 = await getOriginSpecificAddress(
      testMnemonic,
      "https://app.example.com"
    );

    console.assert(
      wallet1.address !== wallet2.address,
      "Different domains should have different addresses"
    );
    console.assert(
      wallet1.address !== wallet3.address,
      "Different subdomains should have different addresses"
    );

    console.log(`  example.com:     ${wallet1.address}`);
    console.log(`  another.com:     ${wallet2.address}`);
    console.log(`  app.example.com: ${wallet3.address}`);
    console.log("✅ Different origins generate different addresses");
  }

  // Test 5: Origin normalization
  console.log("\nTest 5: Origin normalization");
  {
    // These should all normalize to the same origin
    const normalized1 = normalizeOrigin("https://example.com");
    const normalized2 = normalizeOrigin("https://example.com/");
    const normalized3 = normalizeOrigin("https://EXAMPLE.COM");
    const normalized4 = normalizeOrigin("https://example.com:443");

    console.assert(
      normalized1 === normalized2,
      "Trailing slash should be removed"
    );
    console.assert(
      normalized1 === normalized3,
      "Should be case-insensitive"
    );
    console.assert(
      normalized1 === normalized4,
      "Default HTTPS port should be removed"
    );

    console.log(`  Normalized: ${normalized1}`);

    // Verify they produce the same address
    const wallet1 = await getOriginSpecificAddress(
      testMnemonic,
      "https://example.com"
    );
    const wallet2 = await getOriginSpecificAddress(
      testMnemonic,
      "https://EXAMPLE.COM/"
    );

    console.assert(
      wallet1.address === wallet2.address,
      "Normalized origins should produce same address"
    );

    console.log("✅ Origin normalization working correctly");
  }

  // Test 6: Tag case insensitivity
  console.log("\nTest 6: Tag case insensitivity");
  {
    const origin = "https://example.com";

    const wallet1 = await getOriginSpecificAddress(
      testMnemonic,
      origin,
      "gaming"
    );
    const wallet2 = await getOriginSpecificAddress(
      testMnemonic,
      origin,
      "GAMING"
    );
    const wallet3 = await getOriginSpecificAddress(
      testMnemonic,
      origin,
      "GaMiNg"
    );

    console.assert(
      wallet1.address === wallet2.address,
      "Tag should be case-insensitive"
    );
    console.assert(
      wallet1.address === wallet3.address,
      "Tag should be case-insensitive"
    );
    console.assert(
      wallet1.tag === "GAMING" && wallet2.tag === "GAMING",
      "Tag should be normalized to uppercase"
    );

    console.log(`  Address: ${wallet1.address}`);
    console.log("✅ Tag case insensitivity working correctly");
  }

  // Test 7: Index derivation is deterministic
  console.log("\nTest 7: Index derivation consistency");
  {
    const origin = "https://example.com";

    const index1 = await deriveIndexFromOriginAndTag(origin, "MAIN");
    const index2 = await deriveIndexFromOriginAndTag(origin, "MAIN");
    const index3 = await deriveIndexFromOriginAndTag(origin, "GAMING");

    console.assert(index1 === index2, "Same inputs should produce same index");
    console.assert(
      index1 !== index3,
      "Different tags should produce different indices"
    );
    console.assert(index1 >= 0 && index1 < 0x7fffffff, "Index should be valid");
    console.assert(
      index3 >= 0 && index3 < 0x7fffffff,
      "Index should be valid"
    );

    console.log(`  MAIN index:   ${index1}`);
    console.log(`  GAMING index: ${index3}`);
    console.log("✅ Index derivation consistent");
  }

  // Test 8: Multiple tags on single domain
  console.log("\nTest 8: Multiple tags for single domain");
  {
    const origin = "https://game.xyz";
    const tags = ["MAIN", "GAMING", "SIMPLE", "TRADING", "SOCIAL"];
    const wallets = [];

    for (const tag of tags) {
      const wallet = await getOriginSpecificAddress(testMnemonic, origin, tag);
      wallets.push(wallet);
      console.log(`  ${tag.padEnd(8)}: ${wallet.address} (index: ${wallet.index})`);
    }

    // Verify all addresses are unique
    const addresses = new Set(wallets.map((w) => w.address));
    console.assert(
      addresses.size === tags.length,
      "All tags should produce unique addresses"
    );

    // Verify all indices are unique
    const indices = new Set(wallets.map((w) => w.index));
    console.assert(
      indices.size === tags.length,
      "All tags should produce unique indices"
    );

    console.log("✅ Multiple tags working correctly");
  }

  // Test 9: Real-world domain examples
  console.log("\nTest 9: Real-world domain examples");
  {
    const domains = [
      "https://uniswap.org",
      "https://app.aave.com",
      "https://opensea.io",
      "https://etherscan.io",
    ];

    console.log("  Main addresses for popular dApps:");
    for (const domain of domains) {
      const wallet = await getOriginSpecificAddress(testMnemonic, domain);
      const domainName = new URL(domain).hostname;
      console.log(`  ${domainName.padEnd(20)}: ${wallet.address}`);
    }

    console.log("\n  Gaming addresses for same dApps:");
    for (const domain of domains) {
      const wallet = await getOriginSpecificAddress(
        testMnemonic,
        domain,
        "GAMING"
      );
      const domainName = new URL(domain).hostname;
      console.log(`  ${domainName.padEnd(20)}: ${wallet.address}`);
    }

    console.log("✅ Real-world examples working correctly");
  }

  // Test 10: HTTP vs HTTPS are different
  console.log("\nTest 10: Protocol isolation");
  {
    const httpWallet = await getOriginSpecificAddress(
      testMnemonic,
      "http://example.com"
    );
    const httpsWallet = await getOriginSpecificAddress(
      testMnemonic,
      "https://example.com"
    );

    console.assert(
      httpWallet.address !== httpsWallet.address,
      "HTTP and HTTPS should be different"
    );
    console.assert(
      httpWallet.origin === "http://example.com",
      "HTTP origin preserved"
    );
    console.assert(
      httpsWallet.origin === "https://example.com",
      "HTTPS origin preserved"
    );

    console.log(`  HTTP:  ${httpWallet.address}`);
    console.log(`  HTTPS: ${httpsWallet.address}`);
    console.log("✅ Protocol isolation working correctly");
  }

  // Test 11: Non-standard ports
  console.log("\nTest 11: Non-standard ports");
  {
    const standard = await getOriginSpecificAddress(
      testMnemonic,
      "https://example.com"
    );
    const nonStandard = await getOriginSpecificAddress(
      testMnemonic,
      "https://example.com:8443"
    );

    console.assert(
      standard.address !== nonStandard.address,
      "Non-standard port should be different"
    );
    console.assert(
      nonStandard.origin === "https://example.com:8443",
      "Non-standard port preserved"
    );

    console.log(`  Standard:     ${standard.address}`);
    console.log(`  Port 8443:    ${nonStandard.address}`);
    console.log("✅ Non-standard ports working correctly");
  }

  // Test 12: Tag with special characters (should be normalized)
  console.log("\nTest 12: Special tag names");
  {
    const origin = "https://example.com";

    const tag1 = await getOriginSpecificAddress(testMnemonic, origin, "MY-TAG");
    const tag2 = await getOriginSpecificAddress(
      testMnemonic,
      origin,
      "MY_TAG_123"
    );
    const tag3 = await getOriginSpecificAddress(
      testMnemonic,
      origin,
      "EMOJI_🎮"
    );

    console.assert(tag1.address, "Hyphenated tag should work");
    console.assert(tag2.address, "Underscored tag should work");
    console.assert(tag3.address, "Emoji tag should work");
    console.assert(
      tag1.address !== tag2.address,
      "Different special tags should differ"
    );

    console.log(`  MY-TAG:     ${tag1.address}`);
    console.log(`  MY_TAG_123: ${tag2.address}`);
    console.log(`  EMOJI_🎮:   ${tag3.address}`);
    console.log("✅ Special tag names working correctly");
  }

  // Test 13: Verify addresses are valid Ethereum addresses
  console.log("\nTest 13: Valid Ethereum addresses");
  {
    const wallet = await getOriginSpecificAddress(
      testMnemonic,
      "https://example.com",
      "GAMING"
    );

    console.assert(wallet.address.startsWith("0x"), "Should start with 0x");
    console.assert(wallet.address.length === 42, "Should be 42 characters");
    console.assert(
      wallet.privateKey.startsWith("0x"),
      "Private key should start with 0x"
    );
    console.assert(
      wallet.privateKey.length === 66,
      "Private key should be 66 characters"
    );

    // Verify it's a valid hex address
    const isValidHex = /^0x[0-9a-fA-F]{40}$/.test(wallet.address);
    console.assert(isValidHex, "Should be valid hex address");

    console.log(`  Address: ${wallet.address}`);
    console.log("✅ Valid Ethereum addresses generated");
  }

  console.log("\n✅ All Origin-Specific Address Derivation Tests Passed!\n");
}

runTests().catch(console.error);
