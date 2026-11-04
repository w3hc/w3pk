/**
 * Origin-Specific Address Derivation Tests
 * Tests for tag-based origin address derivation
 */

import assert from "node:assert";
import {
  getOriginSpecificAddress,
  deriveOriginPath,
  normalizeOrigin,
  DEFAULT_TAG,
  DEFAULT_MODE,
} from "../src/wallet/origin-derivation";
import { deriveWalletFromMnemonic, deriveWalletFromPath } from "../src/wallet/generate";
import type { SecurityMode } from "../src/types";

async function runTests() {
  console.log("\n🧪 Running Origin-Specific Address Derivation Tests...\n");

  const testMnemonic =
    "test test test test test test test test test test test junk";

  // Test 1: Basic domain derivation with default STANDARD mode and MAIN tag
  console.log("Test 1: Default STANDARD mode + MAIN tag derivation");
  {
    const origin = "https://example.com";
    const wallet = await getOriginSpecificAddress(testMnemonic, origin);

    assert(wallet.address, "Should have an address");
    assert(wallet.privateKey === undefined, "STANDARD mode should NOT expose private key");
    assert(wallet.path.startsWith("m/13'/"), "Should have a SLIP-0013 path");
    assert(wallet.origin === origin, "Should preserve origin");
    assert(wallet.mode === DEFAULT_MODE, "Should use STANDARD mode by default");
    assert(wallet.tag === DEFAULT_TAG, "Should use MAIN tag by default");

    console.log(`  Origin: ${wallet.origin}`);
    console.log(`  Mode: ${wallet.mode}`);
    console.log(`  Tag: ${wallet.tag}`);
    console.log(`  Path: ${wallet.path}`);
    console.log(`  Address: ${wallet.address}`);
    console.log(`  Private Key: ${wallet.privateKey ? 'EXPOSED (ERROR!)' : 'HIDDEN (CORRECT)'}`);
    console.log("✅ Default STANDARD mode + MAIN tag working correctly (private key hidden)");
  }

  // Test 2: Different modes and tags generate different addresses
  console.log("\nTest 2: Different modes and tags for same origin");
  {
    const origin = "https://example.com";

    const standardMain = await getOriginSpecificAddress(testMnemonic, origin);
    const strictMain = await getOriginSpecificAddress(testMnemonic, origin, 'STRICT');
    const yoloMain = await getOriginSpecificAddress(testMnemonic, origin, 'YOLO');
    const standardGaming = await getOriginSpecificAddress(testMnemonic, origin, 'STANDARD', 'GAMING');

    assert(
      standardMain.address !== strictMain.address,
      "STANDARD and STRICT modes should have different addresses"
    );
    assert(
      standardMain.address !== yoloMain.address,
      "STANDARD and YOLO modes should have different addresses"
    );
    assert(
      standardMain.address !== standardGaming.address,
      "MAIN and GAMING tags should have different addresses"
    );

    // SECURITY: Check mode-based private key exposure
    assert(
      standardMain.privateKey === undefined,
      "STANDARD mode should NOT expose private key"
    );
    assert(
      strictMain.privateKey === undefined,
      "STRICT mode should NOT expose private key"
    );
    assert(
      yoloMain.privateKey !== undefined,
      "YOLO mode SHOULD expose private key"
    );
    assert(
      standardGaming.privateKey === undefined,
      "STANDARD mode should NOT expose private key (even with custom tag)"
    );

    console.log(`  STANDARD+MAIN: ${standardMain.address} (privateKey: hidden)`);
    console.log(`  STRICT+MAIN:   ${strictMain.address} (privateKey: hidden)`);
    console.log(`  YOLO+MAIN:     ${yoloMain.address} (privateKey: exposed)`);
    console.log(`  STANDARD+GAMING: ${standardGaming.address} (privateKey: hidden)`);
    console.log("✅ Different modes and tags generate different addresses with correct security");
  }

  // Test 3: Same origin, mode, and tag always produce same address
  console.log("\nTest 3: Deterministic derivation");
  {
    const origin = "https://example.com";
    const mode: SecurityMode = "YOLO";
    const tag = "GAMING";

    const wallet1 = await getOriginSpecificAddress(testMnemonic, origin, mode, tag);
    const wallet2 = await getOriginSpecificAddress(testMnemonic, origin, mode, tag);

    assert(
      wallet1.address === wallet2.address,
      "Same origin, mode, and tag should produce same address"
    );
    assert(
      wallet1.privateKey === wallet2.privateKey,
      "Same origin, mode, and tag should produce same private key"
    );
    assert(
      wallet1.path === wallet2.path,
      "Same origin, mode, and tag should produce same path"
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

    assert(
      wallet1.address !== wallet2.address,
      "Different domains should have different addresses"
    );
    assert(
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

    assert(
      normalized1 === normalized2,
      "Trailing slash should be removed"
    );
    assert(
      normalized1 === normalized3,
      "Should be case-insensitive"
    );
    assert(
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

    assert(
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
      undefined,
      "gaming"
    );
    const wallet2 = await getOriginSpecificAddress(
      testMnemonic,
      origin,
      undefined,
      "GAMING"
    );
    const wallet3 = await getOriginSpecificAddress(
      testMnemonic,
      origin,
      undefined,
      "GaMiNg"
    );

    assert(
      wallet1.address === wallet2.address,
      "Tag should be case-insensitive"
    );
    assert(
      wallet1.address === wallet3.address,
      "Tag should be case-insensitive"
    );
    assert(
      wallet1.tag === "GAMING" && wallet2.tag === "GAMING",
      "Tag should be normalized to uppercase"
    );

    console.log(`  Address: ${wallet1.address}`);
    console.log("✅ Tag case insensitivity working correctly");
  }

  // Test 7: Path test vectors
  console.log("\nTest 7: Path test vectors");
  {
    const originLevels = "m/13'/645184497'/1329031'/2055466046'/1660046646'";
    const vectors: Array<[string, SecurityMode, string, string, string]> = [
      ["https://example.com", "STANDARD", "MAIN", `${originLevels}/0'/360918275'`, "0x92dDB500f04b6DC254efCf224c0C5B872E5F2E20"],
      ["https://example.com", "STRICT", "MAIN", `${originLevels}/1'/360918275'`, "0x1036b53e09272A0143DD340358c61E290F8de123"],
      ["https://example.com", "YOLO", "GAMING", `${originLevels}/2'/152488895'`, "0xBc27c095f3d21E0F37C2deBb16D4eB2650311eF6"],
      ["https://victim.example", "STANDARD", "MAIN", "m/13'/1818679429'/515797001'/1452251921'/1598859960'/0'/360918275'", "0x906f2A9958f2cC279abEDc568e5D0ED48692C29f"],
    ];

    for (const [origin, mode, tag, path, address] of vectors) {
      assert.strictEqual(await deriveOriginPath(origin, mode, tag), path);
      const wallet = await getOriginSpecificAddress(testMnemonic, origin, mode, tag);
      assert.strictEqual(wallet.path, path);
      assert.strictEqual(wallet.address, address);
      console.log(`  ${origin} ${mode} ${tag}: ${path}`);
    }

    assert.strictEqual(
      await deriveOriginPath("https://example.com", "PRIMARY", "MAIN"),
      `${originLevels}/3'/360918275'`
    );
    await assert.rejects(deriveOriginPath("https://example.com", "BOGUS" as SecurityMode));

    console.log("✅ Path test vectors match");
  }

  // Test 8: Multiple tags on single domain
  console.log("\nTest 8: Multiple tags for single domain");
  {
    const origin = "https://game.xyz";
    const tags = ["MAIN", "GAMING", "SIMPLE", "TRADING", "SOCIAL"];
    const wallets = [];

    for (const tag of tags) {
      const wallet = await getOriginSpecificAddress(testMnemonic, origin, undefined, tag);
      wallets.push(wallet);
      console.log(`  ${tag.padEnd(8)}: ${wallet.address} (path: ${wallet.path})`);
    }

    // Verify all addresses are unique
    const addresses = new Set(wallets.map((w) => w.address));
    assert(
      addresses.size === tags.length,
      "All tags should produce unique addresses"
    );

    const paths = new Set(wallets.map((w) => w.path));
    assert(
      paths.size === tags.length,
      "All tags should produce unique paths"
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

    console.log("  Main addresses for popular apps:");
    for (const domain of domains) {
      const wallet = await getOriginSpecificAddress(testMnemonic, domain);
      const domainName = new URL(domain).hostname;
      console.log(`  ${domainName.padEnd(20)}: ${wallet.address}`);
    }

    console.log("\n  Gaming addresses for same apps:");
    for (const domain of domains) {
      const wallet = await getOriginSpecificAddress(
        testMnemonic,
        domain,
        undefined,
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

    assert(
      httpWallet.address !== httpsWallet.address,
      "HTTP and HTTPS should be different"
    );
    assert(
      httpWallet.origin === "http://example.com",
      "HTTP origin preserved"
    );
    assert(
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

    assert(
      standard.address !== nonStandard.address,
      "Non-standard port should be different"
    );
    assert(
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

    const tag1 = await getOriginSpecificAddress(testMnemonic, origin, undefined, "MY-TAG");
    const tag2 = await getOriginSpecificAddress(
      testMnemonic,
      origin,
      undefined,
      "MY_TAG_123"
    );
    const tag3 = await getOriginSpecificAddress(
      testMnemonic,
      origin,
      undefined,
      "EMOJI_🎮"
    );

    assert(tag1.address, "Hyphenated tag should work");
    assert(tag2.address, "Underscored tag should work");
    assert(tag3.address, "Emoji tag should work");
    assert(
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
      "YOLO",
      "GAMING"
    );

    assert(wallet.address.startsWith("0x"), "Should start with 0x");
    assert(wallet.address.length === 42, "Should be 42 characters");
    assert(
      wallet.privateKey !== undefined,
      "YOLO mode should expose private key"
    );
    assert(
      wallet.privateKey!.startsWith("0x"),
      "Private key should start with 0x"
    );
    assert(
      wallet.privateKey!.length === 66,
      "Private key should be 66 characters"
    );

    // Verify it's a valid hex address
    const isValidHex = /^0x[0-9a-fA-F]{40}$/.test(wallet.address);
    assert(isValidHex, "Should be valid hex address");

    console.log(`  Address: ${wallet.address}`);
    console.log("✅ Valid Ethereum addresses generated");
  }

  // Test 14: No tag on one origin reaches another origin's key
  console.log("\nTest 14: Cross-origin isolation");
  {
    const victim = await deriveOriginPath("https://victim.example", "STANDARD", "MAIN");
    const victimOrigin = victim.split("/").slice(0, 6).join("/");
    const registration = deriveWalletFromMnemonic(testMnemonic, 0);

    // The tag that collided with victim.example's index under the old scheme
    const tags = ["T4CE385B8", "MAIN", "GAMING", "", "0", "victim"];
    const modes: SecurityMode[] = ["PRIMARY", "STANDARD", "STRICT", "YOLO"];

    for (const mode of modes) {
      for (const tag of tags) {
        const path = await deriveOriginPath("https://evil.example", mode, tag);
        const levels = path.split("/");
        assert.strictEqual(levels.length, 8, "Path has 7 levels below the root");
        assert(levels.slice(1).every((level) => level.endsWith("'")), "Every level is hardened");
        assert.strictEqual(levels[1], "13'", "Purpose is 13'");
        assert.notStrictEqual(levels.slice(0, 6).join("/"), victimOrigin, "Origin levels differ");
        assert.notStrictEqual(path, victim);
      }
    }

    const evil = await getOriginSpecificAddress(testMnemonic, "https://evil.example", "YOLO", "T4CE385B8");
    const victimWallet = await getOriginSpecificAddress(testMnemonic, "https://victim.example");
    assert.notStrictEqual(evil.address, victimWallet.address);
    assert.notStrictEqual(evil.address, registration.address);
    assert.notStrictEqual(victimWallet.address, registration.address);

    for (const path of [undefined, null, "", "m", "44'/60'"]) {
      assert.throws(
        () => deriveWalletFromPath(testMnemonic, path as unknown as string),
        "A missing or malformed path never falls back to the registration key"
      );
    }

    console.log("✅ Origins are isolated");
  }

  console.log("\n✅ All Origin-Specific Address Derivation Tests Passed!\n");
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
