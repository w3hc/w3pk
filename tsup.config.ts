import { defineConfig } from "tsup";

export default defineConfig([
  // Main entry point (core features: WebAuthn, wallets, stealth addresses)
  {
    entry: ["src/index.ts"],
    format: ["cjs", "esm"],
    dts: true,
    clean: true,
    sourcemap: true,
    minify: true,
    splitting: false,
    external: ["ethers", "@simplewebauthn/browser", "snarkjs", "circomlibjs"],
    platform: "browser",
    target: "es2020",
    esbuildOptions(options) {
      options.mainFields = ["browser", "module", "main"];
    },
  },
  // ZK subpath exports (requires optional dependencies)
  {
    entry: {
      "zk/index": "src/zk/index.ts",
      "zk/utils": "src/zk/utils.ts",
    },
    format: ["cjs", "esm"],
    dts: true,
    sourcemap: true,
    minify: true,
    splitting: false,
    external: ["ethers", "snarkjs", "circomlibjs"],
    platform: "browser",
    target: "es2020",
  },
  // Chainlist subpath export
  {
    entry: {
      "chainlist/index": "src/chainlist/index.ts",
    },
    format: ["cjs", "esm"],
    dts: true,
    sourcemap: true,
    minify: true,
    splitting: false,
    platform: "browser",
    target: "es2020",
  },
]);
