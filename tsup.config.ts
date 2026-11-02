import { defineConfig, type Options } from "tsup";

const base = {
  format: ["cjs", "esm"],
  sourcemap: true,
  minify: true,
  splitting: false,
  platform: "browser",
  target: "es2020",
} satisfies Options;

const external = ["ethers", "snarkjs", "circomlibjs", "@semaphore-protocol/identity", "poseidon-lite"];

export default defineConfig([
  // Main entry point (core features: WebAuthn, wallets, stealth addresses)
  {
    ...base,
    entry: ["src/index.ts"],
    dts: true,
    clean: true,
    external,
    esbuildOptions(options) {
      options.mainFields = ["browser", "module", "main"];
      // Mark ZK module as external to prevent bundling circomlibjs
      options.external = [
        ...(options.external || []),
        "w3pk/zk"
      ];
    },
  },
  // ZK subpath exports (requires optional dependencies)
  {
    ...base,
    entry: {
      "zk/index": "src/zk/index.ts",
      "zk/utils": "src/zk/utils.ts",
    },
    dts: true,
    external,
  },
  // Web Worker for zkProve, resolved from dist/index.mjs
  {
    ...base,
    entry: {
      "zk/prove-worker": "src/zk/prove-worker.ts",
    },
    format: ["esm"],
    external: ["snarkjs"],
  },
  // Chainlist subpath export
  {
    ...base,
    entry: {
      "chainlist/index": "src/chainlist/index.ts",
    },
    dts: true,
  },
]);
