import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  minify: true,
  splitting: false,
  // Keep these as external - don't bundle them
  external: ["ethers", "@simplewebauthn/browser", "snarkjs", "circomlibjs"],
  // Specify that this is for browser environment
  platform: "browser",
  target: "es2020",
  // Don't bundle Node.js built-ins
  noExternal: [],
  esbuildOptions(options) {
    options.mainFields = ["browser", "module", "main"];
  },
});
