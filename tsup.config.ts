import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  minify: true,
  splitting: false,
  external: [],
  noExternal: ["@simplewebauthn/browser", "ethers"],
});
