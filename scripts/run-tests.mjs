#!/usr/bin/env node
/**
 * Runs every test/**\/*.test.ts file with tsx, or only those under the
 * paths given as arguments, and exits non-zero if any of them failed.
 *
 *   node scripts/run-tests.mjs                     # all tests
 *   node scripts/run-tests.mjs test/zk             # a directory
 *   node scripts/run-tests.mjs test/siwe.test.ts   # specific files
 */

import { readdirSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(import.meta.url), "../..");
const isTestFile = (path) => path.endsWith(".test.ts");

function collect(target) {
  const abs = resolve(root, target);
  let stat;
  try {
    stat = statSync(abs);
  } catch {
    console.error(`No such file or directory: ${target}`);
    process.exit(1);
  }
  if (stat.isFile()) return [abs];
  return readdirSync(abs, { recursive: true })
    .filter(isTestFile)
    .map((path) => join(abs, path));
}

const targets = process.argv.slice(2);
const files = [...new Set((targets.length ? targets : ["test"]).flatMap(collect))]
  .filter(isTestFile)
  .map((path) => relative(root, path))
  .sort();

if (files.length === 0) {
  console.error(`No *.test.ts files found in: ${targets.join(" ") || "test"}`);
  process.exit(1);
}

const tsx = join(root, "node_modules", ".bin", process.platform === "win32" ? "tsx.cmd" : "tsx");
const failed = [];

for (const file of files) {
  console.log(`\n▶ ${file}`);
  const { status, signal, error } = spawnSync(tsx, [file], {
    cwd: root,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  if (error || status !== 0) {
    failed.push(`${file} (${error?.message ?? signal ?? `exit ${status}`})`);
  }
}

console.log(`\n${files.length - failed.length}/${files.length} test files passed`);
if (failed.length > 0) {
  console.error(`Failed:\n${failed.map((f) => `  ✗ ${f}`).join("\n")}`);
  process.exit(1);
}
