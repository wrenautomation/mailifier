#!/usr/bin/env node
/** One ESM file, dist/mailifier.mjs, for `node mailifier.mjs` on a box with no npm install. */
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(root, "dist/mailifier.mjs");
mkdirSync(resolve(root, "dist"), { recursive: true });
await build({
  entryPoints: [resolve(root, "src/main.ts")],
  outfile: out,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  logLevel: "info",
});
execFileSync("node", ["--check", out], { stdio: "inherit" });
console.log(`built ${out}`);
