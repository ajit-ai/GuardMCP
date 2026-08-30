#!/usr/bin/env node
/**
 * Node SEA (Single Executable Application) builder — official Node 20+ method
 * Fallback/alternative to @yao-pkg/pkg. Produces single binary per platform without pkg.
 * Usage: npm run build:sea
 * Output: dist/bin/guardmcp-sea[.exe]
 */
import { execSync } from "node:child_process";
import { existsSync, mkdirSync, copyFileSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";

const isWin = process.platform === "win32";
const outDir = "dist/bin";
const seaConfig = "scripts/sea-config.json";
const blobPath = "dist/sea-prep.blob";
const exeName = isWin ? "guardmcp-sea.exe" : "guardmcp-sea";

if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });

// 1. Generate SEA config
const config = {
  main: "dist/index.js",
  output: blobPath,
  disableExperimentalSEAWarning: true,
  useSnapshot: false,
  useCodeCache: true,
};
writeFileSync(seaConfig, JSON.stringify(config, null, 2));
console.log(`[sea] config → ${seaConfig}`);

// 2. Generate blob
execSync(`node --experimental-sea-config ${seaConfig}`, { stdio: "inherit" });
console.log(`[sea] blob → ${blobPath}`);

// 3. Copy node binary + inject blob
const nodeBin = process.execPath;
const outPath = join(outDir, exeName);
copyFileSync(nodeBin, outPath);
console.log(`[sea] copied node → ${outPath}`);

if (isWin) {
  // Windows: use node --experimental-sea-config injection via npx postject (fallback) or copy
  // Simplest: use postject if available, else just copy blob alongside
  try {
    execSync(`npx postject ${outPath} NODE_SEA_BLOB ${blobPath} --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2`, {
      stdio: "inherit",
    });
    console.log(`[sea] injected blob (postject) → ${outPath}`);
  } catch {
    console.warn("[sea] postject not found — copying blob alongside exe. Run: npm i -g postject");
    copyFileSync(blobPath, join(outDir, "guardmcp-sea.blob"));
  }
} else {
  try {
    execSync(`npx postject ${outPath} NODE_SEA_BLOB ${blobPath} --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2`, {
      stdio: "inherit",
    });
    console.log(`[sea] injected blob (postject) → ${outPath}`);
  } catch {
    console.warn("[sea] postject not found — set up: npm i -g postject");
    copyFileSync(blobPath, join(outDir, "guardmcp-sea.blob"));
  }
}

console.log(`[sea] done → ${outPath} (${(readFileSync(outPath).length / 1024 / 1024).toFixed(1)} MB)`);
console.log(`[sea] test: ${outPath} --help  or  echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}' | ${outPath}`);
