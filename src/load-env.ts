/**
 * Load .env / .env.local before anything else evaluates.
 *
 * Vault requires VAULT_ACCESS_TOKEN, VAULT_ADMIN_TOKEN and VAULT_MASTER_SECRET.
 * Bun (the original runtime) reads both files automatically, with .env.local
 * taking precedence over .env. Node does not, so we replicate that behaviour
 * here using process.loadEnvFile (Node 20.12+).
 *
 * process.loadEnvFile does NOT overwrite already-set variables, so we load in
 * priority order: .env.local first (highest priority), then .env for defaults.
 * Shell / deployment environment variables always win over both files.
 *
 * Imported first in index.ts on purpose: ESM evaluates imports in source order,
 * and modules like auth.ts read these variables at import time, so loading them
 * from inside index.ts's body would already be too late.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

function tryLoadEnv(filePath: string): void {
  if (!fs.existsSync(filePath) || typeof process.loadEnvFile !== "function") return;
  try {
    process.loadEnvFile(filePath);
  } catch (err) {
    // A malformed file should not be a silent startup mystery, but also
    // must not stop a deployment that supplies its config another way.
    console.warn(`[vault] could not load ${filePath}:`, (err as Error).message);
  }
}

// .env.local overrides .env (matches Bun's resolution order)
tryLoadEnv(path.resolve(root, ".env.local"));
tryLoadEnv(path.resolve(root, ".env"));
