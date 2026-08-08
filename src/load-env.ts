/**
 * Load .env before anything else evaluates.
 *
 * Vault requires VAULT_ACCESS_TOKEN, VAULT_ADMIN_TOKEN and VAULT_MASTER_SECRET,
 * and ships a .env holding them — but nothing ever read that file. The app has
 * no dotenv dependency and never called loadEnvFile, so `npm run dev` died with
 * "VAULT_ACCESS_TOKEN and VAULT_ADMIN_TOKEN must be set in environment" on a
 * checkout that was, in fact, fully configured.
 *
 * It happened to work under bun, which reads .env implicitly — but bun cannot
 * load better-sqlite3 (ERR_DLOPEN_FAILED), so the runtime that reads the config
 * cannot open the database and the runtime that opens the database did not read
 * the config. This closes that gap on the Node side, which is the one
 * package.json actually targets via tsx.
 *
 * Imported first in index.ts on purpose: ESM evaluates imports in source order,
 * and modules like auth.ts read these variables at import time, so loading them
 * from inside index.ts's body would already be too late.
 *
 * Uses Node's built-in process.loadEnvFile (20.12+) rather than adding a
 * dependency. Real environment variables always win — loadEnvFile does not
 * overwrite what is already set — so container and systemd deployments that
 * inject config directly are unaffected.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.resolve(here, "..", ".env");

if (fs.existsSync(envPath) && typeof process.loadEnvFile === "function") {
  try {
    process.loadEnvFile(envPath);
  } catch (err) {
    // A malformed .env should not be a silent startup mystery, but it also
    // should not stop a deployment that supplies its config another way.
    console.warn(`[vault] could not load ${envPath}:`, (err as Error).message);
  }
}
