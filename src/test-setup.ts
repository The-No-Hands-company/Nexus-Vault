import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "nexus-vault-tests-"));

process.env.VAULT_DATA_DIR = dir;
// Deterministic test-only credentials — never used in production
process.env.VAULT_MASTER_SECRET = "test-master-secret-32-chars-min!!";
process.env.VAULT_ACCESS_TOKEN = "test-access-token-at-least-24-chars-long";
process.env.VAULT_ADMIN_TOKEN = "test-admin-token-at-least-24-chars-long!";
process.env.VAULT_ALLOW_WEAK_TOKENS = "true";
