import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { createHmac } from 'crypto';

export const DB_DIR = process.env.VAULT_DATA_DIR ?? './data';
export const DB_PATH = path.join(DB_DIR, 'vault.db');

if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

export const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

type Migration = {
  id: string;
  sql: string;
};

const MIGRATIONS: Migration[] = [
  {
    id: '001_initial_schema',
    sql: `
CREATE TABLE IF NOT EXISTS vault_collections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  parent_id INTEGER,
  icon TEXT NOT NULL DEFAULT '',
  color TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  is_active INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY(parent_id) REFERENCES vault_collections(id)
);

CREATE TABLE IF NOT EXISTS vault_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  category TEXT NOT NULL,
  name TEXT NOT NULL UNIQUE,
  value_enc TEXT NOT NULL,
  tags TEXT NOT NULL DEFAULT '[]',
  collection_id INTEGER,
  project TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT,
  last_accessed TEXT,
  access_count INTEGER NOT NULL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY(collection_id) REFERENCES vault_collections(id)
);

CREATE TABLE IF NOT EXISTS vault_import_exports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  format TEXT NOT NULL,
  filename TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_name TEXT NOT NULL,
  action TEXT NOT NULL,
  ip TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  meta TEXT NOT NULL,
  timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);
`,
  },
  {
    id: '002_indexes',
    sql: `
CREATE INDEX IF NOT EXISTS idx_vault_entries_category ON vault_entries(category);
CREATE INDEX IF NOT EXISTS idx_vault_entries_collection ON vault_entries(collection_id);
CREATE INDEX IF NOT EXISTS idx_vault_entries_active ON vault_entries(is_active);
CREATE INDEX IF NOT EXISTS idx_audit_log_entry ON audit_log(entry_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
`,
  },
  {
    id: '003_audit_chain',
    sql: `ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';`,
  },
  {
    id: '004_audit_verification_history',
    sql: `
CREATE TABLE IF NOT EXISTS audit_verification_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  ok INTEGER NOT NULL,
  broken_at INTEGER,
  expected_hash TEXT,
  got_hash TEXT,
  total_entries INTEGER NOT NULL,
  head_id INTEGER,
  head_hash TEXT,
  genesis_ok INTEGER NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  alert_sent INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_verification_runs_created_at
  ON audit_verification_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_verification_runs_ok
  ON audit_verification_runs(ok);
`,
  },
];

export function runMigrations(): string[] {
  db.exec(`
CREATE TABLE IF NOT EXISTS schema_migrations (
  id TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

  const applied = db.prepare<[], { id: string }>(`SELECT id FROM schema_migrations`).all();
  const appliedSet = new Set(applied.map((row) => row.id));
  const markApplied = db.prepare<[string], void>(`INSERT INTO schema_migrations (id) VALUES (?)`);

  const executed: string[] = [];
  for (const migration of MIGRATIONS) {
    if (appliedSet.has(migration.id)) continue;
    db.transaction(() => {
      db.exec(migration.sql);
      markApplied.run(migration.id);
    })();
    executed.push(migration.id);
  }

  return executed;
}

export function getAppliedMigrations(): string[] {
  db.exec(`
CREATE TABLE IF NOT EXISTS schema_migrations (
  id TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);
  return db.prepare<[], { id: string }>(`SELECT id FROM schema_migrations ORDER BY id`).all().map((row) => row.id);
}

runMigrations();

export const VAULT_ENTRY_TYPES = ['api-key', 'password', 'note', 'recovery-code', 'token', 'card', 'secret'] as const;
export type VaultEntryType = (typeof VAULT_ENTRY_TYPES)[number];

export const VAULT_CATEGORIES = ['api-keys', 'credentials', 'notes', 'recovery-codes', 'tokens', 'cards', 'general'] as const;
export type VaultCategory = (typeof VAULT_CATEGORIES)[number];

export const VAULT_EXPORT_FORMATS = ['json'] as const;

export interface VaultCollection {
  id: number;
  name: string;
  description: string;
  parent_id: number | null;
  icon: string;
  color: string;
  created_at: string;
  updated_at: string;
  is_active: number;
}

export interface VaultEntry {
  id: number;
  type: VaultEntryType;
  category: VaultCategory;
  name: string;
  value_enc: string;
  tags: string;
  collection_id: number | null;
  project: string;
  notes: string;
  metadata: string;
  created_at: string;
  updated_at: string;
  expires_at: string | null;
  last_accessed: string | null;
  access_count: number;
  is_active: number;
}

export interface VaultImportExportRecord {
  id: number;
  kind: 'import' | 'export';
  format: string;
  filename: string;
  created_at: string;
  metadata: string;
}

export interface AuditEntry {
  id: number;
  entry_name: string;
  action: string;
  ip: string;
  user_agent: string;
  timestamp: string;
  meta: string;
  prev_hash: string;
}

export interface AuditVerificationRun {
  id: number;
  source: string;
  ok: number;
  broken_at: number | null;
  expected_hash: string | null;
  got_hash: string | null;
  total_entries: number;
  head_id: number | null;
  head_hash: string | null;
  genesis_ok: number;
  details: string;
  alert_sent: number;
  created_at: string;
}

export interface VaultExportCollection {
  name: string;
  description: string;
  parentName: string | null;
  icon: string;
  color: string;
}

export interface VaultExportEntry {
  name: string;
  type: VaultEntryType;
  category: VaultCategory;
  value: string;
  tags: readonly string[];
  collection: string | null;
  project: string;
  notes: string;
  metadata: Record<string, unknown>;
  expiresAt: string | null;
}

export interface VaultExportDocument {
  version: 1;
  generatedAt: string;
  collections: readonly VaultExportCollection[];
  entries: readonly VaultExportEntry[];
}

export interface VaultImportDocument {
  version: 1;
  collections?: readonly VaultExportCollection[];
  entries?: readonly VaultExportEntry[];
  replaceExisting?: boolean;
}

export function isVaultEntryType(value: unknown): value is VaultEntryType {
  return typeof value === 'string' && (VAULT_ENTRY_TYPES as readonly string[]).includes(value);
}

export function isVaultCategory(value: unknown): value is VaultCategory {
  return typeof value === 'string' && (VAULT_CATEGORIES as readonly string[]).includes(value);
}

export function inferVaultCategory(type: VaultEntryType): VaultCategory {
  switch (type) {
    case 'api-key':
      return 'api-keys';
    case 'password':
      return 'credentials';
    case 'note':
      return 'notes';
    case 'recovery-code':
      return 'recovery-codes';
    case 'token':
      return 'tokens';
    case 'card':
      return 'cards';
    default:
      return 'general';
  }
}

export function normalizeVaultEntryType(value: unknown): VaultEntryType {
  if (isVaultEntryType(value)) return value;
  return 'secret';
}

export function normalizeVaultCategory(value: unknown, fallbackType: VaultEntryType): VaultCategory {
  if (isVaultCategory(value)) return value;
  return inferVaultCategory(fallbackType);
}

export function serializeTags(value: unknown): string {
  if (Array.isArray(value)) {
    return JSON.stringify(value.filter((item): item is string => typeof item === 'string').map((item) => item.trim()).filter(Boolean));
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return '[]';
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        return JSON.stringify(parsed.filter((item): item is string => typeof item === 'string').map((item) => item.trim()).filter(Boolean));
      }
    } catch {
      // fall through
    }
    return JSON.stringify(trimmed.split(',').map((item) => item.trim()).filter(Boolean));
  }
  return '[]';
}

export function parseTags(value: string): string[] {
  try {
    const parsed = JSON.parse(value || '[]');
    if (Array.isArray(parsed)) {
      return parsed.filter((item): item is string => typeof item === 'string');
    }
  } catch {
    // fall through
  }
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : [];
}

export function serializeMetadata(value: unknown): string {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return '{}';
    try {
      JSON.parse(trimmed);
      return trimmed;
    } catch {
      return JSON.stringify({ value: trimmed });
    }
  }
  if (value && typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch {
      return '{}';
    }
  }
  return '{}';
}

export function parseMetadata(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

export function parseDateLike(value: string | null): string | null {
  return value ?? null;
}

export const collectionQueries = {
  getAll: db.prepare<[], VaultCollection>(`SELECT * FROM vault_collections WHERE is_active = 1 ORDER BY name`),
  getById: db.prepare<[number], VaultCollection>(`SELECT * FROM vault_collections WHERE id = ? AND is_active = 1`),
  getByName: db.prepare<[string], VaultCollection>(`SELECT * FROM vault_collections WHERE name = ? AND is_active = 1`),
  insert: db.prepare<{
    name: string;
    description: string;
    parent_id: number | null;
    icon: string;
    color: string;
  }, void>(
    `INSERT INTO vault_collections (name, description, parent_id, icon, color)
     VALUES (@name, @description, @parent_id, @icon, @color)`
  ),
  upsert: db.prepare<{
    name: string;
    description: string;
    parent_id: number | null;
    icon: string;
    color: string;
  }, void>(
    `INSERT INTO vault_collections (name, description, parent_id, icon, color)
     VALUES (@name, @description, @parent_id, @icon, @color)
     ON CONFLICT(name) DO UPDATE SET
       description = excluded.description,
       parent_id = excluded.parent_id,
       icon = excluded.icon,
       color = excluded.color,
       updated_at = datetime('now'),
       is_active = 1`
  ),
  update: db.prepare<{
    id: number;
    name: string;
    description: string;
    parent_id: number | null;
    icon: string;
    color: string;
  }, void>(
    `UPDATE vault_collections
     SET name = @name, description = @description, parent_id = @parent_id,
         icon = @icon, color = @color, updated_at = datetime('now')
     WHERE id = @id`
  ),
  softDelete: db.prepare<[number], void>(
    `UPDATE vault_collections SET is_active = 0, updated_at = datetime('now') WHERE id = ?`
  ),
};

export const entryQueries = {
  getAll: db.prepare<[], VaultEntry>(`SELECT * FROM vault_entries ORDER BY type, category, project, name`),
  getByName: db.prepare<[string], VaultEntry>(`SELECT * FROM vault_entries WHERE name = ? AND is_active = 1`),
  getById: db.prepare<[number], VaultEntry>(`SELECT * FROM vault_entries WHERE id = ? AND is_active = 1`),
  getByType: db.prepare<[VaultEntryType], VaultEntry>(`SELECT * FROM vault_entries WHERE type = ? AND is_active = 1 ORDER BY category, project, name`),
  getByCategory: db.prepare<[VaultCategory], VaultEntry>(`SELECT * FROM vault_entries WHERE category = ? AND is_active = 1 ORDER BY type, project, name`),
  getByCollection: db.prepare<[number], VaultEntry>(`SELECT * FROM vault_entries WHERE collection_id = ? AND is_active = 1 ORDER BY type, project, name`),
  insert: db.prepare<{
    type: VaultEntryType;
    category: VaultCategory;
    name: string;
    value_enc: string;
    tags: string;
    collection_id: number | null;
    project: string;
    notes: string;
    metadata: string;
    expires_at: string | null;
  }, void>(
    `INSERT INTO vault_entries (type, category, name, value_enc, tags, collection_id, project, notes, metadata, expires_at)
     VALUES (@type, @category, @name, @value_enc, @tags, @collection_id, @project, @notes, @metadata, @expires_at)`
  ),
  upsert: db.prepare<{
    type: VaultEntryType;
    category: VaultCategory;
    name: string;
    value_enc: string;
    tags: string;
    collection_id: number | null;
    project: string;
    notes: string;
    metadata: string;
    expires_at: string | null;
  }, void>(
    `INSERT INTO vault_entries (type, category, name, value_enc, tags, collection_id, project, notes, metadata, expires_at)
     VALUES (@type, @category, @name, @value_enc, @tags, @collection_id, @project, @notes, @metadata, @expires_at)
     ON CONFLICT(name) DO UPDATE SET
       type = excluded.type,
       category = excluded.category,
       value_enc = excluded.value_enc,
       tags = excluded.tags,
       collection_id = excluded.collection_id,
       project = excluded.project,
       notes = excluded.notes,
       metadata = excluded.metadata,
       expires_at = excluded.expires_at,
       updated_at = datetime('now'),
       is_active = 1`
  ),
  update: db.prepare<{
    id: number;
    type: VaultEntryType;
    category: VaultCategory;
    value_enc: string;
    tags: string;
    collection_id: number | null;
    project: string;
    notes: string;
    metadata: string;
    expires_at: string | null;
  }, void>(
    `UPDATE vault_entries
     SET type = @type, category = @category, value_enc = @value_enc, tags = @tags, collection_id = @collection_id,
         project = @project, notes = @notes, metadata = @metadata, expires_at = @expires_at,
         updated_at = datetime('now')
     WHERE id = @id`
  ),
  recordAccess: db.prepare<[string], void>(
    `UPDATE vault_entries
     SET last_accessed = datetime('now'), access_count = access_count + 1
     WHERE name = ?`
  ),
  softDelete: db.prepare<[number], void>(
    `UPDATE vault_entries SET is_active = 0, updated_at = datetime('now') WHERE id = ?`
  ),
  getExpiringSoon: db.prepare<[string], VaultEntry>(
    `SELECT * FROM vault_entries
     WHERE is_active = 1 AND expires_at IS NOT NULL AND expires_at <= ?
     ORDER BY expires_at`
  ),
  search: db.prepare<[string, string, string, string], VaultEntry>(
    `SELECT * FROM vault_entries
     WHERE is_active = 1
       AND (name LIKE ? OR tags LIKE ? OR project LIKE ? OR category LIKE ?)
     ORDER BY type, category, project, name`
  ),
};

export const exportQueries = {
  insert: db.prepare<{
    kind: 'import' | 'export';
    format: string;
    filename: string;
    metadata: string;
  }, void>(
    `INSERT INTO vault_import_exports (kind, format, filename, metadata)
     VALUES (@kind, @format, @filename, @metadata)`
  ),
  getRecent: db.prepare<[number], VaultImportExportRecord>(
    `SELECT * FROM vault_import_exports ORDER BY created_at DESC LIMIT ?`
  ),
};

export const auditQueries = {
  insert: db.prepare<{
    entry_name: string;
    action: string;
    ip: string;
    user_agent: string;
    meta: string;
  }, void>(
    `INSERT INTO audit_log (entry_name, action, ip, user_agent, meta)
     VALUES (@entry_name, @action, @ip, @user_agent, @meta)`
  ),
  insertChained: db.prepare<{
    entry_name: string;
    action: string;
    ip: string;
    user_agent: string;
    meta: string;
    prev_hash: string;
  }, void>(
    `INSERT INTO audit_log (entry_name, action, ip, user_agent, meta, prev_hash)
     VALUES (@entry_name, @action, @ip, @user_agent, @meta, @prev_hash)`
  ),
  getRecent: db.prepare<[number], AuditEntry>(
    `SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?`
  ),
  getForEntry: db.prepare<[string, number], AuditEntry>(
    `SELECT * FROM audit_log WHERE entry_name = ? ORDER BY timestamp DESC LIMIT ?`
  ),
  getStats: db.prepare<[], { entry_name: string; access_count: number; last_accessed: string }>(
    `SELECT entry_name, COUNT(*) as access_count, MAX(timestamp) as last_accessed
     FROM audit_log WHERE action = 'READ'
     GROUP BY entry_name ORDER BY access_count DESC`
  ),
  getLastRow: db.prepare<[], AuditEntry>(
    `SELECT * FROM audit_log ORDER BY id DESC LIMIT 1`
  ),
};

export const verificationQueries = {
  insert: db.prepare<{
    source: string;
    ok: number;
    broken_at: number | null;
    expected_hash: string | null;
    got_hash: string | null;
    total_entries: number;
    head_id: number | null;
    head_hash: string | null;
    genesis_ok: number;
    details: string;
    alert_sent: number;
  }, void>(
    `INSERT INTO audit_verification_runs (
      source, ok, broken_at, expected_hash, got_hash,
      total_entries, head_id, head_hash, genesis_ok, details, alert_sent
    ) VALUES (
      @source, @ok, @broken_at, @expected_hash, @got_hash,
      @total_entries, @head_id, @head_hash, @genesis_ok, @details, @alert_sent
    )`
  ),
  getRecent: db.prepare<[number], AuditVerificationRun>(
    `SELECT * FROM audit_verification_runs ORDER BY id DESC LIMIT ?`
  ),
  getLast: db.prepare<[], AuditVerificationRun>(
    `SELECT * FROM audit_verification_runs ORDER BY id DESC LIMIT 1`
  ),
};

/** Compute the HMAC-SHA256 hash of a canonical audit row representation. */
function hashAuditRow(row: AuditEntry, key: string): string {
  const canonical = JSON.stringify({
    id: row.id,
    entry_name: row.entry_name,
    action: row.action,
    ip: row.ip,
    user_agent: row.user_agent,
    timestamp: row.timestamp,
    meta: row.meta,
    prev_hash: row.prev_hash,
  });
  return createHmac('sha256', key).update(canonical).digest('hex');
}

/**
 * Insert an audit log entry with a chained HMAC over the previous entry.
 * The key defaults to VAULT_MASTER_SECRET so the chain is verifiable only
 * by a party holding the master secret.
 */
export function logAudit(entry_name: string, action: string, ip = 'unknown', user_agent = '', meta = '') {
  const key = process.env.VAULT_MASTER_SECRET ?? '';
  const last = auditQueries.getLastRow.get();
  const prev_hash = last ? hashAuditRow(last, key) : 'genesis';
  auditQueries.insertChained.run({ entry_name, action, ip, user_agent, meta, prev_hash });
}

/**
 * Verify the audit chain integrity. Returns the first broken link (if any).
 * Only works when called with the same VAULT_MASTER_SECRET used at write time.
 */
export function verifyAuditChain(): { ok: true } | { ok: false; brokenAt: number; expected: string; got: string } {
  const key = process.env.VAULT_MASTER_SECRET ?? '';
  const rows = db.prepare<[], AuditEntry>(`SELECT * FROM audit_log ORDER BY id ASC`).all();
  for (let i = 1; i < rows.length; i++) {
    const expected = hashAuditRow(rows[i - 1]!, key);
    if (rows[i]!.prev_hash !== expected) {
      return { ok: false, brokenAt: rows[i]!.id, expected, got: rows[i]!.prev_hash };
    }
  }
  return { ok: true };
}

export function getAuditChainStatus(): {
  totalEntries: number;
  headId: number | null;
  headHash: string | null;
  genesisOk: boolean;
} {
  const key = process.env.VAULT_MASTER_SECRET ?? '';
  const rows = db.prepare<[], AuditEntry>(`SELECT * FROM audit_log ORDER BY id ASC`).all();
  if (!rows.length) {
    return {
      totalEntries: 0,
      headId: null,
      headHash: null,
      genesisOk: true,
    };
  }
  const head = rows[rows.length - 1]!;
  return {
    totalEntries: rows.length,
    headId: head.id,
    headHash: hashAuditRow(head, key),
    genesisOk: rows[0]!.prev_hash === 'genesis',
  };
}

export function recordAuditVerificationRun(input: {
  source: string;
  ok: boolean;
  status: {
    totalEntries: number;
    headId: number | null;
    headHash: string | null;
    genesisOk: boolean;
  };
  verification: { ok: true } | { ok: false; brokenAt: number; expected: string; got: string };
  details: string;
  alertSent: boolean;
}): void {
  verificationQueries.insert.run({
    source: input.source,
    ok: input.ok ? 1 : 0,
    broken_at: input.verification.ok ? null : input.verification.brokenAt,
    expected_hash: input.verification.ok ? null : input.verification.expected,
    got_hash: input.verification.ok ? null : input.verification.got,
    total_entries: input.status.totalEntries,
    head_id: input.status.headId,
    head_hash: input.status.headHash,
    genesis_ok: input.status.genesisOk ? 1 : 0,
    details: input.details,
    alert_sent: input.alertSent ? 1 : 0,
  });
}

export function getLastAuditVerificationRun(): AuditVerificationRun | null {
  return verificationQueries.getLast.get() ?? null;
}

export function listAuditVerificationRuns(limit = 100): AuditVerificationRun[] {
  const safeLimit = Math.max(1, Math.min(limit, 1000));
  return verificationQueries.getRecent.all(safeLimit);
}
