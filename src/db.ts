import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';

const DB_DIR = process.env.VAULT_DATA_DIR ?? './data';
const DB_PATH = path.join(DB_DIR, 'vault.db');

// Ensure data directory exists
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

export const db = new Database(DB_PATH);

// WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Schema ──────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS vault_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    UNIQUE NOT NULL,
    value_enc   TEXT    NOT NULL,
    tags        TEXT    DEFAULT '',
    project     TEXT    DEFAULT '',
    notes       TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT,
    last_accessed TEXT,
    access_count  INTEGER NOT NULL DEFAULT 0,
    is_active   INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    key_name  TEXT NOT NULL,
    action    TEXT NOT NULL,
    ip        TEXT,
    user_agent TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    meta      TEXT DEFAULT ''
  );

  CREATE INDEX IF NOT EXISTS idx_audit_key  ON audit_log(key_name);
  CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(timestamp);
  CREATE INDEX IF NOT EXISTS idx_keys_name  ON vault_keys(name);
  CREATE INDEX IF NOT EXISTS idx_keys_project ON vault_keys(project);
`);

// ── Types ────────────────────────────────────────────────────────────────────

export interface VaultKey {
  id: number;
  name: string;
  value_enc: string;
  tags: string;
  project: string;
  notes: string;
  created_at: string;
  updated_at: string;
  expires_at: string | null;
  last_accessed: string | null;
  access_count: number;
  is_active: number;
}

export interface AuditEntry {
  id: number;
  key_name: string;
  action: string;
  ip: string;
  user_agent: string;
  timestamp: string;
  meta: string;
}

// ── Key queries ───────────────────────────────────────────────────────────────

export const keyQueries = {
  getAll: db.prepare<[], VaultKey>(
    `SELECT * FROM vault_keys ORDER BY project, name`
  ),

  getByName: db.prepare<[string], VaultKey>(
    `SELECT * FROM vault_keys WHERE name = ? AND is_active = 1`
  ),

  getById: db.prepare<[number], VaultKey>(
    `SELECT * FROM vault_keys WHERE id = ?`
  ),

  insert: db.prepare<{
    name: string; value_enc: string; tags: string;
    project: string; notes: string; expires_at: string | null;
  }, void>(
    `INSERT INTO vault_keys (name, value_enc, tags, project, notes, expires_at)
     VALUES (@name, @value_enc, @tags, @project, @notes, @expires_at)`
  ),

  update: db.prepare<{
    id: number; value_enc: string; tags: string;
    project: string; notes: string; expires_at: string | null;
  }, void>(
    `UPDATE vault_keys
     SET value_enc = @value_enc, tags = @tags, project = @project,
         notes = @notes, expires_at = @expires_at,
         updated_at = datetime('now')
     WHERE id = @id`
  ),

  recordAccess: db.prepare<[string], void>(
    `UPDATE vault_keys
     SET last_accessed = datetime('now'), access_count = access_count + 1
     WHERE name = ?`
  ),

  softDelete: db.prepare<[number], void>(
    `UPDATE vault_keys SET is_active = 0, updated_at = datetime('now') WHERE id = ?`
  ),

  getExpiringSoon: db.prepare<[string], VaultKey>(
    `SELECT * FROM vault_keys
     WHERE is_active = 1 AND expires_at IS NOT NULL AND expires_at <= ?
     ORDER BY expires_at`
  ),

  search: db.prepare<[string, string, string], VaultKey>(
    `SELECT * FROM vault_keys
     WHERE is_active = 1
       AND (name LIKE ? OR tags LIKE ? OR project LIKE ?)
     ORDER BY project, name`
  ),
};

// ── Audit queries ─────────────────────────────────────────────────────────────

export const auditQueries = {
  insert: db.prepare<{
    key_name: string; action: string; ip: string;
    user_agent: string; meta: string;
  }, void>(
    `INSERT INTO audit_log (key_name, action, ip, user_agent, meta)
     VALUES (@key_name, @action, @ip, @user_agent, @meta)`
  ),

  getRecent: db.prepare<[number], AuditEntry>(
    `SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?`
  ),

  getForKey: db.prepare<[string, number], AuditEntry>(
    `SELECT * FROM audit_log WHERE key_name = ? ORDER BY timestamp DESC LIMIT ?`
  ),

  getStats: db.prepare<[], { key_name: string; access_count: number; last_accessed: string }>(
    `SELECT key_name, COUNT(*) as access_count, MAX(timestamp) as last_accessed
     FROM audit_log WHERE action = 'READ'
     GROUP BY key_name ORDER BY access_count DESC`
  ),
};

export function logAudit(
  key_name: string,
  action: string,
  ip = 'unknown',
  user_agent = '',
  meta = ''
) {
  auditQueries.insert.run({ key_name, action, ip, user_agent, meta });
}
