import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';

const DB_DIR = process.env.VAULT_DATA_DIR ?? './data';
const DB_PATH = path.join(DB_DIR, 'vault.db');

if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

export const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

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
};

export function logAudit(entry_name: string, action: string, ip = 'unknown', user_agent = '', meta = '') {
  auditQueries.insert.run({ entry_name, action, ip, user_agent, meta });
}
