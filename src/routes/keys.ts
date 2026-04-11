import { Router, type Request, type Response } from 'express';
import { collectionQueries, entryQueries, exportQueries, logAudit, parseMetadata, parseTags, serializeMetadata, serializeTags, normalizeVaultCategory, normalizeVaultEntryType, type VaultEntryType, type VaultCategory } from '../db.js';
import { encrypt, decrypt } from '../crypto.js';
import { requireReadToken, requireAdminToken } from '../auth.js';

export const vaultRouter = Router();

const MASTER = process.env.VAULT_MASTER_SECRET!;

function clientIp(req: Request): string {
  return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
    ?? req.socket.remoteAddress
    ?? 'unknown';
}

function safeEntry(row: ReturnType<typeof entryQueries.getAll.all>[number]) {
  const { value_enc: _v, ...rest } = row;
  return {
    ...rest,
    tags: parseTags(rest.tags),
    metadata: parseMetadata(rest.metadata),
  };
}

function safeCollection(row: ReturnType<typeof collectionQueries.getAll.all>[number]) {
  return { ...row };
}

function readBody(req: Request): Record<string, unknown> {
  return (req.body ?? {}) as Record<string, unknown>;
}

vaultRouter.get('/', requireReadToken, (_req, res) => {
  res.json(entryQueries.getAll.all().map(safeEntry));
});

vaultRouter.get('/types', requireReadToken, (_req, res) => {
  res.json([
    { type: 'api-key', category: 'api-keys' },
    { type: 'password', category: 'credentials' },
    { type: 'note', category: 'notes' },
    { type: 'recovery-code', category: 'recovery-codes' },
    { type: 'token', category: 'tokens' },
    { type: 'card', category: 'cards' },
    { type: 'secret', category: 'general' },
  ]);
});

vaultRouter.get('/categories', requireReadToken, (_req, res) => {
  res.json([
    'api-keys',
    'credentials',
    'notes',
    'recovery-codes',
    'tokens',
    'cards',
    'general',
  ] satisfies VaultCategory[]);
});

vaultRouter.get('/types/:type', requireReadToken, (req, res) => {
  const type = normalizeVaultEntryType(req.params.type);
  res.json(entryQueries.getByType.all(type).map(safeEntry));
});

vaultRouter.get('/categories/:category', requireReadToken, (req, res) => {
  const category = req.params.category as VaultCategory;
  res.json(entryQueries.getByCategory.all(category).map(safeEntry));
});

vaultRouter.get('/collections', requireReadToken, (_req, res) => {
  res.json(collectionQueries.getAll.all().map(safeCollection));
});

vaultRouter.get('/collections/:name', requireReadToken, (req, res) => {
  const collection = collectionQueries.getByName.get(req.params.name);
  if (!collection) return res.status(404).json({ error: 'Collection not found' });
  res.json(collection);
});

vaultRouter.get('/collections/:name/entries', requireReadToken, (req, res) => {
  const collection = collectionQueries.getByName.get(req.params.name);
  if (!collection) return res.status(404).json({ error: 'Collection not found' });
  res.json(entryQueries.getByCollection.all(collection.id).map(safeEntry));
});

vaultRouter.post('/collections', requireAdminToken, (req, res) => {
  const body = readBody(req);
  const name = String(body.name ?? '').trim();
  if (!name) return res.status(400).json({ error: 'name is required' });
  const description = String(body.description ?? '');
  const parentName = body.parentName ? String(body.parentName) : null;
  const parent = parentName ? collectionQueries.getByName.get(parentName) : null;
  const icon = String(body.icon ?? 'folder');
  const color = String(body.color ?? 'slate');
  collectionQueries.upsert.run({
    name,
    description,
    parent_id: parent?.id ?? null,
    icon,
    color,
  });
  const saved = collectionQueries.getByName.get(name)!;
  res.status(201).json(saved);
});

vaultRouter.put('/collections/:name', requireAdminToken, (req, res) => {
  const existing = collectionQueries.getByName.get(req.params.name);
  if (!existing) return res.status(404).json({ error: 'Collection not found' });
  const body = readBody(req);
  const name = String(body.name ?? existing.name).trim();
  const description = String(body.description ?? existing.description);
  const parentName = body.parentName ? String(body.parentName) : null;
  const parent = parentName ? collectionQueries.getByName.get(parentName) : null;
  const icon = String(body.icon ?? existing.icon);
  const color = String(body.color ?? existing.color);
  collectionQueries.update.run({
    id: existing.id,
    name,
    description,
    parent_id: parent?.id ?? null,
    icon,
    color,
  });
  const saved = collectionQueries.getByName.get(name)!;
  res.json(saved);
});

vaultRouter.delete('/collections/:name', requireAdminToken, (req, res) => {
  const existing = collectionQueries.getByName.get(req.params.name);
  if (!existing) return res.status(404).json({ error: 'Collection not found' });
  collectionQueries.softDelete.run(existing.id);
  res.json({ ok: true });
});

vaultRouter.get('/expiring', requireAdminToken, (req, res) => {
  const days = parseInt(req.query.days as string ?? '7', 10);
  const cutoff = new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);
  const rows = entryQueries.getExpiringSoon.all(cutoff);
  res.json(rows.map(safeEntry));
});

vaultRouter.get('/search', requireReadToken, (req, res) => {
  const q = `%${req.query.q ?? ''}%`;
  const rows = entryQueries.search.all(q, q, q, q);
  res.json(rows.map(safeEntry));
});

vaultRouter.get('/:name', requireReadToken, (req, res) => {
  const row = entryQueries.getByName.get(req.params.name);
  if (!row) return res.status(404).json({ error: `Entry "${req.params.name}" not found` });
  let value: string;
  try {
    value = decrypt(row.value_enc, MASTER);
  } catch {
    logAudit(row.name, 'DECRYPT_ERROR', clientIp(req), req.headers['user-agent'] ?? '');
    return res.status(500).json({ error: 'Failed to decrypt — wrong master secret?' });
  }
  entryQueries.recordAccess.run(row.name);
  logAudit(row.name, 'READ', clientIp(req), req.headers['user-agent'] ?? '');
  res.json({
    name: row.name,
    type: row.type,
    category: row.category,
    value,
    tags: parseTags(row.tags),
    collection: row.collection_id,
    project: row.project,
    notes: row.notes,
    metadata: parseMetadata(row.metadata),
    expires_at: row.expires_at,
  });
});

vaultRouter.post('/', requireAdminToken, (req, res) => {
  const body = readBody(req);
  const name = String(body.name ?? '').trim();
  const value = body.value;
  if (!name || value === undefined || value === null || value === '') {
    return res.status(400).json({ error: 'name and value are required' });
  }
  const type = normalizeVaultEntryType(body.type);
  const category = body.category ? (body.category as VaultCategory) : normalizeVaultCategory(undefined, type);
  const tags = serializeTags(body.tags ?? []);
  const collectionName = body.collection ? String(body.collection) : null;
  const collection = collectionName ? collectionQueries.getByName.get(collectionName) : null;
  const project = String(body.project ?? '');
  const notes = String(body.notes ?? '');
  const metadata = serializeMetadata(body.metadata ?? {});
  const expires_at = body.expires_at ? String(body.expires_at) : null;

  try {
    const value_enc = encrypt(String(value), MASTER);
    entryQueries.upsert.run({
      type,
      category,
      name,
      value_enc,
      tags,
      collection_id: collection?.id ?? null,
      project,
      notes,
      metadata,
      expires_at,
    });
    logAudit(name, 'CREATE', clientIp(req), req.headers['user-agent'] ?? '', JSON.stringify({ type, category }));
    res.status(201).json({ ok: true, name, type, category });
  } catch (err: any) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: `Entry "${name}" already exists — use PUT to update` });
    }
    throw err;
  }
});

vaultRouter.put('/:name', requireAdminToken, (req, res) => {
  const row = entryQueries.getByName.get(req.params.name);
  if (!row) return res.status(404).json({ error: 'Entry not found' });
  const body = readBody(req);
  const type = body.type ? normalizeVaultEntryType(body.type) : row.type;
  const category = body.category ? (body.category as VaultCategory) : row.category;
  const collectionName = body.collection ? String(body.collection) : null;
  const collection = collectionName ? collectionQueries.getByName.get(collectionName) : null;
  const value = body.value;
  const value_enc = value ? encrypt(String(value), MASTER) : row.value_enc;
  entryQueries.update.run({
    id: row.id,
    type,
    category,
    value_enc,
    tags: serializeTags(body.tags ?? parseTags(row.tags)),
    collection_id: collection?.id ?? row.collection_id,
    project: String(body.project ?? row.project),
    notes: String(body.notes ?? row.notes),
    metadata: serializeMetadata(body.metadata ?? parseMetadata(row.metadata)),
    expires_at: body.expires_at === undefined ? row.expires_at : (body.expires_at ? String(body.expires_at) : null),
  });
  logAudit(row.name, 'UPDATE', clientIp(req), req.headers['user-agent'] ?? '', JSON.stringify({ type, category }));
  res.json({ ok: true, name: row.name, type, category });
});

vaultRouter.delete('/:name', requireAdminToken, (req, res) => {
  const row = entryQueries.getByName.get(req.params.name);
  if (!row) return res.status(404).json({ error: 'Entry not found' });
  entryQueries.softDelete.run(row.id);
  logAudit(row.name, 'DELETE', clientIp(req), req.headers['user-agent'] ?? '');
  res.json({ ok: true });
});

vaultRouter.get('/import/export', requireAdminToken, (_req, res) => {
  res.json(exportQueries.getRecent.all(20));
});

vaultRouter.post('/import', requireAdminToken, (req, res) => {
  const body = readBody(req) as { version?: number; collections?: unknown[]; entries?: unknown[]; replaceExisting?: boolean };
  if (body.version !== 1) return res.status(400).json({ error: 'Unsupported import version' });
  const collections = Array.isArray(body.collections) ? body.collections : [];
  const entries = Array.isArray(body.entries) ? body.entries : [];
  const replaceExisting = body.replaceExisting === true;
  if (replaceExisting) {
    for (const existing of entryQueries.getAll.all()) {
      entryQueries.softDelete.run(existing.id);
    }
  }
  for (const rawCollection of collections) {
    if (!rawCollection || typeof rawCollection !== 'object') continue;
    const item = rawCollection as Record<string, unknown>;
    const name = String(item.name ?? '').trim();
    if (!name) continue;
    const parentName = item.parentName ? String(item.parentName) : null;
    const parent = parentName ? collectionQueries.getByName.get(parentName) : null;
    collectionQueries.upsert.run({
      name,
      description: String(item.description ?? ''),
      parent_id: parent?.id ?? null,
      icon: String(item.icon ?? 'folder'),
      color: String(item.color ?? 'slate'),
    });
  }
  for (const rawEntry of entries) {
    if (!rawEntry || typeof rawEntry !== 'object') continue;
    const item = rawEntry as Record<string, unknown>;
    const name = String(item.name ?? '').trim();
    const value = item.value;
    if (!name || value === undefined || value === null) continue;
    const type = normalizeVaultEntryType(item.type);
    const category = item.category ? (item.category as VaultCategory) : normalizeVaultCategory(undefined, type);
    const collectionName = item.collection ? String(item.collection) : null;
    const collection = collectionName ? collectionQueries.getByName.get(collectionName) : null;
    entryQueries.upsert.run({
      type,
      category,
      name,
      value_enc: encrypt(String(value), MASTER),
      tags: serializeTags(item.tags ?? []),
      collection_id: collection?.id ?? null,
      project: String(item.project ?? ''),
      notes: String(item.notes ?? ''),
      metadata: serializeMetadata(item.metadata ?? {}),
      expires_at: item.expiresAt ? String(item.expiresAt) : (item.expires_at ? String(item.expires_at) : null),
    });
  }
  exportQueries.insert.run({ kind: 'import', format: 'json', filename: 'vault-import.json', metadata: JSON.stringify({ replaceExisting }) });
  res.json({ ok: true, imported: entries.length, collections: collections.length });
});

vaultRouter.get('/export', requireAdminToken, (_req, res) => {
  const collections = collectionQueries.getAll.all().map((collection) => ({
    name: collection.name,
    description: collection.description,
    parentName: collection.parent_id ? collectionQueries.getById.get(collection.parent_id)?.name ?? null : null,
    icon: collection.icon,
    color: collection.color,
  }));
  const entries = entryQueries.getAll.all().map((entry) => ({
    name: entry.name,
    type: entry.type,
    category: entry.category,
    value: decrypt(entry.value_enc, MASTER),
    tags: parseTags(entry.tags),
    collection: entry.collection_id ? collectionQueries.getById.get(entry.collection_id)?.name ?? null : null,
    project: entry.project,
    notes: entry.notes,
    metadata: parseMetadata(entry.metadata),
    expiresAt: entry.expires_at,
  }));
  const document = { version: 1, generatedAt: new Date().toISOString(), collections, entries };
  exportQueries.insert.run({ kind: 'export', format: 'json', filename: 'vault-export.json', metadata: JSON.stringify({ entryCount: entries.length, collectionCount: collections.length }) });
  res.json(document);
});
