import { Router, type Request, type Response } from 'express';
import { collectionQueries, entryQueries, exportQueries, logAudit, parseMetadata, parseTags, serializeMetadata, serializeTags, normalizeVaultCategory, normalizeVaultEntryType, type VaultEntryType, type VaultCategory } from '../db.js';
import { encrypt, decrypt } from '../crypto.js';
import { requireReadToken, requireAdminToken } from '../auth.js';
import { validateCreateEntry, validateUpdateEntry, validateCreateCollection, validateImportDocument, validateImportEnv, validateImportOpenClaw, validateCollectionName, validateEntryName, sendValidationError } from '../validate.js';

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
  const validated = validateCreateCollection(body);
  if (!validated.ok) return sendValidationError(res, validated.errors);
  const v = validated.value;
  const parent = v.parentName ? collectionQueries.getByName.get(v.parentName) : null;
  if (v.parentName && !parent) {
    return res.status(400).json({ error: `Parent collection "${v.parentName}" not found` });
  }
  collectionQueries.upsert.run({
    name: v.name,
    description: v.description ?? '',
    parent_id: parent?.id ?? null,
    icon: v.icon ?? 'folder',
    color: v.color ?? 'slate',
  });
  const saved = collectionQueries.getByName.get(v.name)!;
  res.status(201).json(saved);
});

vaultRouter.put('/collections/:name', requireAdminToken, (req, res) => {
  const existing = collectionQueries.getByName.get(req.params.name);
  if (!existing) return res.status(404).json({ error: 'Collection not found' });
  const body = readBody(req);
  // Treat PUT /collections/:name as a partial update — only name is truly required for upsert
  const rawName = body.name !== undefined ? body.name : existing.name;
  const tempBody = { ...body, name: rawName };
  const validated = validateCreateCollection(tempBody as Record<string, unknown>);
  if (!validated.ok) return sendValidationError(res, validated.errors);
  const v = validated.value;
  const parentName = body.parentName !== undefined
    ? (body.parentName ? String(body.parentName) : null)
    : (existing.parent_id ? collectionQueries.getById.get(existing.parent_id)?.name ?? null : null);
  const parent = parentName ? collectionQueries.getByName.get(parentName) : null;
  if (parentName && !parent) {
    return res.status(400).json({ error: `Parent collection "${parentName}" not found` });
  }
  collectionQueries.update.run({
    id: existing.id,
    name: v.name,
    description: body.description !== undefined ? String(body.description) : existing.description,
    parent_id: parent?.id ?? null,
    icon: body.icon !== undefined ? String(body.icon) : existing.icon,
    color: body.color !== undefined ? String(body.color) : existing.color,
  });
  const saved = collectionQueries.getByName.get(v.name)!;
  res.json(saved);
});

vaultRouter.delete('/collections/:name', requireAdminToken, (req, res) => {
  const nameErr = validateCollectionName(req.params.name, 'name');
  if (nameErr) return sendValidationError(res, [nameErr]);
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

vaultRouter.get('/import/export', requireAdminToken, (_req, res) => {
  res.json(exportQueries.getRecent.all(20));
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
  const validated = validateCreateEntry(body);
  if (!validated.ok) return sendValidationError(res, validated.errors);
  const v = validated.value;

  const type = normalizeVaultEntryType(v.type);
  const category = v.category ?? normalizeVaultCategory(undefined, type);
  const tags = serializeTags(v.tags ?? []);
  const collection = v.collection ? collectionQueries.getByName.get(v.collection) : null;
  if (v.collection && !collection) {
    return res.status(400).json({ error: `Collection "${v.collection}" not found` });
  }

  try {
    const value_enc = encrypt(v.value, MASTER);
    entryQueries.upsert.run({
      type,
      category,
      name: v.name,
      value_enc,
      tags,
      collection_id: collection?.id ?? null,
      project: v.project ?? '',
      notes: v.notes ?? '',
      metadata: serializeMetadata(v.metadata ?? {}),
      expires_at: v.expires_at ?? null,
    });
    logAudit(v.name, 'CREATE', clientIp(req), req.headers['user-agent'] ?? '', JSON.stringify({ type, category }));
    res.status(201).json({ ok: true, name: v.name, type, category });
  } catch (err: any) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: `Entry "${v.name}" already exists — use PUT to update` });
    }
    throw err;
  }
});

vaultRouter.put('/:name', requireAdminToken, (req, res) => {
  const nameErr = validateEntryName(req.params.name);
  if (nameErr) return sendValidationError(res, [nameErr]);
  const row = entryQueries.getByName.get(req.params.name);
  if (!row) return res.status(404).json({ error: 'Entry not found' });
  const body = readBody(req);
  const validated = validateUpdateEntry(body);
  if (!validated.ok) return sendValidationError(res, validated.errors);
  const v = validated.value;

  const type = v.type ?? row.type;
  const category = v.category ?? row.category;
  const collectionName = v.collection !== undefined ? v.collection : null;
  const collection = collectionName ? collectionQueries.getByName.get(collectionName) : null;
  if (collectionName && !collection) {
    return res.status(400).json({ error: `Collection "${collectionName}" not found` });
  }
  const value_enc = v.value ? encrypt(v.value, MASTER) : row.value_enc;
  entryQueries.update.run({
    id: row.id,
    type,
    category,
    value_enc,
    tags: serializeTags(v.tags !== undefined ? v.tags : parseTags(row.tags)),
    collection_id: v.collection !== undefined ? (collection?.id ?? null) : row.collection_id,
    project: v.project !== undefined ? v.project : row.project,
    notes: v.notes !== undefined ? v.notes : row.notes,
    metadata: serializeMetadata(v.metadata !== undefined ? v.metadata : parseMetadata(row.metadata)),
    expires_at: v.expires_at !== undefined ? v.expires_at : row.expires_at,
  });
  logAudit(row.name, 'UPDATE', clientIp(req), req.headers['user-agent'] ?? '', JSON.stringify({ type, category }));
  res.json({ ok: true, name: row.name, type, category });
});

vaultRouter.delete('/:name', requireAdminToken, (req, res) => {
  const nameErr = validateEntryName(req.params.name);
  if (nameErr) return sendValidationError(res, [nameErr]);
  const row = entryQueries.getByName.get(req.params.name);
  if (!row) return res.status(404).json({ error: 'Entry not found' });
  entryQueries.softDelete.run(row.id);
  logAudit(row.name, 'DELETE', clientIp(req), req.headers['user-agent'] ?? '');
  res.json({ ok: true });
});

vaultRouter.post('/import', requireAdminToken, (req, res) => {
  const body = readBody(req);
  const validated = validateImportDocument(body);
  if (!validated.ok) return sendValidationError(res, validated.errors);
  const { collections, entries, replaceExisting } = validated.value;
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

// ── .env bulk import ──────────────────────────────────────────────────────────

function inferTypeFromEnvKey(key: string): VaultEntryType {
  const u = key.toUpperCase();
  if (u.endsWith('_API_KEY') || u.endsWith('_APIKEY')) return 'api-key';
  if (u.endsWith('_TOKEN') || u === 'TOKEN') return 'token';
  if (u.endsWith('_SECRET') || u === 'SECRET') return 'secret';
  if (u.endsWith('_PASSWORD') || u.endsWith('_PASS') || u === 'PASSWORD') return 'password';
  if (u.includes('_KEY') || u.endsWith('KEY')) return 'api-key';
  return 'secret';
}

function parseEnvText(text: string): Array<{ key: string; value: string }> {
  const result: Array<{ key: string; value: string }> = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const stripped = line.startsWith('export ') ? line.slice(7).trim() : line;
    const eqIdx = stripped.indexOf('=');
    if (eqIdx < 1) continue;
    const key = stripped.slice(0, eqIdx).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    let value = stripped.slice(eqIdx + 1);
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    } else {
      // Allow inline comments for unquoted values: KEY=value # comment
      value = value.split(' #')[0] ?? value;
    }
    result.push({ key, value: value.trim() });
  }
  return result;
}

vaultRouter.post('/import/env', requireAdminToken, (req, res) => {
  const body = readBody(req);
  const validated = validateImportEnv(body);
  if (!validated.ok) return sendValidationError(res, validated.errors);
  const v = validated.value;
  const envText = v.env.trim();
  if (!envText) return res.status(400).json({ error: '"env" string is required' });
  const pairs = parseEnvText(envText);
  if (!pairs.length) return res.status(400).json({ error: 'No valid KEY=VALUE pairs found' });

  const collectionName = v.collection ? v.collection.trim() : null;
  const collection = collectionName ? collectionQueries.getByName.get(collectionName) : null;
  if (collectionName && !collection) {
    return res.status(400).json({ error: `Collection "${collectionName}" not found` });
  }
  const project = v.project ?? '';
  const baseTags = Array.isArray(v.tags)
    ? v.tags.map((item) => item.trim()).filter(Boolean)
    : ['source:env'];
  const namePrefix = v.namePrefix ? v.namePrefix.trim() : '';
  let created = 0;
  let updated = 0;

  for (const { key, value } of pairs) {
    const name = namePrefix ? `${namePrefix}${key}` : key;
    const type = inferTypeFromEnvKey(key);
    const category = normalizeVaultCategory(undefined, type);
    const tags = serializeTags([...baseTags, `env-key:${key}`]);
    const value_enc = encrypt(value, MASTER);
    const existing = entryQueries.getByName.get(name);
    if (existing) {
      entryQueries.update.run({
        id: existing.id,
        type,
        category,
        value_enc,
        tags,
        collection_id: collection?.id ?? existing.collection_id,
        project: project || existing.project,
        notes: existing.notes,
        metadata: existing.metadata,
        expires_at: existing.expires_at,
      });
      logAudit(name, 'UPDATE', clientIp(req), req.headers['user-agent'] ?? '', JSON.stringify({ source: 'env-import' }));
      updated++;
    } else {
      entryQueries.upsert.run({
        type,
        category,
        name,
        value_enc,
        tags,
        collection_id: collection?.id ?? null,
        project,
        notes: '',
        metadata: '{}',
        expires_at: null,
      });
      logAudit(name, 'CREATE', clientIp(req), req.headers['user-agent'] ?? '', JSON.stringify({ source: 'env-import' }));
      created++;
    }
  }

  exportQueries.insert.run({
    kind: 'import',
    format: 'env',
    filename: '.env',
    metadata: JSON.stringify({ created, updated, total: pairs.length }),
  });
  res.json({ ok: true, created, updated, total: pairs.length });
});

// ── OpenClaw import contract ──────────────────────────────────────────────────

interface OpenClawPlugin {
  name: string;
  icon?: string;
  env?: string[];
  config?: string[];
  bins?: string[];
  anyBins?: string[];
  os?: string | null;
}

vaultRouter.post('/import/openclaw', requireAdminToken, (req, res) => {
  const body = readBody(req);
  const validated = validateImportOpenClaw(body);
  if (!validated.ok) return sendValidationError(res, validated.errors);
  const { plugins, values, project, includePlaceholders } = validated.value;

  // Ensure top-level "openclaw" collection
  collectionQueries.upsert.run({
    name: 'openclaw',
    description: 'OpenClaw integrations',
    parent_id: null,
    icon: 'claw',
    color: 'orange',
  });
  const parentCollection = collectionQueries.getByName.get('openclaw')!;

  let created = 0;
  let updated = 0;
  let placeholders = 0;
  const summary: Array<{ plugin: string; entries: string[] }> = [];

  for (const plugin of plugins) {
    const pluginName = String(plugin.name ?? '').trim();
    if (!pluginName) continue;

    // Ensure plugin sub-collection
    const collName = `openclaw/${pluginName}`;
    collectionQueries.upsert.run({
      name: collName,
      description: `${plugin.icon ? plugin.icon + ' ' : ''}${pluginName} integration secrets`,
      parent_id: parentCollection.id,
      icon: plugin.icon ?? 'plug',
      color: 'slate',
    });
    const pluginCollection = collectionQueries.getByName.get(collName)!;

    const osTags = plugin.os ? [`os:${plugin.os}`] : [];
    const pluginTags = serializeTags(['source:openclaw', `plugin:${pluginName}`, ...osTags]);
    const pluginEntries: string[] = [];

    const saveEntry = (name: string, rawValue: string | undefined, type: VaultEntryType, action: string) => {
      if (!rawValue && !includePlaceholders) return;
      const value = rawValue ?? '';
      const notes = rawValue ? '' : 'placeholder — configure this value';
      const category = normalizeVaultCategory(undefined, type);
      const value_enc = encrypt(value, MASTER);
      const existing = entryQueries.getByName.get(name);
      if (existing) {
        entryQueries.update.run({
          id: existing.id,
          type,
          category,
          value_enc,
          tags: pluginTags,
          collection_id: pluginCollection.id,
          project,
          notes: notes || existing.notes,
          metadata: existing.metadata,
          expires_at: existing.expires_at,
        });
        updated++;
      } else {
        entryQueries.upsert.run({
          type,
          category,
          name,
          value_enc,
          tags: pluginTags,
          collection_id: pluginCollection.id,
          project,
          notes,
          metadata: '{}',
          expires_at: null,
        });
        rawValue ? created++ : placeholders++;
      }
      logAudit(name, action, clientIp(req), req.headers['user-agent'] ?? '', JSON.stringify({ source: 'openclaw-import', plugin: pluginName }));
      pluginEntries.push(name);
    };

    for (const envKey of (plugin.env ?? [])) {
      const raw = values[envKey] ?? values[`env:${envKey}`];
      saveEntry(envKey, raw, inferTypeFromEnvKey(envKey), raw ? 'CREATE' : 'PLACEHOLDER');
    }

    for (const configKey of (plugin.config ?? [])) {
      const raw = values[configKey] ?? values[`config:${configKey}`];
      saveEntry(configKey, raw, 'secret', raw ? 'CREATE' : 'PLACEHOLDER');
    }

    if (pluginEntries.length) summary.push({ plugin: pluginName, entries: pluginEntries });
  }

  exportQueries.insert.run({
    kind: 'import',
    format: 'openclaw',
    filename: 'openclaw-import.json',
    metadata: JSON.stringify({ created, updated, placeholders }),
  });
  res.json({ ok: true, created, updated, placeholders, plugins: summary });
});

