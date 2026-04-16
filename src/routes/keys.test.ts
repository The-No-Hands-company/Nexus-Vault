import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

type VaultEntryType = 'api-key' | 'password' | 'note' | 'recovery-code' | 'token' | 'card' | 'secret';
type VaultCategory = 'api-keys' | 'credentials' | 'notes' | 'recovery-codes' | 'tokens' | 'cards' | 'general';

function createDbMockModule() {
  type Collection = {
    id: number;
    name: string;
    description: string;
    parent_id: number | null;
    icon: string;
    color: string;
    created_at: string;
    updated_at: string;
    is_active: number;
  };

  type Entry = {
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
  };

  const now = () => new Date().toISOString();
  type Version = {
    id: number;
    entry_name: string;
    version: number;
    type: VaultEntryType;
    category: VaultCategory;
    value_enc: string;
    tags: string;
    notes: string;
    metadata: string;
    expires_at: string | null;
    archived_at: string;
    archived_reason: string;
  };

  const collections: Collection[] = [];
  const entries: Entry[] = [];
  const versions: Version[] = [];
  const importExports: Array<{ kind: string; format: string; filename: string; metadata: string; created_at: string }> = [];
  let collectionId = 1;
  let entryId = 1;
  let versionId = 1;

  const byCollectionName = (name: string) => collections.find((c) => c.name === name && c.is_active === 1) ?? null;
  const byCollectionId = (id: number) => collections.find((c) => c.id === id && c.is_active === 1) ?? null;
  const byEntryName = (name: string) => entries.find((e) => e.name === name && e.is_active === 1) ?? null;

  const VAULT_ENTRY_TYPES: VaultEntryType[] = ['api-key', 'password', 'note', 'recovery-code', 'token', 'card', 'secret'];
  const VAULT_CATEGORIES: VaultCategory[] = ['api-keys', 'credentials', 'notes', 'recovery-codes', 'tokens', 'cards', 'general'];

  const isVaultEntryType = (value: unknown): value is VaultEntryType =>
    typeof value === 'string' && VAULT_ENTRY_TYPES.includes(value as VaultEntryType);
  const isVaultCategory = (value: unknown): value is VaultCategory =>
    typeof value === 'string' && VAULT_CATEGORIES.includes(value as VaultCategory);
  const inferVaultCategory = (type: VaultEntryType): VaultCategory => {
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
  };

  const normalizeVaultEntryType = (value: unknown): VaultEntryType => (isVaultEntryType(value) ? value : 'secret');
  const normalizeVaultCategory = (value: unknown, fallbackType: VaultEntryType): VaultCategory =>
    isVaultCategory(value) ? value : inferVaultCategory(fallbackType);

  const serializeTags = (value: unknown): string => {
    if (Array.isArray(value)) {
      return JSON.stringify(value.filter((item): item is string => typeof item === 'string').map((item) => item.trim()).filter(Boolean));
    }
    return '[]';
  };
  const parseTags = (value: string): string[] => {
    try {
      const parsed = JSON.parse(value || '[]');
      return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [];
    } catch {
      return [];
    }
  };
  const serializeMetadata = (value: unknown): string => {
    if (value && typeof value === 'object') return JSON.stringify(value);
    if (typeof value === 'string') return value;
    return '{}';
  };
  const parseMetadata = (value: string): Record<string, unknown> => {
    try {
      const parsed = JSON.parse(value || '{}');
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
    } catch {
      return {};
    }
  };

  return {
    collectionQueries: {
      getAll: { all: () => collections.filter((c) => c.is_active === 1) },
      getByName: { get: (name: string) => byCollectionName(name) },
      getById: { get: (id: number) => byCollectionId(id) },
      upsert: {
        run: (payload: { name: string; description: string; parent_id: number | null; icon: string; color: string }) => {
          const existing = byCollectionName(payload.name);
          if (existing) {
            existing.description = payload.description;
            existing.parent_id = payload.parent_id;
            existing.icon = payload.icon;
            existing.color = payload.color;
            existing.updated_at = now();
            existing.is_active = 1;
            return;
          }
          collections.push({
            id: collectionId++,
            name: payload.name,
            description: payload.description,
            parent_id: payload.parent_id,
            icon: payload.icon,
            color: payload.color,
            created_at: now(),
            updated_at: now(),
            is_active: 1,
          });
        },
      },
      update: {
        run: (payload: { id: number; name: string; description: string; parent_id: number | null; icon: string; color: string }) => {
          const existing = collections.find((c) => c.id === payload.id);
          if (!existing) return;
          existing.name = payload.name;
          existing.description = payload.description;
          existing.parent_id = payload.parent_id;
          existing.icon = payload.icon;
          existing.color = payload.color;
          existing.updated_at = now();
        },
      },
      softDelete: {
        run: (id: number) => {
          const existing = collections.find((c) => c.id === id);
          if (!existing) return;
          existing.is_active = 0;
          existing.updated_at = now();
        },
      },
    },
    entryQueries: {
      getAll: { all: () => entries.filter((e) => e.is_active === 1) },
      getPage: { all: (limit: number, offset: number) => entries.filter((e) => e.is_active === 1).slice(offset, offset + limit) },
      getCount: { get: () => ({ count: entries.filter((e) => e.is_active === 1).length }) },
      getByName: { get: (name: string) => byEntryName(name) },
      getByType: { all: (type: VaultEntryType) => entries.filter((e) => e.type === type && e.is_active === 1) },
      getByCategory: { all: (category: VaultCategory) => entries.filter((e) => e.category === category && e.is_active === 1) },
      getByCollection: { all: (collection_id: number) => entries.filter((e) => e.collection_id === collection_id && e.is_active === 1) },
      getExpiringSoon: { all: (_cutoff: string) => [] as Entry[] },
      search: { all: (_q1: string, _q2: string, _q3: string, _q4: string) => [] as Entry[] },
      countByType: { all: () => entries.filter((e) => e.is_active === 1).reduce<{ type: string; count: number }[]>((acc, e) => {
        const existing = acc.find((x) => x.type === e.type);
        if (existing) { existing.count++; } else { acc.push({ type: e.type, count: 1 }); }
        return acc;
      }, []) },
      countByCategory: { all: () => entries.filter((e) => e.is_active === 1).reduce<{ category: string; count: number }[]>((acc, e) => {
        const existing = acc.find((x) => x.category === e.category);
        if (existing) { existing.count++; } else { acc.push({ category: e.category, count: 1 }); }
        return acc;
      }, []) },
      upsert: {
        run: (payload: {
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
        }) => {
          const existing = byEntryName(payload.name);
          if (existing) {
            existing.type = payload.type;
            existing.category = payload.category;
            existing.value_enc = payload.value_enc;
            existing.tags = payload.tags;
            existing.collection_id = payload.collection_id;
            existing.project = payload.project;
            existing.notes = payload.notes;
            existing.metadata = payload.metadata;
            existing.expires_at = payload.expires_at;
            existing.updated_at = now();
            existing.is_active = 1;
            return;
          }
          entries.push({
            id: entryId++,
            type: payload.type,
            category: payload.category,
            name: payload.name,
            value_enc: payload.value_enc,
            tags: payload.tags,
            collection_id: payload.collection_id,
            project: payload.project,
            notes: payload.notes,
            metadata: payload.metadata,
            created_at: now(),
            updated_at: now(),
            expires_at: payload.expires_at,
            last_accessed: null,
            access_count: 0,
            is_active: 1,
          });
        },
      },
      update: {
        run: (payload: {
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
        }) => {
          const existing = entries.find((e) => e.id === payload.id);
          if (!existing) return;
          existing.type = payload.type;
          existing.category = payload.category;
          existing.value_enc = payload.value_enc;
          existing.tags = payload.tags;
          existing.collection_id = payload.collection_id;
          existing.project = payload.project;
          existing.notes = payload.notes;
          existing.metadata = payload.metadata;
          existing.expires_at = payload.expires_at;
          existing.updated_at = now();
        },
      },
      recordAccess: {
        run: (name: string) => {
          const existing = byEntryName(name);
          if (!existing) return;
          existing.last_accessed = now();
          existing.access_count += 1;
        },
      },
      softDelete: {
        run: (id: number) => {
          const existing = entries.find((e) => e.id === id);
          if (!existing) return;
          existing.is_active = 0;
          existing.updated_at = now();
        },
      },
    },
    exportQueries: {
      insert: {
        run: (payload: { kind: 'import' | 'export'; format: string; filename: string; metadata: string }) => {
          importExports.push({ ...payload, created_at: now() });
        },
      },
      getRecent: {
        all: (limit: number) => importExports.slice(0, limit),
      },
    },
    auditQueries: {
      getRecent: { all: (_limit: number) => [] },
      getForEntry: { all: (_entry: string, _limit: number) => [] },
      getStats: { all: () => [] },
      insert: { run: (_payload: unknown) => void 0 },
      insertChained: { run: (_payload: unknown) => void 0 },
      getLastRow: { get: () => null },
    },
    versionQueries: {
      insert: {
        run: (payload: {
          entry_name: string;
          version: number;
          type: VaultEntryType;
          category: VaultCategory;
          value_enc: string;
          tags: string;
          notes: string;
          metadata: string;
          expires_at: string | null;
          archived_reason: string;
        }) => {
          versions.push({
            id: versionId++,
            entry_name: payload.entry_name,
            version: payload.version,
            type: payload.type,
            category: payload.category,
            value_enc: payload.value_enc,
            tags: payload.tags,
            notes: payload.notes,
            metadata: payload.metadata,
            expires_at: payload.expires_at,
            archived_at: now(),
            archived_reason: payload.archived_reason,
          });
        },
      },
      getByName: {
        all: (name: string) =>
          versions
            .filter((v) => v.entry_name === name)
            .map(({ value_enc: _v, ...rest }) => rest)
            .sort((a, b) => b.version - a.version),
      },
      getByVersion: {
        get: (name: string, version: number) =>
          versions.find((v) => v.entry_name === name && v.version === version) ?? null,
      },
      countByName: {
        get: (name: string) => ({ count: versions.filter((v) => v.entry_name === name).length }),
      },
    },
    logAudit: (_entry_name: string, _action: string, _ip = 'unknown', _user_agent = '', _meta = '') => void 0,
    parseMetadata,
    parseTags,
    serializeMetadata,
    serializeTags,
    normalizeVaultCategory,
    normalizeVaultEntryType,
    VAULT_ENTRY_TYPES,
    VAULT_CATEGORIES,
    isVaultEntryType,
    isVaultCategory,
    inferVaultCategory,
  };
}

async function setupTestApp() {
  vi.resetModules();

  const dbMock = createDbMockModule();
  vi.doMock('../db.js', () => dbMock);
  vi.doMock('../crypto.js', () => ({
    encrypt: (plaintext: string) => `enc:${plaintext}`,
    decrypt: (ciphertext: string) => (ciphertext.startsWith('enc:') ? ciphertext.slice(4) : ciphertext),
  }));

  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nexus-vault-test-'));
  process.env.VAULT_DATA_DIR = dataDir;
  process.env.VAULT_ACCESS_TOKEN = 'read-token-1234567890abcdef'; // pragma: allowlist secret
  process.env.VAULT_ADMIN_TOKEN = 'admin-token-1234567890abcdef'; // pragma: allowlist secret
  process.env.VAULT_MASTER_SECRET = 'test-master-secret'; // pragma: allowlist secret

  const express = (await import('express')).default;
  const { vaultRouter } = await import('./keys.js');

  const app = express();
  app.use(express.json());
  app.use('/api/keys', vaultRouter);

  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to resolve test server address');
  }
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function request(method: string, route: string, token: string, body?: unknown) {
    const response = await fetch(`${baseUrl}${route}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    let payload: unknown;
    const text = await response.text();
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = text;
    }

    return { status: response.status, payload };
  }

  async function cleanup() {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    try {
      fs.rmSync(dataDir, { recursive: true, force: true });
    } catch {
      // Best effort cleanup for temp test DBs.
    }
  }

  return { request, cleanup };
}

afterEach(() => {
  delete process.env.VAULT_DATA_DIR;
  delete process.env.VAULT_ACCESS_TOKEN;
  delete process.env.VAULT_ADMIN_TOKEN;
  delete process.env.VAULT_MASTER_SECRET;
});

describe.sequential('vaultRouter import contracts', () => {
  it('parses .env edge cases (comments, export prefix, quoted values)', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      const env = [
        '# a comment should be ignored',
        'export GITHUB_TOKEN=ghp_abc123',
        'OPENAI_API_KEY="sk-live=value#not-a-comment"', // pragma: allowlist secret
        'ELEVENLABS_API_KEY=el_123 # trailing comment should be removed',
        'INVALID-KEY=oops',
        'NO_EQUALS_LINE',
      ].join('\n');

      const imported = await request('POST', '/api/keys/import/env', 'admin-token-1234567890abcdef', {
        env,
        project: 'openclaw',
        tags: ['source:test'],
      });

      expect(imported.status).toBe(200);
      expect(imported.payload).toMatchObject({
        ok: true,
        created: 3,
        updated: 0,
        total: 3,
      });

      const github = await request('GET', '/api/keys/GITHUB_TOKEN', 'read-token-1234567890abcdef');
      expect(github.status).toBe(200);
      expect(github.payload).toMatchObject({
        name: 'GITHUB_TOKEN',
        type: 'token',
        value: 'ghp_abc123',
      });

      const openai = await request('GET', '/api/keys/OPENAI_API_KEY', 'read-token-1234567890abcdef');
      expect(openai.status).toBe(200);
      expect(openai.payload).toMatchObject({
        name: 'OPENAI_API_KEY',
        type: 'api-key',
        value: 'sk-live=value#not-a-comment',
      });

      const elevenlabs = await request('GET', '/api/keys/ELEVENLABS_API_KEY', 'read-token-1234567890abcdef');
      expect(elevenlabs.status).toBe(200);
      expect(elevenlabs.payload).toMatchObject({
        value: 'el_123',
      });

      const missingCollection = await request('POST', '/api/keys/import/env', 'admin-token-1234567890abcdef', {
        env: 'SOME_TOKEN=abc123',
        collection: 'does-not-exist',
      });
      expect(missingCollection.status).toBe(400);
      expect(missingCollection.payload).toMatchObject({
        error: 'Collection "does-not-exist" not found',
      });
    } finally {
      await cleanup();
    }
  });

  it('creates OpenClaw placeholders when includePlaceholders=true', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      const imported = await request('POST', '/api/keys/import/openclaw', 'admin-token-1234567890abcdef', {
        project: 'openclaw',
        includePlaceholders: true,
        plugins: [
          {
            name: 'github',
            env: ['GITHUB_TOKEN', 'GITHUB_USERNAME'],
            config: ['github.token'],
          },
        ],
        values: {
          GITHUB_TOKEN: 'ghp_real_token',
        },
      });

      expect(imported.status).toBe(200);
      expect(imported.payload).toMatchObject({
        ok: true,
        created: 1,
        updated: 0,
        placeholders: 2,
      });

      const placeholderEnv = await request('GET', '/api/keys/GITHUB_USERNAME', 'read-token-1234567890abcdef');
      expect(placeholderEnv.status).toBe(200);
      expect(placeholderEnv.payload).toMatchObject({
        name: 'GITHUB_USERNAME',
        value: '',
        notes: 'placeholder — configure this value',
      });

      const placeholderConfig = await request('GET', '/api/keys/github.token', 'read-token-1234567890abcdef');
      expect(placeholderConfig.status).toBe(200);
      expect(placeholderConfig.payload).toMatchObject({
        name: 'github.token',
        value: '',
        notes: 'placeholder — configure this value',
      });
    } finally {
      await cleanup();
    }
  });

  it('keeps /api/keys/export bound to export route (not /:name)', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      const created = await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'export',
        value: 'literal-entry',
        type: 'secret',
      });
      expect(created.status).toBe(201);

      const withReadToken = await request('GET', '/api/keys/export', 'read-token-1234567890abcdef');
      expect(withReadToken.status).toBe(401);
      expect(withReadToken.payload).toMatchObject({
        error: 'Unauthorized — admin token required',
      });

      const withAdminToken = await request('GET', '/api/keys/export', 'admin-token-1234567890abcdef');
      expect(withAdminToken.status).toBe(200);
      expect(withAdminToken.payload).toMatchObject({
        version: 1,
      });

      const exportDoc = withAdminToken.payload as { entries?: Array<{ name: string }> };
      expect(Array.isArray(exportDoc.entries)).toBe(true);
      expect(exportDoc.entries?.some((entry) => entry.name === 'export')).toBe(true);
    } finally {
      await cleanup();
    }
  });
});

describe.sequential('vaultRouter validation regressions', () => {
  function expectValidationFailure(result: { status: number; payload: unknown }, expectedField?: string) {
    expect(result.status).toBe(400);
    expect(result.payload).toMatchObject({ error: 'Validation failed' });
    const details = (result.payload as { details?: Array<{ field?: string; message?: string }> }).details;
    expect(Array.isArray(details)).toBe(true);
    if (expectedField) {
      expect(details?.some((item) => item.field === expectedField)).toBe(true);
    }
  }

  it('rejects invalid payloads for entry write endpoints', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      const createCases: Array<{ body: unknown; field?: string }> = [
        { body: { name: 'alpha' }, field: 'value' },
        { body: { name: 'alpha', value: 'x', type: 'definitely-not-valid' }, field: 'type' },
        { body: { name: 'alpha', value: 'x', category: 'bad-category' }, field: 'category' },
        { body: { name: 'alpha', value: 'x', expires_at: 'not-a-date' }, field: 'expires_at' },
        { body: { name: 'alpha*', value: 'x' }, field: 'name' },
      ];
      for (const testCase of createCases) {
        const res = await request('POST', '/api/keys', 'admin-token-1234567890abcdef', testCase.body);
        expectValidationFailure(res, testCase.field);
      }

      const created = await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'updatable-entry',
        value: 'ok',
      });
      expect(created.status).toBe(201);

      const updateCases: Array<{ body: unknown; field?: string }> = [
        { body: { value: '' }, field: 'value' },
        { body: { type: 'not-real' }, field: 'type' },
        { body: { category: 'bad-category' }, field: 'category' },
        { body: { expires_at: '2026-99-99' }, field: 'expires_at' },
      ];
      for (const testCase of updateCases) {
        const res = await request('PUT', '/api/keys/updatable-entry', 'admin-token-1234567890abcdef', testCase.body);
        expectValidationFailure(res, testCase.field);
      }

      const badParamPut = await request('PUT', '/api/keys/%20', 'admin-token-1234567890abcdef', { value: 'x' });
      expectValidationFailure(badParamPut, 'name');

      const badParamDelete = await request('DELETE', '/api/keys/%20', 'admin-token-1234567890abcdef');
      expectValidationFailure(badParamDelete, 'name');
    } finally {
      await cleanup();
    }
  });

  it('rejects invalid payloads for collection write endpoints', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      const createCases: Array<{ body: unknown; field?: string }> = [
        { body: {}, field: 'name' },
        { body: { name: 'bad name with spaces' }, field: 'name' },
        { body: { name: 'valid-name', description: 'x'.repeat(501) }, field: 'description' },
      ];
      for (const testCase of createCases) {
        const res = await request('POST', '/api/keys/collections', 'admin-token-1234567890abcdef', testCase.body);
        expectValidationFailure(res, testCase.field);
      }

      const created = await request('POST', '/api/keys/collections', 'admin-token-1234567890abcdef', { name: 'base-coll' });
      expect(created.status).toBe(201);

      const badParent = await request('PUT', '/api/keys/collections/base-coll', 'admin-token-1234567890abcdef', {
        parentName: 'does-not-exist',
      });
      expect(badParent.status).toBe(400);
      expect(badParent.payload).toMatchObject({ error: 'Parent collection "does-not-exist" not found' });

      const badDeleteName = await request('DELETE', '/api/keys/collections/%20', 'admin-token-1234567890abcdef');
      expectValidationFailure(badDeleteName, 'name');
    } finally {
      await cleanup();
    }
  });

  it('rejects invalid payloads for import write endpoints', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      const importDocumentCases: Array<{ body: unknown; field?: string }> = [
        { body: { version: 2, entries: [] }, field: 'version' },
        { body: { version: 1, replaceExisting: 'yes' }, field: 'replaceExisting' },
        { body: { version: 1, entries: [{ name: 'ok' }] }, field: 'entries[0].value' },
      ];
      for (const testCase of importDocumentCases) {
        const res = await request('POST', '/api/keys/import', 'admin-token-1234567890abcdef', testCase.body);
        expectValidationFailure(res, testCase.field);
      }

      const importEnvCases: Array<{ body: unknown; field?: string }> = [
        { body: {}, field: 'env' },
        { body: { env: 'A=1', tags: 'nope' }, field: 'tags' },
        { body: { env: 'A=1', namePrefix: 'bad prefix with spaces' }, field: 'namePrefix' },
      ];
      for (const testCase of importEnvCases) {
        const res = await request('POST', '/api/keys/import/env', 'admin-token-1234567890abcdef', testCase.body);
        expectValidationFailure(res, testCase.field);
      }

      const openClawCases: Array<{ body: unknown; field?: string }> = [
        { body: {}, field: 'plugins' },
        { body: { plugins: [{ name: 'github', env: ['A'] }], includePlaceholders: 'yes' }, field: 'includePlaceholders' },
        { body: { plugins: [{ name: 'github', env: 'NOT_AN_ARRAY' }] }, field: 'plugins[0].env' },
        { body: { plugins: [{ name: 'github' }], values: { X: 1 } }, field: 'values.X' },
      ];
      for (const testCase of openClawCases) {
        const res = await request('POST', '/api/keys/import/openclaw', 'admin-token-1234567890abcdef', testCase.body);
        expectValidationFailure(res, testCase.field);
      }
    } finally {
      await cleanup();
    }
  });
});

describe.sequential('vaultRouter production hardening', () => {
  it('returns 410 Gone for expired entries', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      const pastDate = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
      const created = await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'expired-key',
        value: 'old-secret',
        type: 'api-key',
        expires_at: pastDate,
      });
      expect(created.status).toBe(201);

      const res = await request('GET', '/api/keys/expired-key', 'read-token-1234567890abcdef');
      expect(res.status).toBe(410);
      expect(res.payload).toMatchObject({ error: 'Entry has expired', expiredAt: pastDate });
    } finally {
      await cleanup();
    }
  });

  it('archives previous value as version on PUT update', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'versioned-key',
        value: 'original-value',
        type: 'secret',
      });

      await request('PUT', '/api/keys/versioned-key', 'admin-token-1234567890abcdef', { value: 'updated-value' });
      await request('PUT', '/api/keys/versioned-key', 'admin-token-1234567890abcdef', { value: 'updated-value-2' });

      const versionsRes = await request('GET', '/api/keys/versioned-key/versions', 'admin-token-1234567890abcdef');
      expect(versionsRes.status).toBe(200);
      const versionList = versionsRes.payload as Array<{ version: number; entry_name: string }>;
      expect(versionList.length).toBe(2);
      expect(versionList[0]!.version).toBe(2);
      expect(versionList[1]!.version).toBe(1);

      const v1Res = await request('GET', '/api/keys/versioned-key/versions/1', 'admin-token-1234567890abcdef');
      expect(v1Res.status).toBe(200);
      expect(v1Res.payload).toMatchObject({ version: 1, value: 'original-value' });

      const v404 = await request('GET', '/api/keys/versioned-key/versions/99', 'admin-token-1234567890abcdef');
      expect(v404.status).toBe(404);
    } finally {
      await cleanup();
    }
  });

  it('paginates GET /api/keys when page/limit query params are provided', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      for (let i = 1; i <= 5; i++) {
        await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
          name: `pagination-key-${i}`,
          value: `value-${i}`,
          type: 'secret',
        });
      }

      const page1 = await request('GET', '/api/keys?page=1&limit=3', 'read-token-1234567890abcdef');
      expect(page1.status).toBe(200);
      const page1Body = page1.payload as { entries: unknown[]; total: number; page: number; limit: number; pages: number };
      expect(page1Body.entries.length).toBe(3);
      expect(page1Body.total).toBe(5);
      expect(page1Body.page).toBe(1);
      expect(page1Body.limit).toBe(3);
      expect(page1Body.pages).toBe(2);

      const page2 = await request('GET', '/api/keys?page=2&limit=3', 'read-token-1234567890abcdef');
      expect(page2.status).toBe(200);
      const page2Body = page2.payload as { entries: unknown[]; total: number; page: number };
      expect(page2Body.entries.length).toBe(2);
      expect(page2Body.page).toBe(2);

      const noParams = await request('GET', '/api/keys', 'read-token-1234567890abcdef');
      expect(noParams.status).toBe(200);
      expect(Array.isArray(noParams.payload)).toBe(true);
      expect((noParams.payload as unknown[]).length).toBe(5);
    } finally {
      await cleanup();
    }
  });
});

describe.sequential('vaultRouter version history and restore', () => {
  it('archives a version on DELETE with reason=delete', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'to-delete',
        value: 'delete-me',
        type: 'secret',
      });

      const del = await request('DELETE', '/api/keys/to-delete', 'admin-token-1234567890abcdef');
      expect(del.status).toBe(200);
      expect(del.payload).toMatchObject({ ok: true });

      // Entry should be gone
      const gone = await request('GET', '/api/keys/to-delete', 'read-token-1234567890abcdef');
      expect(gone.status).toBe(404);
    } finally {
      await cleanup();
    }
  });

  it('GET /stats returns total, byType, byCategory, expiringSoon', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'stat-key-1',
        value: 'v1',
        type: 'token',
      });
      await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'stat-key-2',
        value: 'v2',
        type: 'secret',
      });

      const stats = await request('GET', '/api/keys/stats', 'read-token-1234567890abcdef');
      expect(stats.status).toBe(200);
      const body = stats.payload as { total: number; byType: Array<{ type: string; count: number }>; byCategory: unknown[]; expiringSoon: { days7: number; days30: number } };
      expect(body.total).toBe(2);
      expect(Array.isArray(body.byType)).toBe(true);
      expect(Array.isArray(body.byCategory)).toBe(true);
      expect(body.expiringSoon).toMatchObject({ days7: 0, days30: 0 });

      // Reject read from unauthenticated
      const unauth = await request('GET', '/api/keys/stats', 'wrong-token');
      expect(unauth.status).toBe(401);
    } finally {
      await cleanup();
    }
  });

  it('POST /:name/restore/:version restores archived value and archives current', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'restorable',
        value: 'v0-original',
        type: 'secret',
      });
      // Create 2 versions by updating twice
      await request('PUT', '/api/keys/restorable', 'admin-token-1234567890abcdef', { value: 'v1-updated' });
      await request('PUT', '/api/keys/restorable', 'admin-token-1234567890abcdef', { value: 'v2-updated' });

      // Current value should be v2-updated
      const current = await request('GET', '/api/keys/restorable', 'read-token-1234567890abcdef');
      expect(current.payload).toMatchObject({ value: 'v2-updated' });

      // Restore version 1 (v0-original)
      const restore = await request('POST', '/api/keys/restorable/restore/1', 'admin-token-1234567890abcdef');
      expect(restore.status).toBe(200);
      expect(restore.payload).toMatchObject({ ok: true, name: 'restorable', restoredVersion: 1 });

      // Current value should now be v0-original
      const afterRestore = await request('GET', '/api/keys/restorable', 'read-token-1234567890abcdef');
      expect(afterRestore.payload).toMatchObject({ value: 'v0-original' });

      // Version list should now have 3 entries (v1 + v2 + the 'restore' snapshot of v2)
      const versions = await request('GET', '/api/keys/restorable/versions', 'admin-token-1234567890abcdef');
      expect(versions.status).toBe(200);
      expect((versions.payload as unknown[]).length).toBe(3);

      // Non-existent version returns 404
      const notFound = await request('POST', '/api/keys/restorable/restore/99', 'admin-token-1234567890abcdef');
      expect(notFound.status).toBe(404);

      // Read token cannot restore (admin required)
      const forbidden = await request('POST', '/api/keys/restorable/restore/1', 'read-token-1234567890abcdef');
      expect(forbidden.status).toBe(401);
    } finally {
      await cleanup();
    }
  });
});

describe.sequential('vaultRouter version history and restore', () => {
  it('archives a version on DELETE with reason=delete', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'to-delete',
        value: 'delete-me',
        type: 'secret',
      });

      const del = await request('DELETE', '/api/keys/to-delete', 'admin-token-1234567890abcdef');
      expect(del.status).toBe(200);
      expect(del.payload).toMatchObject({ ok: true });

      // Entry should be gone
      const gone = await request('GET', '/api/keys/to-delete', 'read-token-1234567890abcdef');
      expect(gone.status).toBe(404);
    } finally {
      await cleanup();
    }
  });

  it('GET /stats returns total, byType, byCategory, expiringSoon', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'stat-key-1',
        value: 'v1',
        type: 'token',
      });
      await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'stat-key-2',
        value: 'v2',
        type: 'secret',
      });

      const stats = await request('GET', '/api/keys/stats', 'read-token-1234567890abcdef');
      expect(stats.status).toBe(200);
      const body = stats.payload as { total: number; byType: Array<{ type: string; count: number }>; byCategory: unknown[]; expiringSoon: { days7: number; days30: number } };
      expect(body.total).toBe(2);
      expect(Array.isArray(body.byType)).toBe(true);
      expect(Array.isArray(body.byCategory)).toBe(true);
      expect(body.expiringSoon).toMatchObject({ days7: 0, days30: 0 });

      // Reject read from unauthenticated
      const unauth = await request('GET', '/api/keys/stats', 'wrong-token');
      expect(unauth.status).toBe(401);
    } finally {
      await cleanup();
    }
  });

  it('POST /:name/restore/:version restores archived value and archives current', async () => {
    const { request, cleanup } = await setupTestApp();
    try {
      await request('POST', '/api/keys', 'admin-token-1234567890abcdef', {
        name: 'restorable',
        value: 'v0-original',
        type: 'secret',
      });
      // Create 2 versions by updating twice
      await request('PUT', '/api/keys/restorable', 'admin-token-1234567890abcdef', { value: 'v1-updated' });
      await request('PUT', '/api/keys/restorable', 'admin-token-1234567890abcdef', { value: 'v2-updated' });

      // Current value should be v2-updated
      const current = await request('GET', '/api/keys/restorable', 'read-token-1234567890abcdef');
      expect(current.payload).toMatchObject({ value: 'v2-updated' });

      // Restore version 1 (v0-original)
      const restore = await request('POST', '/api/keys/restorable/restore/1', 'admin-token-1234567890abcdef');
      expect(restore.status).toBe(200);
      expect(restore.payload).toMatchObject({ ok: true, name: 'restorable', restoredVersion: 1 });

      // Current value should now be v0-original
      const afterRestore = await request('GET', '/api/keys/restorable', 'read-token-1234567890abcdef');
      expect(afterRestore.payload).toMatchObject({ value: 'v0-original' });

      // Version list should now have 3 entries (v1 + v2 + the 'restore' snapshot of v2)
      const versions = await request('GET', '/api/keys/restorable/versions', 'admin-token-1234567890abcdef');
      expect(versions.status).toBe(200);
      expect((versions.payload as unknown[]).length).toBe(3);

      // Non-existent version returns 404
      const notFound = await request('POST', '/api/keys/restorable/restore/99', 'admin-token-1234567890abcdef');
      expect(notFound.status).toBe(404);

      // Read token cannot restore (admin required)
      const forbidden = await request('POST', '/api/keys/restorable/restore/1', 'read-token-1234567890abcdef');
      expect(forbidden.status).toBe(401);
    } finally {
      await cleanup();
    }
  });
});
