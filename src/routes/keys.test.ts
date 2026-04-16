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
  const collections: Collection[] = [];
  const entries: Entry[] = [];
  const importExports: Array<{ kind: string; format: string; filename: string; metadata: string; created_at: string }> = [];
  let collectionId = 1;
  let entryId = 1;

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
      getAll: { all: () => entries },
      getByName: { get: (name: string) => byEntryName(name) },
      getByType: { all: (type: VaultEntryType) => entries.filter((e) => e.type === type && e.is_active === 1) },
      getByCategory: { all: (category: VaultCategory) => entries.filter((e) => e.category === category && e.is_active === 1) },
      getByCollection: { all: (collection_id: number) => entries.filter((e) => e.collection_id === collection_id && e.is_active === 1) },
      getExpiringSoon: { all: (_cutoff: string) => [] as Entry[] },
      search: { all: (_q1: string, _q2: string, _q3: string, _q4: string) => [] as Entry[] },
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
  process.env.VAULT_ACCESS_TOKEN = 'read-token-1234567890abcdef';
  process.env.VAULT_ADMIN_TOKEN = 'admin-token-1234567890abcdef';
  process.env.VAULT_MASTER_SECRET = 'test-master-secret';

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
        'OPENAI_API_KEY="sk-live=value#not-a-comment"',
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
