import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Server } from 'http';

async function setupOpsTestApp() {
  vi.resetModules();

  vi.doMock('../db.js', () => ({
    logAudit: vi.fn(),
    getDatabaseMaintenanceState: vi.fn(() => ({ running: false, lastCompletedAt: null })),
    runDatabaseMaintenance: vi.fn((operation: 'VACUUM' | 'ANALYZE') => ({
      operation,
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: 12,
    })),
  }));

  vi.doMock('../metrics.js', () => ({
    incCounter: vi.fn(),
  }));

  vi.doMock('../ops.js', () => ({
    backupDirPath: () => './backups',
    databasePath: () => './data/vault.db',
    listBackups: () => [
      {
        filename: 'vault-2026-04-16.db',
        bytes: 123,
        createdAt: new Date().toISOString(),
        sha256: 'a'.repeat(64),
      },
    ],
    createBackup: async (filename?: string) => ({
      filename: filename || 'vault-2026-04-16.db',
      bytes: 123,
      createdAt: new Date().toISOString(),
      sha256: 'a'.repeat(64),
      encrypted: false,
      encryptionMode: 'none',
    }),
    enforceBackupRetention: () => ({ deleted: [], kept: 1 }),
    verifyBackupChecksum: () => ({ ok: true, expected: 'a'.repeat(64), actual: 'a'.repeat(64) }),
    createSignedBackupToken: (_action: string, _filename: string, _expires: number) => 'token-123',
    verifySignedBackupToken: () => ({ action: 'backup-download', filename: 'vault-2026-04-16.db', exp: Math.floor(Date.now() / 1000) + 300 }),
    writeUploadedBackup: async () => ({
      filename: 'vault-upload.db',
      bytes: 123,
      createdAt: new Date().toISOString(),
      sha256: 'a'.repeat(64),
      encrypted: false,
      encryptionMode: 'none',
    }),
    restoreBackup: (filename: string) => ({
      restored: filename,
      rows: {
        collections: 1,
        entries: 1,
        importsExports: 0,
        auditEvents: 0,
        auditVerificationRuns: 0,
      },
    }),
    restoreBackupDrill: (filename: string) => ({
      drill: filename,
      rows: {
        collections: 1,
        entries: 1,
        importsExports: 0,
        auditEvents: 0,
        auditVerificationRuns: 0,
      },
      integrityOk: true,
      integrityMessage: 'ok',
      encrypted: false,
      encryptionMode: 'none',
    }),
  }));

  process.env.VAULT_ACCESS_TOKEN = 'read-token-1234567890abcdef';
  process.env.VAULT_ADMIN_TOKEN = 'admin-token-1234567890abcdef';
  process.env.VAULT_MASTER_SECRET = 'test-master-secret';

  const express = (await import('express')).default;
  const { opsRouter } = await import('./ops.js');

  const app = express();
  app.use(express.json());
  app.use('/api/ops', opsRouter);

  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to resolve test server address');
  }
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function request(method: string, route: string, token?: string, body?: unknown) {
    const response = await fetch(`${baseUrl}${route}`, {
      method,
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
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
  }

  return { request, cleanup };
}

afterEach(() => {
  delete process.env.VAULT_ACCESS_TOKEN;
  delete process.env.VAULT_ADMIN_TOKEN;
  delete process.env.VAULT_MASTER_SECRET;
  delete process.env.VAULT_DB_MAINTENANCE_MIN_INTERVAL_SECONDS;
});

describe.sequential('opsRouter operational APIs', () => {
  it('requires admin token for backup inventory', async () => {
    const { request, cleanup } = await setupOpsTestApp();
    try {
      const result = await request('GET', '/api/ops/backups', 'read-token-1234567890abcdef');
      expect(result.status).toBe(401);
      expect(result.payload).toMatchObject({ error: 'Unauthorized — admin token required' });
    } finally {
      await cleanup();
    }
  });

  it('creates signed download token', async () => {
    const { request, cleanup } = await setupOpsTestApp();
    try {
      const result = await request(
        'POST',
        '/api/ops/backups/sign-download',
        'admin-token-1234567890abcdef',
        { filename: 'vault-2026-04-16.db', expiresSeconds: 120 }
      );
      expect(result.status).toBe(200);
      expect(result.payload).toMatchObject({
        token: 'token-123',
        downloadUrl: '/api/ops/backups/download?token=token-123',
      });
    } finally {
      await cleanup();
    }
  });

  it('validates restore payload', async () => {
    const { request, cleanup } = await setupOpsTestApp();
    try {
      const bad = await request('POST', '/api/ops/backups/restore', 'admin-token-1234567890abcdef', {});
      expect(bad.status).toBe(400);
      expect(bad.payload).toMatchObject({ error: 'filename is required' });

      const missingConfirm = await request(
        'POST',
        '/api/ops/backups/restore',
        'admin-token-1234567890abcdef',
        { filename: 'vault-2026-04-16.db', verifyChecksum: true }
      );
      expect(missingConfirm.status).toBe(400);
      expect(missingConfirm.payload).toMatchObject({
        error: 'restore confirmation mismatch',
        expectedConfirm: 'RESTORE vault-2026-04-16.db',
      });

      const ok = await request(
        'POST',
        '/api/ops/backups/restore',
        'admin-token-1234567890abcdef',
        {
          filename: 'vault-2026-04-16.db',
          verifyChecksum: true,
          confirm: 'RESTORE vault-2026-04-16.db',
        }
      );
      expect(ok.status).toBe(200);
      expect(ok.payload).toMatchObject({ ok: true, restored: 'vault-2026-04-16.db' });
    } finally {
      await cleanup();
    }
  });

  it('supports restore drill mode without mutation', async () => {
    const { request, cleanup } = await setupOpsTestApp();
    try {
      const bad = await request('POST', '/api/ops/backups/restore-drill', 'admin-token-1234567890abcdef', {
        filename: 'vault-2026-04-16.db',
      });
      expect(bad.status).toBe(400);
      expect(bad.payload).toMatchObject({
        error: 'restore drill confirmation mismatch',
        expectedConfirm: 'DRILL vault-2026-04-16.db',
      });

      const ok = await request('POST', '/api/ops/backups/restore-drill', 'admin-token-1234567890abcdef', {
        filename: 'vault-2026-04-16.db',
        verifyChecksum: true,
        confirm: 'DRILL vault-2026-04-16.db',
      });
      expect(ok.status).toBe(200);
      expect(ok.payload).toMatchObject({ ok: true, drill: 'vault-2026-04-16.db', integrityOk: true });
    } finally {
      await cleanup();
    }
  });

  it('allows maintenance mode toggle and state readback', async () => {
    const { request, cleanup } = await setupOpsTestApp();
    try {
      const enable = await request(
        'POST',
        '/api/ops/maintenance',
        'admin-token-1234567890abcdef',
        { enabled: true, reason: 'planned upgrade' }
      );
      expect(enable.status).toBe(200);
      expect(enable.payload).toMatchObject({
        ok: true,
        state: {
          maintenanceMode: true,
          maintenanceReason: 'planned upgrade',
        },
      });

      const state = await request('GET', '/api/ops/state', 'admin-token-1234567890abcdef');
      expect(state.status).toBe(200);
      expect(state.payload).toMatchObject({
        state: {
          maintenanceMode: true,
          maintenanceReason: 'planned upgrade',
        },
      });
    } finally {
      await cleanup();
    }
  });

  it('runs guarded database maintenance', async () => {
    const { request, cleanup } = await setupOpsTestApp();
    try {
      const vacuumBlocked = await request('POST', '/api/ops/db/maintenance', 'admin-token-1234567890abcdef', {
        operation: 'VACUUM',
        confirm: 'MAINTAIN VACUUM',
      });
      expect(vacuumBlocked.status).toBe(409);

      await request('POST', '/api/ops/maintenance', 'admin-token-1234567890abcdef', { enabled: true, reason: 'db maintenance' });

      const run = await request('POST', '/api/ops/db/maintenance', 'admin-token-1234567890abcdef', {
        operation: 'VACUUM',
        confirm: 'MAINTAIN VACUUM',
        reason: 'periodic vacuum',
      });
      expect(run.status).toBe(200);
      expect(run.payload).toMatchObject({ ok: true, result: { operation: 'VACUUM' } });
    } finally {
      await cleanup();
    }
  });

  it('rotates tokens atomically and old admin token stops working', async () => {
    const { request, cleanup } = await setupOpsTestApp();
    try {
      const rotate = await request(
        'POST',
        '/api/ops/tokens/rotate',
        'admin-token-1234567890abcdef',
        {
          mode: 'replace',
          adminTokens: ['new-admin-token-1234567890abcdef'],
        }
      );
      expect(rotate.status).toBe(200);
      expect(rotate.payload).toMatchObject({ ok: true, adminCount: 1 });

      const oldTokenState = await request('GET', '/api/ops/state', 'admin-token-1234567890abcdef');
      expect(oldTokenState.status).toBe(401);

      const newTokenState = await request('GET', '/api/ops/state', 'new-admin-token-1234567890abcdef');
      expect(newTokenState.status).toBe(200);
    } finally {
      await cleanup();
    }
  });
});
