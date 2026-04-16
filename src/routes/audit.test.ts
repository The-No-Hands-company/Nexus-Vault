import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Server } from 'http';

async function setupAuditTestApp(opts: { brokenChain?: boolean } = {}) {
  vi.resetModules();

  const auditRows = [
    {
      id: 1,
      entry_name: 'alpha',
      action: 'CREATE',
      ip: '127.0.0.1',
      user_agent: 'vitest',
      meta: '{}',
      timestamp: new Date().toISOString(),
      prev_hash: 'genesis',
    },
  ];

  vi.doMock('../db.js', () => ({
    auditQueries: {
      getRecent: {
        all: (limit: number) => auditRows.slice(0, limit),
      },
      getStats: {
        all: () => [{ entry_name: 'alpha', access_count: 3, last_accessed: new Date().toISOString() }],
      },
      getForEntry: {
        all: (entry: string, limit: number) => auditRows.filter((row) => row.entry_name === entry).slice(0, limit),
      },
    },
    verifyAuditChain: () => {
      if (opts.brokenChain) {
        return {
          ok: false as const,
          brokenAt: 1,
          expected: 'expected-hash',
          got: 'tampered-hash',
        };
      }
      return { ok: true as const };
    },
    getAuditChainStatus: () => ({
      totalEntries: auditRows.length,
      headId: auditRows[0]?.id ?? null,
      headHash: 'head-hash-123',
      genesisOk: true,
    }),
    listAuditVerificationRuns: (limit: number) => [
      {
        id: 1,
        source: 'periodic',
        ok: 1,
        broken_at: null,
        expected_hash: null,
        got_hash: null,
        total_entries: 1,
        head_id: 1,
        head_hash: 'head-hash-123',
        genesis_ok: 1,
        details: 'ok',
        alert_sent: 0,
        created_at: new Date().toISOString(),
      },
    ].slice(0, limit),
  }));

  vi.doMock('../periodic-verify.js', () => ({
    getLastVerificationResult: () => ({
      timestamp: new Date().toISOString(),
      ok: true,
      status: {
        totalEntries: 1,
        headId: 1,
        headHash: 'head-hash-123',
        genesisOk: true,
      },
      verification: { ok: true as const },
      details: 'ok',
    }),
    performVerification: async () => ({
      timestamp: new Date().toISOString(),
      ok: opts.brokenChain ? false : true,
      status: {
        totalEntries: 1,
        headId: 1,
        headHash: 'head-hash-123',
        genesisOk: true,
      },
      verification: opts.brokenChain
        ? { ok: false as const, brokenAt: 1, expected: 'expected-hash', got: 'tampered-hash' }
        : { ok: true as const },
      details: opts.brokenChain ? 'broken' : 'ok',
    }),
  }));

  process.env.VAULT_ACCESS_TOKEN = 'read-token-1234567890abcdef';
  process.env.VAULT_ADMIN_TOKEN = 'admin-token-1234567890abcdef';
  process.env.VAULT_MASTER_SECRET = 'test-master-secret';

  const express = (await import('express')).default;
  const { auditRouter } = await import('./audit.js');

  const app = express();
  app.use(express.json());
  app.use('/api/audit', auditRouter);

  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to resolve test server address');
  }
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function request(method: string, route: string, token: string) {
    const response = await fetch(`${baseUrl}${route}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
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

async function setupAuditPersistenceTestApp() {
  vi.resetModules();
  vi.doUnmock('../db.js');
  vi.doUnmock('../periodic-verify.js');
  vi.doUnmock('../mail.js');

  const verificationHistory: Array<{
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
  }> = [];

  vi.doMock('../db.js', () => {
    let nextId = 1;
    return {
      auditQueries: {
        getRecent: { all: (_limit: number) => [] },
        getStats: { all: () => [] },
        getForEntry: { all: (_entry: string, _limit: number) => [] },
      },
      getAuditChainStatus: () => ({
        totalEntries: 0,
        headId: null,
        headHash: null,
        genesisOk: true,
      }),
      verifyAuditChain: () => ({ ok: true as const }),
      recordAuditVerificationRun: (input: {
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
      }) => {
        verificationHistory.unshift({
          id: nextId++,
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
          created_at: new Date().toISOString(),
        });
      },
      getLastAuditVerificationRun: () => verificationHistory[0] ?? null,
      listAuditVerificationRuns: (limit: number) => verificationHistory.slice(0, limit),
    };
  });

  vi.doMock('../mail.js', () => ({
    sendAuditFailureEmail: async () => true,
  }));

  process.env.VAULT_ACCESS_TOKEN = 'read-token-1234567890abcdef';
  process.env.VAULT_ADMIN_TOKEN = 'admin-token-1234567890abcdef';
  process.env.VAULT_MASTER_SECRET = 'test-master-secret';

  const express = (await import('express')).default;
  const { auditRouter } = await import('./audit.js');

  const app = express();
  app.use(express.json());
  app.use('/api/audit', auditRouter);

  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to resolve test server address');
  }
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function request(method: string, route: string, token: string) {
    const response = await fetch(`${baseUrl}${route}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
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
});

describe.sequential('auditRouter verification regressions', () => {
  it('requires admin token for chain verification', async () => {
    const { request, cleanup } = await setupAuditTestApp();
    try {
      const result = await request('GET', '/api/audit/verify', 'read-token-1234567890abcdef');
      expect(result.status).toBe(401);
      expect(result.payload).toMatchObject({ error: 'Unauthorized — admin token required' });
    } finally {
      await cleanup();
    }
  });

  it('returns 200 when audit chain is intact', async () => {
    const { request, cleanup } = await setupAuditTestApp({ brokenChain: false });
    try {
      const result = await request('GET', '/api/audit/verify', 'admin-token-1234567890abcdef');
      expect(result.status).toBe(200);
      expect(result.payload).toMatchObject({ ok: true });
    } finally {
      await cleanup();
    }
  });

  it('returns 409 when audit chain is broken', async () => {
    const { request, cleanup } = await setupAuditTestApp({ brokenChain: true });
    try {
      const result = await request('GET', '/api/audit/verify', 'admin-token-1234567890abcdef');
      expect(result.status).toBe(409);
      expect(result.payload).toMatchObject({
        ok: false,
        brokenAt: 1,
        expected: 'expected-hash',
        got: 'tampered-hash',
        totalEntries: 1,
        headId: 1,
        headHash: 'head-hash-123',
        genesisOk: true,
      });
    } finally {
      await cleanup();
    }
  });

  it('returns chain status without full verification scan', async () => {
    const { request, cleanup } = await setupAuditTestApp();
    try {
      const result = await request('GET', '/api/audit/chain', 'admin-token-1234567890abcdef');
      expect(result.status).toBe(200);
      expect(result.payload).toMatchObject({
        totalEntries: 1,
        headId: 1,
        headHash: 'head-hash-123',
        genesisOk: true,
      });
    } finally {
      await cleanup();
    }
  });

  it('returns persisted verification history', async () => {
    const { request, cleanup } = await setupAuditTestApp();
    try {
      const result = await request('GET', '/api/audit/verification-history', 'admin-token-1234567890abcdef');
      expect(result.status).toBe(200);
      expect(result.payload).toMatchObject([
        {
          id: 1,
          source: 'periodic',
          ok: 1,
          total_entries: 1,
        },
      ]);
    } finally {
      await cleanup();
    }
  });

  it('triggers on-demand verification run', async () => {
    const { request, cleanup } = await setupAuditTestApp({ brokenChain: false });
    try {
      const result = await request('POST', '/api/audit/verify-now', 'admin-token-1234567890abcdef');
      expect(result.status).toBe(200);
      expect(result.payload).toMatchObject({ ok: true });
    } finally {
      await cleanup();
    }
  });

  it('persists a new verification run when verify-now is triggered', async () => {
    const { request, cleanup } = await setupAuditPersistenceTestApp();
    try {
      const before = await request('GET', '/api/audit/verification-history?limit=5', 'admin-token-1234567890abcdef');
      expect(before.status).toBe(200);
      expect(Array.isArray(before.payload)).toBe(true);
      expect((before.payload as unknown[]).length).toBe(0);

      const run = await request('POST', '/api/audit/verify-now', 'admin-token-1234567890abcdef');
      expect(run.status).toBe(200);
      expect(run.payload).toMatchObject({ ok: true });

      const after = await request('GET', '/api/audit/verification-history?limit=5', 'admin-token-1234567890abcdef');
      expect(after.status).toBe(200);
      expect(after.payload).toMatchObject([
        {
          source: 'manual',
          ok: 1,
          total_entries: 0,
          genesis_ok: 1,
        },
      ]);
      expect((after.payload as unknown[]).length).toBe(1);
    } finally {
      await cleanup();
    }
  });
});
