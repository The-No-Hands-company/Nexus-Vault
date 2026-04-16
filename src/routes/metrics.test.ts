import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Server } from 'http';

async function setupMetricsTestApp() {
  vi.resetModules();

  process.env.VAULT_ACCESS_TOKEN = 'read-token-1234567890abcdef';
  process.env.VAULT_ADMIN_TOKEN = 'admin-token-1234567890abcdef';
  process.env.VAULT_MASTER_SECRET = 'test-master-secret';
  delete process.env.VAULT_METRICS_PUBLIC;

  const { incCounter, resetMetricsForTests } = await import('../metrics.js');
  resetMetricsForTests();
  incCounter('vault_ops_backup_create_total', 'Total backup create operations', 2, { result: 'ok' });

  const express = (await import('express')).default;
  const { metricsRouter } = await import('./metrics.js');

  const app = express();
  app.use('/api', metricsRouter);

  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to resolve test server address');
  }
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function request(path: string, token?: string) {
    const response = await fetch(`${baseUrl}${path}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    });
    const text = await response.text();
    let payload: unknown = text;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      // text response
    }
    return { status: response.status, payload, text };
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
  delete process.env.VAULT_METRICS_PUBLIC;
});

describe.sequential('metricsRouter', () => {
  it('requires admin token when metrics are not public', async () => {
    const { request, cleanup } = await setupMetricsTestApp();
    try {
      const unauthorized = await request('/api/metrics');
      expect(unauthorized.status).toBe(401);

      const authorized = await request('/api/metrics', 'admin-token-1234567890abcdef');
      expect(authorized.status).toBe(200);
      expect(authorized.text).toContain('vault_ops_backup_create_total');
    } finally {
      await cleanup();
    }
  });

  it('returns OTel JSON format when requested', async () => {
    const { request, cleanup } = await setupMetricsTestApp();
    try {
      const response = await request('/api/metrics?format=otel', 'admin-token-1234567890abcdef');
      expect(response.status).toBe(200);
      expect(response.payload).toMatchObject({
        resource: { service: { name: 'nexus-vault' } },
        metrics: expect.any(Array),
      });
    } finally {
      await cleanup();
    }
  });
});
