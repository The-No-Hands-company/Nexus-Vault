import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Server } from 'http';

async function setupConfigTestApp() {
  vi.resetModules();

  process.env.VAULT_ACCESS_TOKEN = 'read-token-1234567890abcdef';
  process.env.VAULT_ADMIN_TOKEN = 'admin-token-1234567890abcdef';
  process.env.VAULT_MASTER_SECRET = 'test-master-secret';
  process.env.VAULT_BACKUP_RETENTION_COUNT = '12';
  process.env.CORS_ORIGIN = 'https://vault.example.com';

  const express = (await import('express')).default;
  const { configRouter } = await import('./config.js');

  const app = express();
  app.use(express.json());
  app.use('/api/config', configRouter);

  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to resolve test server address');
  }
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function request(token: string) {
    const response = await fetch(`${baseUrl}/api/config/check`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
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
  delete process.env.VAULT_BACKUP_RETENTION_COUNT;
  delete process.env.CORS_ORIGIN;
});

describe.sequential('configRouter checks', () => {
  it('requires admin token', async () => {
    const { request, cleanup } = await setupConfigTestApp();
    try {
      const result = await request('read-token-1234567890abcdef');
      expect(result.status).toBe(401);
      expect(result.payload).toMatchObject({ error: 'Unauthorized — admin token required' });
    } finally {
      await cleanup();
    }
  });

  it('returns non-secret preflight report', async () => {
    const { request, cleanup } = await setupConfigTestApp();
    try {
      const result = await request('admin-token-1234567890abcdef');
      expect(result.status).toBe(200);
      expect(result.payload).toMatchObject({
        report: {
          summary: {
            total: expect.any(Number),
            pass: expect.any(Number),
            fail: expect.any(Number),
          },
          findings: expect.any(Array),
        },
      });

      const payloadText = JSON.stringify(result.payload);
      expect(payloadText.includes('admin-token-1234567890abcdef')).toBe(false);
      expect(payloadText.includes('test-master-secret')).toBe(false);
    } finally {
      await cleanup();
    }
  });
});
