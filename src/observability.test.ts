import type { Server } from 'http';
import express from 'express';
import { afterEach, describe, expect, it } from 'vitest';
import { getMetricsSnapshot, resetMetricsForTests } from './metrics.js';
import { httpObservabilityMiddleware } from './observability.js';

async function setupApp() {
  resetMetricsForTests();

  const app = express();
  app.use(httpObservabilityMiddleware);

  app.get('/api/items/:id', (_req, res) => {
    res.json({ ok: true });
  });

  app.get('/api/fail', (_req, res) => {
    res.status(500).json({ error: 'boom' });
  });

  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to resolve test server address');
  }
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function request(path: string, headers?: HeadersInit) {
    return fetch(`${baseUrl}${path}`, { headers });
  }

  async function cleanup() {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  }

  return { request, cleanup };
}

afterEach(() => {
  resetMetricsForTests();
  delete process.env.VAULT_HTTP_METRICS_ENABLED;
  delete process.env.VAULT_HTTP_METRICS_IGNORE_PATHS;
});

describe.sequential('httpObservabilityMiddleware', () => {
  it('propagates x-request-id and emits normalized request metrics', async () => {
    const { request, cleanup } = await setupApp();
    try {
      const response = await request('/api/items/123', { 'X-Request-Id': 'req-fixed-1' });
      expect(response.status).toBe(200);
      expect(response.headers.get('x-request-id')).toBe('req-fixed-1');

      const metrics = getMetricsSnapshot();
      expect(metrics.some((m) => m.name === 'vault_http_requests_total' && m.labels.route === '/api/items/:id')).toBe(true);
      expect(metrics.some((m) => m.name === 'vault_http_request_duration_ms_count' && m.labels.route === '/api/items/:id')).toBe(true);
    } finally {
      await cleanup();
    }
  });

  it('tracks 5xx responses as error metrics', async () => {
    const { request, cleanup } = await setupApp();
    try {
      const response = await request('/api/fail');
      expect(response.status).toBe(500);

      const metrics = getMetricsSnapshot();
      expect(metrics.some((m) => m.name === 'vault_http_errors_total' && m.labels.route === '/api/fail')).toBe(true);
      expect(metrics.some((m) => m.name === 'vault_http_requests_total' && m.labels.status_class === '5xx')).toBe(true);
    } finally {
      await cleanup();
    }
  });
});
