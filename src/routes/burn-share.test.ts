import { describe, expect, it, beforeAll, afterAll } from 'bun:test';
import http from 'node:http';
import express from 'express';
import { vaultRouter } from './keys.js';
import { runMigrations } from '../db.js';

describe('Nexus-Vault: One-time burn links and secret rotation', () => {
  let app: express.Express;
  let server: http.Server;
  let base: string;
  const token = process.env.VAULT_ACCESS_TOKEN || 'e2846fb8930ed04f7ba71257d56d451ced0df935b741e865cb6aed3ed8efda85';

  beforeAll(async () => {
    runMigrations();

    app = express();
    app.use(express.json());
    app.use('/api/keys', vaultRouter);

    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as any).port;
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(() => {
    server.close();
  });

  it('creates and burns a one-time secret link', async () => {
    const createRes = await fetch(`${base}/api/keys/share`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: 'super-sensitive-api-token-xyz',
        title: 'Database Prod Secret',
        maxViews: 1,
        expiresInSeconds: 3600,
      }),
    });

    expect(createRes.status).toBe(201);
    const created = (await createRes.json()) as any;
    expect(created.token).toBeDefined();
    expect(created.shareUrl).toBe(`/share/${created.token}`);

    // 2. Read the secret for the first time (burn on read)
    const readRes = await fetch(`${base}/api/keys/share/${created.token}`);
    expect(readRes.status).toBe(200);
    const readData = (await readRes.json()) as any;
    expect(readData.secret).toBe('super-sensitive-api-token-xyz');
    expect(readData.burned).toBe(true);

    // 3. Second read should return 404 (burned)
    const secondRead = await fetch(`${base}/api/keys/share/${created.token}`);
    expect(secondRead.status).toBe(404);
  });

  it('checks rotation status', async () => {
    const res = await fetch(`${base}/api/keys/rotation/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const data = (await res.json()) as any;
    expect(data.healthyCount).toBeDefined();
    expect(data.expiredCount).toBeDefined();
    expect(data.expiringSoonCount).toBeDefined();
  });
});
