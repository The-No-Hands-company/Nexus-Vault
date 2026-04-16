import { afterEach, describe, it, expect, vi } from 'vitest';
import type { Server } from 'http';
import crypto from 'crypto';
import {
  buildVaultCloudDiscovery,
  buildVaultCloudClient,
  buildVaultCloudRegistration,
} from './cloud.js';

async function setupCloudRouterTestApp() {
  vi.resetModules();
  const express = (await import('express')).default;
  const { default: cloudRouter } = await import('./cloud.js');

  const app = express();
  app.use(express.json());
  app.use('/', cloudRouter);

  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Failed to resolve test server address');
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function postRegistration(
    body: unknown,
    headers: Record<string, string> = {},
  ): Promise<{ status: number; payload: unknown }> {
    const response = await fetch(`${baseUrl}/api/cloud/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
      body: JSON.stringify(body),
    });

    const text = await response.text();
    let payload: unknown;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = text;
    }

    return { status: response.status, payload };
  }

  async function cleanup() {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  return { postRegistration, cleanup };
}

afterEach(() => {
  delete process.env.NEXUS_CLOUD_REGISTER_SECRET;
  delete process.env.NEXUS_CLOUD_ALLOW_INSECURE_REGISTRATION_ENDPOINT;
  delete process.env.NEXUS_CLOUD_SIGNATURE_MAX_SKEW_SECONDS;
});

describe('Nexus Vault cloud contracts', () => {
  it('builds discovery payloads', () => {
    const payload = buildVaultCloudDiscovery();
    expect(payload.protocol).toBe('nexus-cloud/1.0');
    expect(payload.app.id).toBe('nexus-vault');
    expect(payload.app.role).toBe('secrets-layer');
    expect(payload.app.exposes).toContain('/.well-known/nexus-cloud');
    expect(payload.app.exposes).toContain('/api/cloud/discovery');
  });

  it('builds the client contract', () => {
    const { client } = buildVaultCloudClient();
    expect(client.name).toBe('Nexus Vault client');
    expect(client.endpoints.keys).toBe('/api/keys');
    expect(client.endpoints.audit).toBe('/api/audit');
    expect(client.endpoints.cloud).toBe('/api/cloud/discovery');
    expect(client.auth).toContain('VAULT_ACCESS_TOKEN');
  });

  it('builds registration responses', () => {
    const registration = buildVaultCloudRegistration({
      appId: 'nexus-vault',
      nodeId: 'node-1',
      endpoint: 'https://vault.example.com',
      capabilities: ['keys', 'audit'],
    });
    expect(registration.registered).toBe(true);
    expect(registration.appId).toBe('nexus-vault');
    expect(registration.capabilityHint).toEqual(['keys', 'audit']);
    expect(registration.registry).toBe('/api/cloud/discovery');
    expect(registration.client).toBe('/api/cloud/client');
  });

  it('rejects invalid registration endpoint URLs', async () => {
    const { postRegistration, cleanup } = await setupCloudRouterTestApp();
    try {
      const result = await postRegistration({
        appId: 'nexus-vault',
        nodeId: 'node-1',
        endpoint: 'not-a-url',
      });
      expect(result.status).toBe(400);
      expect(result.payload).toMatchObject({ error: 'endpoint must be a valid https URL' });
    } finally {
      await cleanup();
    }
  });

  it('requires valid signature when registration secret is configured', async () => {
    process.env.NEXUS_CLOUD_REGISTER_SECRET = 'super-secret-for-tests';
    const { postRegistration, cleanup } = await setupCloudRouterTestApp();
    try {
      const result = await postRegistration({
        appId: 'nexus-vault',
        nodeId: 'node-1',
        endpoint: 'https://vault.example.com',
      });
      expect(result.status).toBe(401);
      expect(result.payload).toMatchObject({ error: 'Invalid registration signature' });
    } finally {
      await cleanup();
    }
  });

  it('accepts signed registration payloads with valid timestamp and signature', async () => {
    const secret = 'super-secret-for-tests';
    process.env.NEXUS_CLOUD_REGISTER_SECRET = secret;

    const body = {
      appId: 'nexus-vault',
      nodeId: 'node-1',
      endpoint: 'https://vault.example.com',
      capabilities: ['keys', 'audit'],
    };
    const timestamp = new Date().toISOString();
    const signature = crypto
      .createHmac('sha256', secret)
      .update(`${timestamp}.${JSON.stringify(body)}`)
      .digest('hex');

    const { postRegistration, cleanup } = await setupCloudRouterTestApp();
    try {
      const result = await postRegistration(body, {
        'X-Nexus-Timestamp': timestamp,
        'X-Nexus-Signature': signature,
      });
      expect(result.status).toBe(201);
      expect(result.payload).toMatchObject({
        registered: true,
        appId: 'nexus-vault',
        nodeId: 'node-1',
      });
    } finally {
      await cleanup();
    }
  });
});
