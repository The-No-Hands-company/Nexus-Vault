import { describe, it, expect } from 'vitest';
import { buildVaultCloudDiscovery, buildVaultCloudClient, buildVaultCloudRegistration } from './cloud.js';

describe('Nexus Vault cloud contracts', () => {
  it('builds discovery payloads', () => {
    const payload = buildVaultCloudDiscovery();
    expect(payload.protocol).toBe('nexus-cloud/1.0');
    expect(payload.app.id).toBe('nexus-vault');
  });

  it('builds the client contract', () => {
    const client = buildVaultCloudClient();
    expect(client.client.endpoints.keys).toBe('/api/keys/:name');
  });

  it('builds registration responses', () => {
    const registration = buildVaultCloudRegistration({
      appId: 'nexus-vault',
      nodeId: 'node-1',
      endpoint: 'https://vault.example.com',
      token: 'abcd1234',
    });
    expect(registration.registered).toBe(true);
    expect(registration.tokenHint).toBe('abcd...');
  });
});
