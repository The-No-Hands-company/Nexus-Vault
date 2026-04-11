import { describe, it, expect } from 'vitest';
import {
  buildVaultCloudDiscovery,
  buildVaultCloudClient,
  buildVaultCloudRegistration,
} from './cloud.js';

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
});
