import { afterEach, describe, expect, it } from 'vitest';
import { buildNexusVaultSystemsApiRegistrationPayload } from './nexus-cloud.js';

describe('Nexus Vault systems API contract helper', () => {
  afterEach(() => {
    delete process.env.NEXUS_VAULT_TOOL_ID;
    delete process.env.NEXUS_VAULT_TOOL_NAME;
    delete process.env.NEXUS_VAULT_PUBLIC_URL;
    delete process.env.SYSTEMS_API_MODE;
  });

  it('builds orchestrated registration payload when requested', () => {
    process.env.NEXUS_VAULT_TOOL_ID = 'nexus-vault-main';
    process.env.NEXUS_VAULT_TOOL_NAME = 'Nexus Vault Main';
    process.env.NEXUS_VAULT_PUBLIC_URL = 'https://vault.local';
    process.env.SYSTEMS_API_MODE = 'orchestrated';

    const payload = buildNexusVaultSystemsApiRegistrationPayload(3900);
    expect(payload.id).toBe('nexus-vault-main');
    expect(payload.name).toBe('Nexus Vault Main');
    expect(payload.upstreamUrl).toBe('https://vault.local');
    expect(payload.mode).toBe('orchestrated');
    expect(payload.capabilities).toContain('systems-api');
  });

  it('falls back to local standalone defaults', () => {
    const payload = buildNexusVaultSystemsApiRegistrationPayload(3900);
    expect(payload.id).toBe('nexus-vault');
    expect(payload.name).toBe('Nexus Vault');
    expect(payload.upstreamUrl).toBe('http://localhost:3900');
    expect(payload.mode).toBe('standalone');
  });
});
