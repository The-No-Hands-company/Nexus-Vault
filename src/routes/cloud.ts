import { Router, type Request, type Response } from 'express';

export type NexusCloudVaultApp = {
  id: string;
  name: string;
  role: string;
  embedded: boolean;
  referenced: boolean;
  exposes: readonly string[];
  consumes: readonly string[];
  requiredApis: readonly string[];
};

export type NexusCloudVaultDiscovery = {
  protocol: string;
  hub: string;
  app: NexusCloudVaultApp;
  updatedAt: string;
};

export type NexusCloudVaultRegistration = {
  registered: boolean;
  appId: string;
  nodeId: string;
  endpoint: string;
  tokenHint: string | null;
  registry: string;
  client: string;
};

export type NexusCloudVaultClient = {
  name: string;
  baseUrl: string;
  auth: string;
  endpoints: {
    keys: string;
    entries: string;
    entryByName: string;
    audit: string;
    collections: string;
    cloud: string;
    secrets: string;
  };
};

const router = Router();

const app: NexusCloudVaultApp = {
  id: 'nexus-vault',
  name: 'Nexus Vault',
  role: 'vault-layer',
  embedded: false,
  referenced: true,
  exposes: ['/.well-known/nexus-cloud', '/api/cloud/discovery', '/api/cloud/register', '/api/cloud/client'],
  consumes: ['/api/keys', '/api/keys/types/:type', '/api/collections', '/api/audit', '/api/health'],
  requiredApis: ['systems-api.v1', 'topology.v1'],
};

export function buildVaultCloudDiscovery(): NexusCloudVaultDiscovery {
  return {
    protocol: 'nexus-cloud/1.0',
    hub: 'Nexus Cloud',
    app,
    updatedAt: new Date().toISOString(),
  };
}

export function buildVaultCloudRegistration(input: { appId: string; nodeId: string; endpoint: string; token?: string }): NexusCloudVaultRegistration {
  return {
    registered: true,
    appId: input.appId,
    nodeId: input.nodeId,
    endpoint: input.endpoint,
    tokenHint: input.token ? `${input.token.slice(0, 4)}...` : null,
    registry: '/api/cloud/discovery',
    client: '/api/cloud/client',
  };
}

export function buildVaultCloudClient(): { client: NexusCloudVaultClient } {
  return {
    client: {
      name: 'Nexus Vault client',
      baseUrl: '/api',
      auth: 'Bearer VAULT_ACCESS_TOKEN',
      endpoints: {
        keys: '/api/keys/:name',
        entries: '/api/keys',
        entryByName: '/api/keys/:name',
        audit: '/api/audit',
        collections: '/api/collections',
        cloud: '/api/cloud/discovery',
        secrets: '/api/keys/:name',
      },
    },
  };
}

router.get('/.well-known/nexus-cloud', (_req, res) => {
  res.json(buildVaultCloudDiscovery());
});

router.get('/api/cloud/discovery', (_req, res) => {
  res.json(buildVaultCloudDiscovery());
});

router.post('/api/cloud/register', (req: Request, res: Response) => {
  const { appId, nodeId, endpoint, token } = (req.body ?? {}) as { appId?: string; nodeId?: string; endpoint?: string; token?: string };
  if (!appId || !nodeId || !endpoint) {
    res.status(400).json({ error: 'Missing required fields: appId, nodeId, endpoint' });
    return;
  }
  res.status(201).json(buildVaultCloudRegistration({ appId, nodeId, endpoint, token }));
});

router.get('/api/cloud/client', (_req, res) => {
  res.json(buildVaultCloudClient());
});

export default router;
