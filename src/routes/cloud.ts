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
  capabilityHint: string[];
  registry: string;
  client: string;
};

export type NexusCloudVaultClient = {
  name: string;
  baseUrl: string;
  auth: string;
  endpoints: {
    keys: string;
    audit: string;
    cloud: string;
  };
};

const router = Router();

const app: NexusCloudVaultApp = {
  id: 'nexus-vault',
  name: 'Nexus Vault',
  role: 'secrets-layer',
  embedded: false,
  referenced: true,
  exposes: ['/.well-known/nexus-cloud', '/api/cloud/discovery', '/api/cloud/register', '/api/cloud/client'],
  consumes: ['/api/keys', '/api/audit'],
  requiredApis: ['topology.v1', 'systems-api.v1'],
};

export function buildVaultCloudDiscovery(): NexusCloudVaultDiscovery {
  return {
    protocol: 'nexus-cloud/1.0',
    hub: 'Nexus Cloud',
    app,
    updatedAt: new Date().toISOString(),
  };
}

export function buildVaultCloudRegistration(input: {
  appId: string;
  nodeId: string;
  endpoint: string;
  capabilities?: readonly string[];
}): NexusCloudVaultRegistration {
  return {
    registered: true,
    appId: input.appId,
    nodeId: input.nodeId,
    endpoint: input.endpoint,
    capabilityHint: Array.isArray(input.capabilities) ? [...input.capabilities] : [],
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
        keys: '/api/keys',
        audit: '/api/audit',
        cloud: '/api/cloud/discovery',
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
  const { appId, nodeId, endpoint, capabilities } = (req.body ?? {}) as {
    appId?: string;
    nodeId?: string;
    endpoint?: string;
    capabilities?: readonly string[];
  };
  if (!appId || !nodeId || !endpoint) {
    res.status(400).json({ error: 'Missing required fields: appId, nodeId, endpoint' });
    return;
  }
  res.status(201).json(buildVaultCloudRegistration({ appId, nodeId, endpoint, capabilities }));
});

router.get('/api/cloud/client', (_req, res) => {
  res.json(buildVaultCloudClient());
});

export default router;
