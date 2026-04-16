import { Router, type Request, type Response } from 'express';
import crypto from 'crypto';

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

const registrationSecret = process.env.NEXUS_CLOUD_REGISTER_SECRET?.trim() ?? '';
const signatureSkewSeconds = Math.max(1, parseInt(process.env.NEXUS_CLOUD_SIGNATURE_MAX_SKEW_SECONDS ?? '300', 10));
const allowInsecureRegistrationEndpoint = envFlag('NEXUS_CLOUD_ALLOW_INSECURE_REGISTRATION_ENDPOINT', false);

function envFlag(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const normalized = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function envList(name: string, fallback: readonly string[]): readonly string[] {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  const values = raw
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  return values.length ? values : fallback;
}

function normalizeBaseUrl(raw: string | undefined): string {
  const v = (raw ?? '/api').trim();
  if (!v) return '/api';
  if (v === '/') return '';
  return v.endsWith('/') ? v.slice(0, -1) : v;
}

function pathFor(baseUrl: string, suffix: string): string {
  return `${baseUrl}${suffix}`;
}

function normalizeHeaderValue(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value[0] ?? '';
  return value ?? '';
}

function timingSafeHexEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, 'hex');
  const bBuf = Buffer.from(b, 'hex');
  if (aBuf.length !== bBuf.length || aBuf.length === 0) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function hasValidSignature(req: Request): boolean {
  if (!registrationSecret) return true;

  const timestamp = normalizeHeaderValue(req.header('x-nexus-timestamp')).trim();
  const signature = normalizeHeaderValue(req.header('x-nexus-signature')).trim().toLowerCase();
  if (!timestamp || !signature) return false;

  const timestampMs = Date.parse(timestamp);
  if (Number.isNaN(timestampMs)) return false;
  const skewMs = Math.abs(Date.now() - timestampMs);
  if (skewMs > signatureSkewSeconds * 1000) return false;

  const payload = JSON.stringify(req.body ?? {});
  const expected = crypto
    .createHmac('sha256', registrationSecret)
    .update(`${timestamp}.${payload}`)
    .digest('hex');

  return timingSafeHexEqual(signature, expected);
}

function isValidRegistrationEndpoint(value: string): boolean {
  try {
    const parsed = new URL(value);
    if (!allowInsecureRegistrationEndpoint && parsed.protocol !== 'https:') return false;
    if (allowInsecureRegistrationEndpoint && !['https:', 'http:'].includes(parsed.protocol)) return false;
    return Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

function isValidIdentifier(value: string): boolean {
  return /^[A-Za-z0-9._:-]{3,120}$/.test(value);
}

function isValidCapabilities(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.trim().length > 0 && item.length <= 80);
}

const cloudBaseUrl = normalizeBaseUrl(process.env.NEXUS_CLOUD_BASE_URL);
const cloudEndpoints = {
  keys: pathFor(cloudBaseUrl, '/keys'),
  audit: pathFor(cloudBaseUrl, '/audit'),
  discovery: pathFor(cloudBaseUrl, '/cloud/discovery'),
  register: pathFor(cloudBaseUrl, '/cloud/register'),
  client: pathFor(cloudBaseUrl, '/cloud/client'),
};

const app: NexusCloudVaultApp = {
  id: process.env.NEXUS_CLOUD_APP_ID?.trim() || 'nexus-vault',
  name: process.env.NEXUS_CLOUD_APP_NAME?.trim() || 'Nexus Vault',
  role: process.env.NEXUS_CLOUD_APP_ROLE?.trim() || 'secrets-layer',
  embedded: envFlag('NEXUS_CLOUD_EMBEDDED', false),
  referenced: envFlag('NEXUS_CLOUD_REFERENCED', true),
  exposes: envList('NEXUS_CLOUD_EXPOSES', ['/.well-known/nexus-cloud', cloudEndpoints.discovery, cloudEndpoints.register, cloudEndpoints.client]),
  consumes: envList('NEXUS_CLOUD_CONSUMES', [cloudEndpoints.keys, cloudEndpoints.audit]),
  requiredApis: envList('NEXUS_CLOUD_REQUIRED_APIS', ['topology.v1', 'systems-api.v1']),
};

export function buildVaultCloudDiscovery(): NexusCloudVaultDiscovery {
  return {
    protocol: process.env.NEXUS_CLOUD_PROTOCOL?.trim() || 'nexus-cloud/1.0',
    hub: process.env.NEXUS_CLOUD_HUB?.trim() || 'Nexus Cloud',
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
    registry: cloudEndpoints.discovery,
    client: cloudEndpoints.client,
  };
}

export function buildVaultCloudClient(): { client: NexusCloudVaultClient } {
  return {
    client: {
      name: 'Nexus Vault client',
      baseUrl: cloudBaseUrl,
      auth: 'Bearer VAULT_ACCESS_TOKEN',
      endpoints: {
        keys: cloudEndpoints.keys,
        audit: cloudEndpoints.audit,
        cloud: cloudEndpoints.discovery,
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

  if (!hasValidSignature(req)) {
    res.status(401).json({ error: 'Invalid registration signature' });
    return;
  }

  if (!appId || !nodeId || !endpoint) {
    res.status(400).json({ error: 'Missing required fields: appId, nodeId, endpoint' });
    return;
  }

  if (!isValidIdentifier(appId) || !isValidIdentifier(nodeId)) {
    res.status(400).json({ error: 'appId and nodeId must be 3-120 chars (A-Z, a-z, 0-9, ., _, :, -)' });
    return;
  }

  if (!isValidRegistrationEndpoint(endpoint)) {
    const msg = allowInsecureRegistrationEndpoint
      ? 'endpoint must be a valid http(s) URL'
      : 'endpoint must be a valid https URL';
    res.status(400).json({ error: msg });
    return;
  }

  if (capabilities !== undefined && !isValidCapabilities(capabilities)) {
    res.status(400).json({ error: 'capabilities must be an array of non-empty strings (max 80 chars each)' });
    return;
  }

  res.status(201).json(buildVaultCloudRegistration({ appId, nodeId, endpoint, capabilities }));
});

router.get('/api/cloud/client', (_req, res) => {
  res.json(buildVaultCloudClient());
});

export default router;
