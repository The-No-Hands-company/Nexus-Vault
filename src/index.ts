import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import type { CorsOptions } from 'cors';
import { getAuditChainStatus, recordAuditVerificationRun, verifyAuditChain } from './db.js';
import { startPeriodicVerification, getLastVerificationResult, stopPeriodicVerification } from './periodic-verify.js';

import { vaultRouter } from './routes/keys.js';
import { auditRouter } from './routes/audit.js';
import cloudRouter from './routes/cloud.js';
import { opsRouter } from './routes/ops.js';
import { configRouter } from './routes/config.js';
import { getRuntimeState, isWriteBlocked } from './runtime-state.js';
import { metricsRouter } from './routes/metrics.js';
import { httpObservabilityMiddleware } from './observability.js';

const required = ['VAULT_ACCESS_TOKEN', 'VAULT_ADMIN_TOKEN', 'VAULT_MASTER_SECRET'];
for (const v of required) {
  if (!process.env[v]) {
    console.error(`[vault] Missing required env var: ${v}`);
    process.exit(1);
  }
}

function envFlag(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const normalized = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function resolveTrustProxy(): boolean | number | string | string[] {
  const raw = process.env.TRUST_PROXY?.trim();
  if (!raw) return false;
  const normalized = raw.toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  if (/^\d+$/.test(raw)) return parseInt(raw, 10);
  if (raw.includes(',')) {
    return raw
      .split(',')
      .map((part) => part.trim())
      .filter(Boolean);
  }
  return raw;
}

function resolveCorsOptions(): CorsOptions {
  const allowCredentials = envFlag('CORS_ALLOW_CREDENTIALS', false);
  const originRaw = process.env.CORS_ORIGIN?.trim();

  if (!originRaw) {
    return {
      origin: false,
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      allowedHeaders: ['Authorization', 'Content-Type', 'X-Nexus-Timestamp', 'X-Nexus-Signature'],
    };
  }

  const allowWildcard = envFlag('CORS_ALLOW_WILDCARD', false);
  const origin = originRaw === '*'
    ? (allowWildcard ? '*' : false)
    : originRaw.includes(',')
      ? originRaw.split(',').map((item) => item.trim()).filter(Boolean)
      : originRaw;

  return {
    origin,
    credentials: allowCredentials,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Authorization', 'Content-Type', 'X-Nexus-Timestamp', 'X-Nexus-Signature'],
  };
}

function resolveHelmetConfig(): Parameters<typeof helmet>[0] {
  const cspPreset = (process.env.VAULT_CSP_PRESET ?? 'compat').trim().toLowerCase();
  const allowEmbed = envFlag('VAULT_ALLOW_EMBED', envFlag('NEXUS_CLOUD_EMBEDDED', false));

  const commonDirectives = {
    defaultSrc: ["'self'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    frameAncestors: allowEmbed ? ['*'] : ["'self'"],
    imgSrc: ["'self'", 'data:'],
  };

  if (cspPreset === 'strict') {
    return {
      frameguard: allowEmbed ? false : { action: 'sameorigin' },
      contentSecurityPolicy: {
        directives: {
          ...commonDirectives,
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          fontSrc: ["'self'"],
        },
      },
    };
  }

  // compat preset supports the built-in dashboard page that currently uses inline styles/scripts.
  return {
    frameguard: allowEmbed ? false : { action: 'sameorigin' },
    contentSecurityPolicy: {
      directives: {
        ...commonDirectives,
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      },
    },
  };
}

function enforceAuditIntegrityOnStartup(): void {
  const verifyOnStart = envFlag('VAULT_VERIFY_AUDIT_ON_START', true);
  const failOnIntegrityError = envFlag('VAULT_FAIL_ON_AUDIT_INTEGRITY_ERROR', true);
  if (!verifyOnStart) return;

  const status = getAuditChainStatus();
  const verification = verifyAuditChain();
  const details = verification.ok
    ? `Audit chain verified: ${status.totalEntries} entries, head_id=${status.headId ?? 'none'}`
    : `Audit integrity failure at entry ${verification.brokenAt}: hash mismatch`;

  recordAuditVerificationRun({
    source: 'startup',
    ok: verification.ok,
    status,
    verification,
    details,
    alertSent: false,
  });

  if (!verification.ok) {
    const errorPayload = JSON.stringify({ ...verification, ...status });
    if (failOnIntegrityError) {
      console.error(`[vault] Startup blocked due to audit integrity failure: ${errorPayload}`);
      process.exit(1);
    }
    console.warn(`[vault] Audit integrity warning (continuing due to VAULT_FAIL_ON_AUDIT_INTEGRITY_ERROR=false): ${errorPayload}`);
    return;
  }

  console.log(`[vault] Audit chain verified on startup (entries=${status.totalEntries}, headId=${status.headId ?? 'none'})`);
}

enforceAuditIntegrityOnStartup();

const PORT = parseInt(process.env.PORT ?? '3900', 10);
const app = express();
let isReady = false;
let isDraining = false;

app.set('trust proxy', resolveTrustProxy());

app.use(helmet(resolveHelmetConfig()));

app.use(cors(resolveCorsOptions()));

app.use(rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' },
}));

const writeLimit = rateLimit({
  windowMs: 60_000,
  max: 30,
  message: { error: 'Too many write requests' },
});

app.use(express.json({ limit: '64kb' }));
app.use(httpObservabilityMiddleware);

app.use((req, res, next) => {
  const isWriteMethod = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
  if (!isWriteMethod) return next();

  // Allow maintenance toggle endpoint itself while blocked so operators can recover.
  if (req.path === '/api/ops/maintenance') return next();

  if (isWriteBlocked()) {
    const state = getRuntimeState();
    res.status(503).json({
      error: 'Writes are temporarily disabled',
      maintenanceMode: state.maintenanceMode,
      maintenanceReason: state.maintenanceReason || null,
      restoreInProgress: state.restoreInProgress,
    });
    return;
  }

  next();
});

const __dirname = path.dirname(process.argv[1] ?? '');
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/keys', writeLimit, vaultRouter);
app.use('/api/audit', auditRouter);
app.use('/api/ops', opsRouter);
app.use('/api/config', configRouter);
app.use('/api', metricsRouter);
app.use('/', cloudRouter);

app.get('/api/health', (_req, res) => {
  const lastVerification = getLastVerificationResult();
  res.json({
    status: 'ok',
    ts: new Date().toISOString(),
    audit: lastVerification ? {
      lastVerificationTime: lastVerification.timestamp,
      chainOk: lastVerification.ok,
      totalEntries: lastVerification.status.totalEntries,
    } : null,
  });
});

app.get('/api/ready', (_req, res) => {
  const state = getRuntimeState();
  if (!isReady || isDraining || state.restoreInProgress) {
    res.status(503).json({
      status: 'not-ready',
      ready: isReady,
      draining: isDraining,
      restoreInProgress: state.restoreInProgress,
      ts: new Date().toISOString(),
    });
    return;
  }

  res.status(200).json({
    status: 'ready',
    ready: true,
    draining: false,
    restoreInProgress: state.restoreInProgress,
    ts: new Date().toISOString(),
  });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const requestId = String(res.locals.requestId ?? 'unknown');
  console.error('[vault]', requestId, err.message);
  res.status(500).json({ error: 'Internal server error', requestId });
});

// Start periodic audit verification background job
const verificationTimer = startPeriodicVerification();

const server = app.listen(PORT, () => {
  isReady = true;
  console.log(`\n🔐 Nexus Vault running on http://localhost:${PORT}\n`);
});

function beginGracefulShutdown(signal: string): void {
  if (isDraining) return;
  isDraining = true;
  isReady = false;

  console.log(`[vault] ${signal} received, draining HTTP server`);
  stopPeriodicVerification(verificationTimer);

  const forceMs = Math.max(1000, parseInt(process.env.VAULT_SHUTDOWN_TIMEOUT_MS ?? '15000', 10));
  const forceTimer = setTimeout(() => {
    console.error('[vault] Graceful shutdown timeout exceeded, forcing exit');
    process.exit(1);
  }, forceMs);

  server.close(() => {
    clearTimeout(forceTimer);
    console.log('[vault] HTTP server drained, shutdown complete');
    process.exit(0);
  });
}

// Graceful shutdown
process.on('SIGTERM', () => {
  beginGracefulShutdown('SIGTERM');
});

process.on('SIGINT', () => {
  beginGracefulShutdown('SIGINT');
});

export default app;
