import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import { incCounter } from './metrics.js';

function envFlag(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const normalized = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function generateRequestId(): string {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return crypto.randomBytes(16).toString('hex');
}

function normalizeRoutePath(path: string): string {
  return path
    .replace(/[0-9]+/g, ':id')
    .replace(/[A-Fa-f0-9-]{16,}/g, ':token');
}

function statusClass(code: number): string {
  if (code >= 500) return '5xx';
  if (code >= 400) return '4xx';
  if (code >= 300) return '3xx';
  if (code >= 200) return '2xx';
  return '1xx';
}

function ignoredPathPrefixes(): string[] {
  const raw = process.env.VAULT_HTTP_METRICS_IGNORE_PATHS?.trim();
  if (!raw) return ['/api/metrics'];
  return raw.split(',').map((v) => v.trim()).filter(Boolean);
}

function shouldIgnorePath(path: string, prefixes: string[]): boolean {
  return prefixes.some((prefix) => path.startsWith(prefix));
}

export function httpObservabilityMiddleware(req: Request, res: Response, next: NextFunction): void {
  const requestId = String(req.headers['x-request-id'] ?? '').trim() || generateRequestId();
  res.setHeader('X-Request-Id', requestId);
  res.locals.requestId = requestId;

  if (!envFlag('VAULT_HTTP_METRICS_ENABLED', true)) {
    next();
    return;
  }

  const path = req.path || '/';
  const ignoredPrefixes = ignoredPathPrefixes();
  if (shouldIgnorePath(path, ignoredPrefixes)) {
    next();
    return;
  }

  const startedAt = process.hrtime.bigint();
  res.on('finish', () => {
    const elapsedNs = Number(process.hrtime.bigint() - startedAt);
    const elapsedMs = elapsedNs / 1_000_000;
    const route = normalizeRoutePath(path);
    const status = res.statusCode;
    const method = req.method.toUpperCase();
    const klass = statusClass(status);

    const labels = {
      method,
      route,
      status: String(status),
      status_class: klass,
    };

    incCounter('vault_http_requests_total', 'Total HTTP requests served', 1, labels);
    incCounter('vault_http_request_duration_ms_sum', 'Total HTTP request duration in milliseconds', elapsedMs, {
      method,
      route,
      status_class: klass,
    });
    incCounter('vault_http_request_duration_ms_count', 'Total observed HTTP request durations', 1, {
      method,
      route,
      status_class: klass,
    });

    if (status >= 500) {
      incCounter('vault_http_errors_total', 'Total HTTP 5xx responses', 1, {
        method,
        route,
      });
    }
  });

  next();
}
