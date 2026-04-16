import type { NextFunction, Request, Response } from 'express';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

type LogFields = Record<string, unknown>;

type Logger = {
  debug: (message: string, fields?: LogFields) => void;
  info: (message: string, fields?: LogFields) => void;
  warn: (message: string, fields?: LogFields) => void;
  error: (message: string, fields?: LogFields) => void;
};

const LEVEL_WEIGHT: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const REDACT_TOKENS = [
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'password',
  'passphrase',
  'secret',
  'token',
  'api_key',
  'apikey',
  'client_secret',
  'access_token',
  'refresh_token',
  'vault_master_secret',
  'vault_admin_token',
  'vault_access_token',
];

function env(name: string, fallback: string): string {
  const raw = process.env[name]?.trim();
  return raw || fallback;
}

function envFlag(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const normalized = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function activeLevel(): LogLevel {
  const raw = env('VAULT_LOG_LEVEL', 'info').toLowerCase();
  if (raw === 'debug' || raw === 'info' || raw === 'warn' || raw === 'error') {
    return raw;
  }
  return 'info';
}

function useJsonFormat(): boolean {
  return env('VAULT_LOG_FORMAT', 'json').toLowerCase() === 'json';
}

function truncateString(input: string): string {
  const max = Math.max(64, parseInt(env('VAULT_LOG_MAX_FIELD_CHARS', '1024'), 10) || 1024);
  if (input.length <= max) return input;
  return `${input.slice(0, max)}...<truncated:${input.length - max}>`;
}

function shouldRedact(key: string): boolean {
  const lower = key.toLowerCase();
  return REDACT_TOKENS.some((token) => lower.includes(token));
}

function sanitize(value: unknown, keyHint = '', depth = 0): unknown {
  if (depth > 4) return '[max-depth]';

  if (keyHint && shouldRedact(keyHint)) {
    return '[REDACTED]';
  }

  if (value === null || value === undefined) return value;

  if (typeof value === 'string') return truncateString(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      stack: value.stack ? truncateString(value.stack) : undefined,
    };
  }

  if (Array.isArray(value)) {
    return value.map((entry) => sanitize(entry, keyHint, depth + 1));
  }

  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = sanitize(v, k, depth + 1);
    }
    return out;
  }

  return String(value);
}

function emit(level: LogLevel, message: string, fields: LogFields = {}): void {
  const minLevel = activeLevel();
  if (LEVEL_WEIGHT[level] < LEVEL_WEIGHT[minLevel]) return;

  const sanitizedFields = sanitize(fields) as Record<string, unknown>;
  const payload: Record<string, unknown> = {
    ts: new Date().toISOString(),
    level,
    message,
    ...sanitizedFields,
  };

  if (useJsonFormat()) {
    process.stdout.write(`${JSON.stringify(payload)}\n`);
    return;
  }

  const flat = Object.entries(payload)
    .filter(([key]) => !['ts', 'level', 'message'].includes(key))
    .map(([key, val]) => `${key}=${JSON.stringify(val)}`)
    .join(' ');

  process.stdout.write(`[${payload.ts}] ${String(payload.level).toUpperCase()} ${payload.message}${flat ? ` ${flat}` : ''}\n`);
}

export const logger: Logger = {
  debug: (message, fields) => emit('debug', message, fields),
  info: (message, fields) => emit('info', message, fields),
  warn: (message, fields) => emit('warn', message, fields),
  error: (message, fields) => emit('error', message, fields),
};

export function requestLoggingMiddleware(req: Request, res: Response, next: NextFunction): void {
  const requestId = String(res.locals.requestId ?? 'unknown');
  const startedAt = process.hrtime.bigint();
  const includeBody = envFlag('VAULT_LOG_REQUEST_BODY', false);

  const safeHeaders = sanitize(req.headers) as Record<string, unknown>;
  const safeBody = includeBody ? sanitize(req.body) : undefined;

  logger.debug('http.request.start', {
    requestId,
    method: req.method,
    path: req.path,
    query: sanitize(req.query),
    headers: safeHeaders,
    body: safeBody,
  });

  res.on('finish', () => {
    const elapsedNs = Number(process.hrtime.bigint() - startedAt);
    const elapsedMs = Math.round((elapsedNs / 1_000_000) * 1000) / 1000;
    const status = res.statusCode;
    const level: LogLevel = status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info';

    emit(level, 'http.request.finish', {
      requestId,
      method: req.method,
      path: req.path,
      status,
      durationMs: elapsedMs,
      remoteIp: req.ip,
      userAgent: req.headers['user-agent'],
    });
  });

  next();
}
