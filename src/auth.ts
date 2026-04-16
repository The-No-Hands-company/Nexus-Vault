import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

const MIN_TOKEN_LENGTH = Math.max(parseInt(process.env.VAULT_MIN_TOKEN_LENGTH ?? '24', 10) || 24, 8);
const ALLOW_WEAK_TOKENS = process.env.VAULT_ALLOW_WEAK_TOKENS === 'true';

function parseTokenList(envName: 'VAULT_ACCESS_TOKEN' | 'VAULT_ADMIN_TOKEN'): string[] {
  const raw = process.env[envName] ?? '';
  return raw
    .split(',')
    .map((token) => token.trim())
    .filter(Boolean);
}

const ACCESS_TOKENS = parseTokenList('VAULT_ACCESS_TOKEN');
const ADMIN_TOKENS = parseTokenList('VAULT_ADMIN_TOKEN');

if (!ACCESS_TOKENS.length || !ADMIN_TOKENS.length) {
  console.error('[vault] VAULT_ACCESS_TOKEN and VAULT_ADMIN_TOKEN must be set in environment.');
  process.exit(1);
}

if (!ALLOW_WEAK_TOKENS) {
  const weak = [...ACCESS_TOKENS, ...ADMIN_TOKENS].find((token) => token.length < MIN_TOKEN_LENGTH);
  if (weak) {
    console.error(`[vault] Token length must be at least ${MIN_TOKEN_LENGTH} chars. Set VAULT_ALLOW_WEAK_TOKENS=true for local development only.`);
    process.exit(1);
  }
}

function extractBearer(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  return token || null;
}

function digestToken(token: string): Buffer {
  return crypto.createHash('sha256').update(token).digest();
}

function tokenMatches(provided: string | null, allowedTokens: readonly string[]): boolean {
  if (!provided) return false;
  const providedDigest = digestToken(provided);
  return allowedTokens.some((candidate) => crypto.timingSafeEqual(providedDigest, digestToken(candidate)));
}

/** Read-only access — for projects pulling keys at runtime */
export function requireReadToken(req: Request, res: Response, next: NextFunction) {
  const token = extractBearer(req);
  if (tokenMatches(token, ACCESS_TOKENS) || tokenMatches(token, ADMIN_TOKENS)) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

/** Admin access — for creating, updating, deleting keys via dashboard/API */
export function requireAdminToken(req: Request, res: Response, next: NextFunction) {
  const token = extractBearer(req);
  if (tokenMatches(token, ADMIN_TOKENS)) return next();
  res.status(401).json({ error: 'Unauthorized — admin token required' });
}
