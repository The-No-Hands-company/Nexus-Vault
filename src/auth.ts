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

type TokenState = {
  accessDigests: Buffer[];
  adminDigests: Buffer[];
  accessCount: number;
  adminCount: number;
  updatedAt: string;
};

function extractBearer(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  return token || null;
}

function digestToken(token: string): Buffer {
  return crypto.createHash('sha256').update(token).digest();
}

function validateTokenSet(tokens: readonly string[]): void {
  if (!ALLOW_WEAK_TOKENS) {
    const weak = tokens.find((token) => token.length < MIN_TOKEN_LENGTH);
    if (weak) {
      throw new Error(`Token length must be at least ${MIN_TOKEN_LENGTH} chars. Set VAULT_ALLOW_WEAK_TOKENS=true for local development only.`);
    }
  }
}

function tokenMatches(provided: string | null, allowedDigests: readonly Buffer[]): boolean {
  if (!provided) return false;
  const providedDigest = digestToken(provided);
  return allowedDigests.some((digest) => digest.length === providedDigest.length && crypto.timingSafeEqual(providedDigest, digest));
}

function buildTokenState(accessTokens: readonly string[], adminTokens: readonly string[]): TokenState {
  if (!accessTokens.length || !adminTokens.length) {
    throw new Error('VAULT_ACCESS_TOKEN and VAULT_ADMIN_TOKEN must be set in environment.');
  }
  validateTokenSet(accessTokens);
  validateTokenSet(adminTokens);
  return {
    accessDigests: accessTokens.map((token) => digestToken(token)),
    adminDigests: adminTokens.map((token) => digestToken(token)),
    accessCount: accessTokens.length,
    adminCount: adminTokens.length,
    updatedAt: new Date().toISOString(),
  };
}

let tokenState: TokenState;

try {
  tokenState = buildTokenState(parseTokenList('VAULT_ACCESS_TOKEN'), parseTokenList('VAULT_ADMIN_TOKEN'));
} catch (err) {
  console.error(`[vault] ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}

export function rotateTokensAtomic(input: {
  accessTokens?: readonly string[];
  adminTokens?: readonly string[];
  mode?: 'replace' | 'append';
}): { accessCount: number; adminCount: number; updatedAt: string } {
  const mode = input.mode ?? 'replace';
  const currentAccess = mode === 'append' ? tokenState.accessDigests : [];
  const currentAdmin = mode === 'append' ? tokenState.adminDigests : [];

  const nextAccessRaw = input.accessTokens?.map((token) => token.trim()).filter(Boolean);
  const nextAdminRaw = input.adminTokens?.map((token) => token.trim()).filter(Boolean);

  if (!nextAccessRaw?.length && !nextAdminRaw?.length) {
    throw new Error('At least one of accessTokens or adminTokens must be provided');
  }

  const accessTokens = nextAccessRaw?.length
    ? (mode === 'append'
      ? [...currentAccess, ...nextAccessRaw.map((token) => digestToken(token))]
      : nextAccessRaw.map((token) => digestToken(token)))
    : tokenState.accessDigests;

  const adminTokens = nextAdminRaw?.length
    ? (mode === 'append'
      ? [...currentAdmin, ...nextAdminRaw.map((token) => digestToken(token))]
      : nextAdminRaw.map((token) => digestToken(token)))
    : tokenState.adminDigests;

  // Validate raw tokens for length policy when provided.
  if (nextAccessRaw?.length) validateTokenSet(nextAccessRaw);
  if (nextAdminRaw?.length) validateTokenSet(nextAdminRaw);

  if (!accessTokens.length || !adminTokens.length) {
    throw new Error('Token rotation cannot leave access/admin token sets empty');
  }

  tokenState = {
    accessDigests: accessTokens,
    adminDigests: adminTokens,
    accessCount: accessTokens.length,
    adminCount: adminTokens.length,
    updatedAt: new Date().toISOString(),
  };

  return {
    accessCount: tokenState.accessCount,
    adminCount: tokenState.adminCount,
    updatedAt: tokenState.updatedAt,
  };
}

export function getTokenStateSummary(): { accessCount: number; adminCount: number; updatedAt: string } {
  return {
    accessCount: tokenState.accessCount,
    adminCount: tokenState.adminCount,
    updatedAt: tokenState.updatedAt,
  };
}

/** Read-only access — for projects pulling keys at runtime */
export function requireReadToken(req: Request, res: Response, next: NextFunction) {
  const token = extractBearer(req);
  if (tokenMatches(token, tokenState.accessDigests) || tokenMatches(token, tokenState.adminDigests)) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

/** Admin access — for creating, updating, deleting keys via dashboard/API */
export function requireAdminToken(req: Request, res: Response, next: NextFunction) {
  const token = extractBearer(req);
  if (tokenMatches(token, tokenState.adminDigests)) return next();
  res.status(401).json({ error: 'Unauthorized — admin token required' });
}
