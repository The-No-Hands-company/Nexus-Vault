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

/*
 * Two kinds of caller, deliberately kept distinct.
 *
 * VAULT_ACCESS_TOKEN / VAULT_ADMIN_TOKEN are *service* credentials — the thing a
 * deployed project presents when it pulls its keys at boot. They are not user
 * accounts and are not replaced by single sign-on; removing them would break the
 * vault's actual job.
 *
 * People are different. A human opening the dashboard should not be handed a
 * long-lived shared secret, and should not have to hold a second account just
 * for this app. Nexus-Auth is the ecosystem's identity service, so a valid
 * session from it is accepted too — the same cookie that already signs you in to
 * Nexus-Deploy.
 *
 * Role matters here in a way it does not for other apps: this is a secrets
 * store, so "any authenticated ecosystem user" is far too broad. Reading keys
 * requires an operator-or-above role, administering them requires admin-or-above.
 * Both lists are configurable for operators who organise roles differently.
 *
 * Order is deliberate: the static-token comparison is local and constant-time,
 * so machine callers on the hot path never wait on a network round trip. Only a
 * session credential reaches out to Nexus-Auth.
 */
const NEXUS_AUTH_URL = (process.env.NEXUS_AUTH_URL ?? 'http://localhost:4310').replace(/\/+$/, '');
const NEXUS_AUTH_TIMEOUT_MS = Number(process.env.NEXUS_AUTH_TIMEOUT_MS ?? 5000);
const SESSION_COOKIE = 'nexus_session';

function parseRoles(envName: string, fallback: string): Set<string> {
  const raw = (process.env[envName] ?? fallback).trim();
  return new Set(raw.split(',').map((r) => r.trim().toLowerCase()).filter(Boolean));
}

const SSO_READ_ROLES = parseRoles('VAULT_SSO_READ_ROLES', 'founder,admin,operator');
const SSO_ADMIN_ROLES = parseRoles('VAULT_SSO_ADMIN_ROLES', 'founder,admin');
const SSO_ENABLED = (process.env.VAULT_SSO_ENABLED ?? 'true').toLowerCase() !== 'false';

function extractSessionCookie(req: Request): string | null {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === SESSION_COOKIE) {
      return decodeURIComponent(part.slice(eq + 1).trim()) || null;
    }
  }
  return null;
}

type NexusAuthUser = { id?: string; username?: string; role?: string };

async function resolveNexusAuthUser(credential: string): Promise<NexusAuthUser | null> {
  try {
    const response = await fetch(`${NEXUS_AUTH_URL}/api/v1/auth/check`, {
      headers: { Authorization: `Bearer ${credential}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(NEXUS_AUTH_TIMEOUT_MS),
    });
    if (!response.ok) return null;
    const body = (await response.json().catch(() => null)) as
      | { authorized?: boolean; userId?: string; user?: NexusAuthUser }
      | null;
    if (!body?.authorized || !body.userId) return null;
    return body.user ?? { id: body.userId };
  } catch {
    return null;
  }
}

async function ssoRoleAllows(req: Request, allowed: Set<string>): Promise<boolean> {
  if (!SSO_ENABLED) return false;
  // A browser cannot set Authorization on a navigation, so the cookie is the
  // credential that actually arrives from the dashboard.
  const credential = extractSessionCookie(req) ?? extractBearer(req);
  if (!credential) return false;
  const user = await resolveNexusAuthUser(credential);
  if (!user) return false;
  return allowed.has(String(user.role ?? '').toLowerCase());
}


const NEXUS_AUTH_PUBLIC_URL = (
  process.env.NEXUS_AUTH_PUBLIC_URL ?? process.env.NEXUS_AUTH_URL ?? 'http://localhost:4310'
).replace(/\/+$/, '');

/**
 * People get sent to the sign-in page; machines keep getting 401.
 *
 * The apex hosts the only login form, but nothing pointed at it — an
 * unauthenticated navigation received a bare JSON 401, which reads as a wall of
 * text rather than a way in. A request is treated as a navigation when it is a
 * GET whose Accept mentions text/html, which is a property of the request rather
 * than a guess about the client.
 *
 * Service tokens are unaffected: they arrive on API calls that do not ask for
 * HTML, so a project pulling its keys still gets a machine-readable 401 rather
 * than a redirect it cannot follow.
 */
function wantsHtml(req: Request): boolean {
  return req.method === 'GET' && (req.headers.accept ?? '').includes('text/html');
}

function denyUnauthenticated(req: Request, res: Response, message: string): void {
  if (wantsHtml(req)) {
    const proto = (req.headers['x-forwarded-proto'] as string | undefined) ?? req.protocol;
    const host = (req.headers['x-forwarded-host'] as string | undefined) ?? req.get('host') ?? '';
    const here = `${proto}://${host}${req.originalUrl}`;
    res.redirect(302, `${NEXUS_AUTH_PUBLIC_URL}/login?redirect=${encodeURIComponent(here)}`);
    return;
  }
  res.status(401).json({ error: message });
}

/** Read-only access — service tokens for projects pulling keys, or an SSO session */
export async function requireReadToken(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = extractBearer(req);
  if (tokenMatches(token, tokenState.accessDigests) || tokenMatches(token, tokenState.adminDigests)) {
    next();
    return;
  }
  if (await ssoRoleAllows(req, SSO_READ_ROLES)) {
    next();
    return;
  }
  denyUnauthenticated(req, res, 'Unauthorized');
}

/** Admin access — creating, updating, deleting keys via dashboard/API */
export async function requireAdminToken(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = extractBearer(req);
  if (tokenMatches(token, tokenState.adminDigests)) {
    next();
    return;
  }
  if (await ssoRoleAllows(req, SSO_ADMIN_ROLES)) {
    next();
    return;
  }
  denyUnauthenticated(req, res, 'Unauthorized — admin token or an admin Nexus-Auth session required');
}
