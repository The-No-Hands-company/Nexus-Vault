import { Request, Response, NextFunction } from 'express';

const ACCESS_TOKEN = process.env.VAULT_ACCESS_TOKEN;
const ADMIN_TOKEN = process.env.VAULT_ADMIN_TOKEN;

if (!ACCESS_TOKEN || !ADMIN_TOKEN) {
  console.error('[vault] VAULT_ACCESS_TOKEN and VAULT_ADMIN_TOKEN must be set in environment.');
  process.exit(1);
}

function extractBearer(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return null;
  return header.slice(7).trim();
}

/** Read-only access — for projects pulling keys at runtime */
export function requireReadToken(req: Request, res: Response, next: NextFunction) {
  const token = extractBearer(req);
  if (token === ACCESS_TOKEN || token === ADMIN_TOKEN) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

/** Admin access — for creating, updating, deleting keys via dashboard/API */
export function requireAdminToken(req: Request, res: Response, next: NextFunction) {
  const token = extractBearer(req);
  if (token === ADMIN_TOKEN) return next();
  res.status(401).json({ error: 'Unauthorized — admin token required' });
}
