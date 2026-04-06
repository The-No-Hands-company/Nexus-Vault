import { Router, Request, Response } from 'express';
import { keyQueries, logAudit } from '../db.js';
import { encrypt, decrypt } from '../crypto.js';
import { requireReadToken, requireAdminToken } from '../auth.js';

export const keysRouter = Router();

const MASTER = process.env.VAULT_MASTER_SECRET!;

function clientIp(req: Request): string {
  return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
    ?? req.socket.remoteAddress
    ?? 'unknown';
}

// ── GET /api/keys ── list all (values redacted) ───────────────────────────────
keysRouter.get('/', requireReadToken, (_req, res) => {
  const rows = keyQueries.getAll.all();
  const safe = rows.map(({ value_enc: _v, ...rest }) => rest);
  res.json(safe);
});

// ── GET /api/keys/expiring ── keys expiring within N days ────────────────────
keysRouter.get('/expiring', requireAdminToken, (req, res) => {
  const days = parseInt(req.query.days as string ?? '7', 10);
  const cutoff = new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);
  const rows = keyQueries.getExpiringSoon.all(cutoff);
  res.json(rows.map(({ value_enc: _v, ...rest }) => rest));
});

// ── GET /api/keys/search ──────────────────────────────────────────────────────
keysRouter.get('/search', requireReadToken, (req, res) => {
  const q = `%${req.query.q ?? ''}%`;
  const rows = keyQueries.search.all(q, q, q);
  res.json(rows.map(({ value_enc: _v, ...rest }) => rest));
});

// ── GET /api/keys/:name ── fetch decrypted value (main endpoint for projects) -
keysRouter.get('/:name', requireReadToken, (req, res) => {
  const row = keyQueries.getByName.get(req.params.name);
  if (!row) {
    return res.status(404).json({ error: `Key "${req.params.name}" not found` });
  }

  let value: string;
  try {
    value = decrypt(row.value_enc, MASTER);
  } catch {
    logAudit(row.name, 'DECRYPT_ERROR', clientIp(req), req.headers['user-agent'] ?? '');
    return res.status(500).json({ error: 'Failed to decrypt — wrong master secret?' });
  }

  keyQueries.recordAccess.run(row.name);
  logAudit(row.name, 'READ', clientIp(req), req.headers['user-agent'] ?? '');

  res.json({
    name: row.name,
    value,
    tags: row.tags,
    project: row.project,
    expires_at: row.expires_at,
  });
});

// ── POST /api/keys ── create ──────────────────────────────────────────────────
keysRouter.post('/', requireAdminToken, (req, res) => {
  const { name, value, tags = '', project = '', notes = '', expires_at = null } = req.body;

  if (!name || !value) {
    return res.status(400).json({ error: 'name and value are required' });
  }
  if (!/^[\w.\-:]+$/.test(name)) {
    return res.status(400).json({ error: 'name may only contain word chars, dots, hyphens, colons' });
  }

  try {
    const value_enc = encrypt(String(value), MASTER);
    keyQueries.insert.run({ name, value_enc, tags, project, notes, expires_at });
    logAudit(name, 'CREATE', clientIp(req), req.headers['user-agent'] ?? '');
    res.status(201).json({ ok: true, name });
  } catch (err: any) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: `Key "${name}" already exists — use PUT to update` });
    }
    throw err;
  }
});

// ── PUT /api/keys/:name ── update ─────────────────────────────────────────────
keysRouter.put('/:name', requireAdminToken, (req, res) => {
  const row = keyQueries.getByName.get(req.params.name);
  if (!row) return res.status(404).json({ error: 'Key not found' });

  const {
    value,
    tags = row.tags,
    project = row.project,
    notes = row.notes,
    expires_at = row.expires_at,
  } = req.body;

  const value_enc = value ? encrypt(String(value), MASTER) : row.value_enc;
  keyQueries.update.run({ id: row.id, value_enc, tags, project, notes, expires_at });
  logAudit(row.name, 'UPDATE', clientIp(req), req.headers['user-agent'] ?? '');

  res.json({ ok: true, name: row.name });
});

// ── DELETE /api/keys/:name ────────────────────────────────────────────────────
keysRouter.delete('/:name', requireAdminToken, (req, res) => {
  const row = keyQueries.getByName.get(req.params.name);
  if (!row) return res.status(404).json({ error: 'Key not found' });

  keyQueries.softDelete.run(row.id);
  logAudit(row.name, 'DELETE', clientIp(req), req.headers['user-agent'] ?? '');

  res.json({ ok: true });
});
