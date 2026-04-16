import { Router } from 'express';
import { requireAdminToken } from '../auth.js';
import {
  backupDirPath,
  createBackup,
  createSignedBackupToken,
  databasePath,
  enforceBackupRetention,
  listBackups,
  restoreBackup,
  verifyBackupChecksum,
  verifySignedBackupToken,
  writeUploadedBackup,
} from '../ops.js';
import { getRuntimeState, setMaintenanceMode, setRestoreInProgress } from '../runtime-state.js';

export const opsRouter = Router();

opsRouter.get('/state', requireAdminToken, (_req, res) => {
  res.json({ state: getRuntimeState() });
});

opsRouter.post('/maintenance', requireAdminToken, (req, res) => {
  const enabled = req.body?.enabled === true;
  const reason = typeof req.body?.reason === 'string' ? req.body.reason : '';
  const state = setMaintenanceMode(enabled, reason);
  res.json({ ok: true, state });
});

function asPositiveInt(raw: unknown, fallback: number, max: number): number {
  const value = parseInt(String(raw ?? fallback), 10);
  if (Number.isNaN(value) || value <= 0) return fallback;
  return Math.min(value, max);
}

opsRouter.get('/backups', requireAdminToken, (_req, res) => {
  const retentionCount = Math.max(1, parseInt(process.env.VAULT_BACKUP_RETENTION_COUNT ?? '20', 10));
  res.json({
    backupDir: backupDirPath(),
    databasePath: databasePath(),
    retentionCount,
    backups: listBackups(),
  });
});

opsRouter.post('/backups/create', requireAdminToken, async (req, res) => {
  try {
    const filename = typeof req.body?.filename === 'string' ? req.body.filename : undefined;
    const created = await createBackup(filename);
    const retention = enforceBackupRetention();
    res.status(201).json({ ok: true, created, retention });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

opsRouter.get('/backups/:filename/checksum', requireAdminToken, (req, res) => {
  try {
    const result = verifyBackupChecksum(req.params.filename);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

opsRouter.post('/backups/sign-download', requireAdminToken, (req, res) => {
  try {
    const filename = String(req.body?.filename ?? '').trim();
    if (!filename) {
      res.status(400).json({ error: 'filename is required' });
      return;
    }
    const expiresSeconds = asPositiveInt(req.body?.expiresSeconds, 300, 3600);
    const token = createSignedBackupToken('backup-download', filename, expiresSeconds);
    res.json({
      token,
      expiresSeconds,
      downloadUrl: `/api/ops/backups/download?token=${encodeURIComponent(token)}`,
    });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

opsRouter.get('/backups/download', (req, res) => {
  const raw = req.query.token;
  const token = typeof raw === 'string' ? raw : '';
  if (!token) {
    res.status(401).json({ error: 'token is required' });
    return;
  }

  try {
    const payload = verifySignedBackupToken(token, 'backup-download');
    const backups = listBackups();
    const hit = backups.find((b) => b.filename === payload.filename);
    if (!hit) {
      res.status(404).json({ error: 'Backup not found' });
      return;
    }

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${payload.filename}"`);
    res.sendFile(payload.filename, { root: backupDirPath() });
  } catch (err) {
    res.status(401).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

opsRouter.post('/backups/sign-upload', requireAdminToken, (req, res) => {
  try {
    const provided = typeof req.body?.filename === 'string' ? req.body.filename.trim() : '';
    const filename = provided || `vault-upload-${new Date().toISOString().replace(/[:.]/g, '-')}.db`;
    const expiresSeconds = asPositiveInt(req.body?.expiresSeconds, 300, 3600);
    const token = createSignedBackupToken('backup-upload', filename, expiresSeconds);
    res.json({
      token,
      filename,
      expiresSeconds,
      uploadMethod: 'PUT',
      uploadUrl: `/api/ops/backups/upload?token=${encodeURIComponent(token)}`,
      contentType: 'application/octet-stream',
    });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

opsRouter.put('/backups/upload', async (req, res) => {
  const raw = req.query.token;
  const token = typeof raw === 'string' ? raw : '';
  if (!token) {
    res.status(401).json({ error: 'token is required' });
    return;
  }

  try {
    const payload = verifySignedBackupToken(token, 'backup-upload');
    const uploaded = await writeUploadedBackup(payload.filename, req);
    const retention = enforceBackupRetention();
    res.status(201).json({ ok: true, uploaded, retention });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

opsRouter.post('/backups/restore', requireAdminToken, (req, res) => {
  if (getRuntimeState().restoreInProgress) {
    res.status(409).json({ error: 'A restore operation is already in progress' });
    return;
  }

  try {
    const filename = String(req.body?.filename ?? '').trim();
    if (!filename) {
      res.status(400).json({ error: 'filename is required' });
      return;
    }

    const expectedConfirm = `RESTORE ${filename}`;
    const confirm = String(req.body?.confirm ?? '').trim();
    if (confirm !== expectedConfirm) {
      res.status(400).json({
        error: 'restore confirmation mismatch',
        expectedConfirm,
      });
      return;
    }

    const verifyChecksum = req.body?.verifyChecksum !== false;
    setRestoreInProgress(true);
    const restored = restoreBackup(filename, verifyChecksum);
    res.json({ ok: true, ...restored });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  } finally {
    setRestoreInProgress(false);
  }
});
