import { Router } from 'express';
import { getTokenStateSummary, requireAdminToken, rotateTokensAtomic } from '../auth.js';
import { logAudit } from '../db.js';
import {
  backupDirPath,
  type BackupEncryptionInput,
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
import { incCounter } from '../metrics.js';

export const opsRouter = Router();

function clientIp(req: any): string {
  return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
    ?? req.socket.remoteAddress
    ?? 'unknown';
}

opsRouter.get('/state', requireAdminToken, (_req, res) => {
  res.json({ state: getRuntimeState() });
});

opsRouter.get('/tokens/state', requireAdminToken, (_req, res) => {
  res.json({ state: getTokenStateSummary() });
});

opsRouter.post('/tokens/rotate', requireAdminToken, (req, res) => {
  try {
    const mode = req.body?.mode === 'append' ? 'append' : 'replace';
    const accessTokens = Array.isArray(req.body?.accessTokens)
      ? req.body.accessTokens.map((value: unknown) => String(value).trim()).filter(Boolean)
      : undefined;
    const adminTokens = Array.isArray(req.body?.adminTokens)
      ? req.body.adminTokens.map((value: unknown) => String(value).trim()).filter(Boolean)
      : undefined;

    const result = rotateTokensAtomic({
      accessTokens,
      adminTokens,
      mode,
    });

    logAudit(
      '__auth__',
      'TOKEN_ROTATE',
      clientIp(req),
      String(req.headers['user-agent'] ?? ''),
      JSON.stringify({
        mode,
        rotatedAccessTokens: accessTokens?.length ?? 0,
        rotatedAdminTokens: adminTokens?.length ?? 0,
        resultingAccessCount: result.accessCount,
        resultingAdminCount: result.adminCount,
      }),
    );

    incCounter('vault_token_rotation_total', 'Total token rotation operations', 1, {
      result: 'ok',
      mode,
    });

    res.json({ ok: true, ...result });
  } catch (err) {
    incCounter('vault_token_rotation_total', 'Total token rotation operations', 1, {
      result: 'failed',
    });
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
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
    let encryption: BackupEncryptionInput | undefined;
    if (req.body?.encryption && typeof req.body.encryption === 'object') {
      const mode: BackupEncryptionInput['mode'] = req.body.encryption.mode === 'kms-envelope'
        ? 'kms-envelope'
        : 'passphrase';
      const passphrase = typeof req.body.encryption.passphrase === 'string'
        ? req.body.encryption.passphrase
        : undefined;
      encryption = { mode, passphrase };
    }
    const created = await createBackup(filename, encryption ? { encryption } : undefined);
    const retention = enforceBackupRetention();
    incCounter('vault_ops_backup_create_total', 'Total backup create operations', 1, {
      result: 'ok',
      encrypted: created.encrypted,
    });
    res.status(201).json({ ok: true, created, retention });
  } catch (err) {
    incCounter('vault_ops_backup_create_total', 'Total backup create operations', 1, {
      result: 'failed',
    });
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
    incCounter('vault_ops_backup_download_total', 'Total backup downloads', 1, {
      result: 'ok',
    });
    res.sendFile(payload.filename, { root: backupDirPath() });
  } catch (err) {
    incCounter('vault_ops_backup_download_total', 'Total backup downloads', 1, {
      result: 'failed',
    });
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
    const encryptionMode = String(req.query.encryption ?? '').toLowerCase();
    const passphrase = typeof req.headers['x-vault-backup-passphrase'] === 'string'
      ? req.headers['x-vault-backup-passphrase']
      : undefined;
    let encryption: BackupEncryptionInput | undefined;
    if (encryptionMode === 'passphrase' || encryptionMode === 'kms-envelope') {
      const mode: BackupEncryptionInput['mode'] = encryptionMode;
      encryption = { mode, passphrase };
    }

    const uploaded = await writeUploadedBackup(payload.filename, req, encryption ? { encryption } : undefined);
    const retention = enforceBackupRetention();
    incCounter('vault_ops_backup_upload_total', 'Total backup uploads', 1, {
      result: 'ok',
      encrypted: uploaded.encrypted,
    });
    res.status(201).json({ ok: true, uploaded, retention });
  } catch (err) {
    incCounter('vault_ops_backup_upload_total', 'Total backup uploads', 1, {
      result: 'failed',
    });
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
    const passphrase = typeof req.body?.passphrase === 'string' ? req.body.passphrase : undefined;
    setRestoreInProgress(true);
    const restored = restoreBackup(filename, verifyChecksum, { passphrase });
    incCounter('vault_ops_backup_restore_total', 'Total backup restore operations', 1, {
      result: 'ok',
    });
    res.json({ ok: true, ...restored });
  } catch (err) {
    incCounter('vault_ops_backup_restore_total', 'Total backup restore operations', 1, {
      result: 'failed',
    });
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  } finally {
    setRestoreInProgress(false);
  }
});
