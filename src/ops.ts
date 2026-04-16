import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { DB_PATH, db } from './db.js';

type SignedAction = 'backup-download' | 'backup-upload';

type SignedTokenPayload = {
  action: SignedAction;
  filename: string;
  exp: number;
};

export type BackupRecord = {
  filename: string;
  bytes: number;
  createdAt: string;
  sha256: string | null;
  encrypted: boolean;
  encryptionMode: 'none' | 'passphrase' | 'kms-envelope';
};

type BackupEncryptionMeta = {
  version: 1;
  algorithm: 'aes-256-gcm';
  mode: 'passphrase' | 'kms-envelope';
  iv: string;
  tag: string;
  salt?: string;
  wrappedKey?: string;
  wrapIv?: string;
  wrapTag?: string;
};

export type BackupEncryptionInput = {
  mode: 'passphrase' | 'kms-envelope';
  passphrase?: string;
};

export type CreateBackupOptions = {
  encryption?: BackupEncryptionInput;
};

function timestampForFilename(date: Date): string {
  return date.toISOString().replace(/[:]/g, '-').replace(/[.]/g, '_');
}

function normalizeBackupDir(): string {
  const outputDir = process.env.VAULT_BACKUP_DIR ?? './backups';
  fs.mkdirSync(outputDir, { recursive: true });
  return outputDir;
}

function safeBackupName(filename: string): string {
  const value = filename.trim();
  if (!/^[A-Za-z0-9._-]+\.db(\.enc)?$/.test(value)) {
    throw new Error('Invalid backup filename. Expected pattern: [A-Za-z0-9._-]+.db(.enc)');
  }
  return value;
}

function backupSigningSecret(): string {
  const value = process.env.VAULT_BACKUP_SIGNING_SECRET?.trim();
  if (value) return value;
  return process.env.VAULT_ADMIN_TOKEN ?? '';
}

function maxUploadBytes(): number {
  const mb = Math.max(1, parseInt(process.env.VAULT_BACKUP_MAX_UPLOAD_MB ?? '50', 10));
  return mb * 1024 * 1024;
}

function retentionCount(): number {
  return Math.max(1, parseInt(process.env.VAULT_BACKUP_RETENTION_COUNT ?? '20', 10));
}

function toBackupPath(filename: string): string {
  const dir = normalizeBackupDir();
  const name = safeBackupName(filename);
  const full = path.resolve(path.join(dir, name));
  const base = path.resolve(dir) + path.sep;
  if (!full.startsWith(base)) {
    throw new Error('Invalid backup path');
  }
  return full;
}

function shaPathFor(backupPath: string): string {
  return `${backupPath}.sha256`;
}

function metaPathFor(backupPath: string): string {
  return `${backupPath}.meta.json`;
}

function readEncryptionMeta(backupPath: string): BackupEncryptionMeta | null {
  const metaPath = metaPathFor(backupPath);
  if (!fs.existsSync(metaPath)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(metaPath, 'utf8')) as BackupEncryptionMeta;
    if (!parsed || parsed.version !== 1 || parsed.algorithm !== 'aes-256-gcm') return null;
    return parsed;
  } catch {
    return null;
  }
}

function writeEncryptionMeta(backupPath: string, meta: BackupEncryptionMeta): void {
  fs.writeFileSync(metaPathFor(backupPath), JSON.stringify(meta, null, 2), 'utf8');
}

function removeEncryptionMeta(backupPath: string): void {
  const metaPath = metaPathFor(backupPath);
  if (fs.existsSync(metaPath)) {
    fs.unlinkSync(metaPath);
  }
}

function parseKmsMasterKey(): Buffer | null {
  const raw = process.env.VAULT_BACKUP_KMS_MASTER_KEY?.trim();
  if (!raw) return null;
  if (/^[a-fA-F0-9]{64}$/.test(raw)) return Buffer.from(raw, 'hex');
  try {
    const b64 = Buffer.from(raw, 'base64');
    if (b64.length >= 32) return crypto.createHash('sha256').update(b64).digest();
  } catch {
    // Fall through.
  }
  return crypto.createHash('sha256').update(raw, 'utf8').digest();
}

function encryptBufferWithKey(data: Buffer, key: Buffer): { encrypted: Buffer; iv: Buffer; tag: Buffer } {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { encrypted, iv, tag };
}

function decryptBufferWithKey(data: Buffer, key: Buffer, iv: Buffer, tag: Buffer): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function encryptBackupAtRest(backupPath: string, config: BackupEncryptionInput): void {
  const plain = fs.readFileSync(backupPath);

  if (config.mode === 'passphrase') {
    const passphrase = config.passphrase?.trim() || '';
    if (!passphrase) throw new Error('passphrase is required for passphrase backup encryption');
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync(passphrase, salt, 32);
    const { encrypted, iv, tag } = encryptBufferWithKey(plain, key);
    fs.writeFileSync(backupPath, encrypted);
    writeEncryptionMeta(backupPath, {
      version: 1,
      algorithm: 'aes-256-gcm',
      mode: 'passphrase',
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      salt: salt.toString('base64'),
    });
    return;
  }

  const kmsKey = parseKmsMasterKey();
  if (!kmsKey) throw new Error('VAULT_BACKUP_KMS_MASTER_KEY is required for kms-envelope backup encryption');
  const dataKey = crypto.randomBytes(32);
  const payload = encryptBufferWithKey(plain, dataKey);
  const wrapped = encryptBufferWithKey(dataKey, kmsKey);

  fs.writeFileSync(backupPath, payload.encrypted);
  writeEncryptionMeta(backupPath, {
    version: 1,
    algorithm: 'aes-256-gcm',
    mode: 'kms-envelope',
    iv: payload.iv.toString('base64'),
    tag: payload.tag.toString('base64'),
    wrappedKey: wrapped.encrypted.toString('base64'),
    wrapIv: wrapped.iv.toString('base64'),
    wrapTag: wrapped.tag.toString('base64'),
  });
}

function computeSha256(filePath: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function readStoredChecksum(backupPath: string): string | null {
  const checksumPath = shaPathFor(backupPath);
  if (!fs.existsSync(checksumPath)) return null;
  const raw = fs.readFileSync(checksumPath, 'utf8').trim();
  const token = raw.split(/\s+/)[0]?.toLowerCase() ?? '';
  return /^[a-f0-9]{64}$/.test(token) ? token : null;
}

function writeChecksum(backupPath: string): string {
  const hash = computeSha256(backupPath);
  const checksumPath = shaPathFor(backupPath);
  fs.writeFileSync(checksumPath, `${hash}  ${path.basename(backupPath)}\n`, 'utf8');
  return hash;
}

function toRecord(filePath: string): BackupRecord {
  const st = fs.statSync(filePath);
  const sha256 = readStoredChecksum(filePath);
  const meta = readEncryptionMeta(filePath);
  return {
    filename: path.basename(filePath),
    bytes: st.size,
    createdAt: st.mtime.toISOString(),
    sha256,
    encrypted: Boolean(meta),
    encryptionMode: meta?.mode ?? 'none',
  };
}

export function listBackups(): BackupRecord[] {
  const dir = normalizeBackupDir();
  const files = fs.readdirSync(dir)
    .filter((name) => name.endsWith('.db') || name.endsWith('.db.enc'))
    .map((name) => path.join(dir, name))
    .filter((file) => fs.statSync(file).isFile())
    .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);

  return files.map(toRecord);
}

export function enforceBackupRetention(): { deleted: string[]; kept: number } {
  const keep = retentionCount();
  const backups = listBackups();
  const toDelete = backups.slice(keep);
  const deleted: string[] = [];

  for (const item of toDelete) {
    const filePath = toBackupPath(item.filename);
    try {
      fs.unlinkSync(filePath);
      const checksumPath = shaPathFor(filePath);
      if (fs.existsSync(checksumPath)) fs.unlinkSync(checksumPath);
      removeEncryptionMeta(filePath);
      deleted.push(item.filename);
    } catch {
      // Best-effort retention cleanup.
    }
  }

  return { deleted, kept: Math.min(backups.length, keep) };
}

export async function createBackup(filename?: string, options: CreateBackupOptions = {}): Promise<BackupRecord> {
  const defaultName = `vault-${timestampForFilename(new Date())}${options.encryption ? '.db.enc' : '.db'}`;
  const actualName = safeBackupName(filename?.trim() || defaultName);
  const backupPath = toBackupPath(actualName);
  await db.backup(backupPath);
  if (options.encryption) {
    encryptBackupAtRest(backupPath, options.encryption);
  } else {
    removeEncryptionMeta(backupPath);
  }
  writeChecksum(backupPath);
  enforceBackupRetention();
  return toRecord(backupPath);
}

export function verifyBackupChecksum(filename: string): { ok: boolean; expected: string | null; actual: string } {
  const backupPath = toBackupPath(filename);
  const expected = readStoredChecksum(backupPath);
  const actual = computeSha256(backupPath);
  if (!expected) return { ok: true, expected: null, actual };
  return { ok: expected === actual, expected, actual };
}

export function createSignedBackupToken(action: SignedAction, filename: string, expiresSeconds: number): string {
  const secret = backupSigningSecret();
  if (!secret) throw new Error('Backup signing secret is not configured');

  const payload: SignedTokenPayload = {
    action,
    filename: safeBackupName(filename),
    exp: Math.floor(Date.now() / 1000) + Math.max(30, Math.min(expiresSeconds, 3600)),
  };

  const serialized = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(serialized).digest('hex');
  return `${serialized}.${signature}`;
}

export function verifySignedBackupToken(token: string, action: SignedAction): SignedTokenPayload {
  const secret = backupSigningSecret();
  if (!secret) throw new Error('Backup signing secret is not configured');

  const [serialized, signature] = token.split('.');
  if (!serialized || !signature) throw new Error('Invalid backup token format');

  const expectedSig = crypto.createHmac('sha256', secret).update(serialized).digest('hex');
  const sigA = Buffer.from(signature, 'hex');
  const sigB = Buffer.from(expectedSig, 'hex');
  if (sigA.length !== sigB.length || sigA.length === 0 || !crypto.timingSafeEqual(sigA, sigB)) {
    throw new Error('Invalid backup token signature');
  }

  let payload: SignedTokenPayload;
  try {
    payload = JSON.parse(Buffer.from(serialized, 'base64url').toString('utf8')) as SignedTokenPayload;
  } catch {
    throw new Error('Invalid backup token payload');
  }

  if (payload.action !== action) throw new Error('Backup token action mismatch');
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Backup token expired');
  safeBackupName(payload.filename);
  return payload;
}

export async function writeUploadedBackup(
  filename: string,
  body: NodeJS.ReadableStream,
  options: CreateBackupOptions = {},
): Promise<BackupRecord> {
  const backupPath = toBackupPath(filename);
  const maxBytes = maxUploadBytes();

  const chunks: Buffer[] = [];
  let total = 0;

  await new Promise<void>((resolve, reject) => {
    body.on('data', (chunk) => {
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += data.length;
      if (total > maxBytes) {
        reject(new Error(`Backup upload exceeds max size of ${maxBytes} bytes`));
        return;
      }
      chunks.push(data);
    });
    body.on('end', () => resolve());
    body.on('error', (err) => reject(err));
  });

  if (total === 0) {
    throw new Error('Backup upload payload is empty');
  }

  fs.writeFileSync(backupPath, Buffer.concat(chunks));
  if (options.encryption) {
    encryptBackupAtRest(backupPath, options.encryption);
  } else {
    removeEncryptionMeta(backupPath);
  }
  writeChecksum(backupPath);
  enforceBackupRetention();
  return toRecord(backupPath);
}

export function restoreBackup(
  filename: string,
  verifyChecksum = true,
  options: { passphrase?: string } = {},
): { restored: string; rows: Record<string, number> } {
  const backupPath = toBackupPath(filename);
  if (!fs.existsSync(backupPath)) {
    throw new Error('Backup file not found');
  }

  if (verifyChecksum) {
    const checksum = verifyBackupChecksum(filename);
    if (!checksum.ok) {
      throw new Error('Backup checksum verification failed');
    }
  }

  const meta = readEncryptionMeta(backupPath);
  let attachPath = backupPath;
  let tempPath: string | null = null;

  if (meta) {
    const encrypted = fs.readFileSync(backupPath);
    const iv = Buffer.from(meta.iv, 'base64');
    const tag = Buffer.from(meta.tag, 'base64');

    let plain: Buffer;
    if (meta.mode === 'passphrase') {
      const passphrase = options.passphrase?.trim() || '';
      if (!passphrase) {
        throw new Error('passphrase is required to restore this encrypted backup');
      }
      const salt = Buffer.from(meta.salt ?? '', 'base64');
      const key = crypto.scryptSync(passphrase, salt, 32);
      plain = decryptBufferWithKey(encrypted, key, iv, tag);
    } else {
      const kmsKey = parseKmsMasterKey();
      if (!kmsKey) {
        throw new Error('VAULT_BACKUP_KMS_MASTER_KEY is required to restore kms-envelope backups');
      }
      const wrappedKey = Buffer.from(meta.wrappedKey ?? '', 'base64');
      const wrapIv = Buffer.from(meta.wrapIv ?? '', 'base64');
      const wrapTag = Buffer.from(meta.wrapTag ?? '', 'base64');
      const dataKey = decryptBufferWithKey(wrappedKey, kmsKey, wrapIv, wrapTag);
      plain = decryptBufferWithKey(encrypted, dataKey, iv, tag);
    }

    tempPath = path.join(normalizeBackupDir(), `.restore-${Date.now()}-${Math.random().toString(16).slice(2)}.db`);
    fs.writeFileSync(tempPath, plain);
    attachPath = tempPath;
  }

  const escaped = attachPath.replace(/'/g, "''");
  db.exec(`ATTACH DATABASE '${escaped}' AS restore_src`);

  const hasTableStmt = db.prepare<[string], { ok: number }>(
    `SELECT 1 as ok FROM restore_src.sqlite_master WHERE type='table' AND name=? LIMIT 1`
  );

  const hasTable = (name: string): boolean => Boolean(hasTableStmt.get(name));

  const copy = db.transaction(() => {
    db.exec(`
      DELETE FROM vault_entries;
      DELETE FROM vault_collections;
      DELETE FROM vault_import_exports;
      DELETE FROM audit_log;
      DELETE FROM audit_verification_runs;
      DELETE FROM sqlite_sequence
      WHERE name IN ('vault_entries', 'vault_collections', 'vault_import_exports', 'audit_log', 'audit_verification_runs');
    `);

    if (hasTable('vault_collections')) {
      db.exec(`
        INSERT INTO vault_collections (id, name, description, parent_id, icon, color, created_at, updated_at, is_active)
        SELECT id, name, description, NULL, icon, color, created_at, updated_at, is_active
        FROM restore_src.vault_collections
        ORDER BY id ASC;

        UPDATE vault_collections
        SET parent_id = (
          SELECT src.parent_id
          FROM restore_src.vault_collections src
          WHERE src.id = vault_collections.id
        );
      `);
    }

    if (hasTable('vault_entries')) {
      db.exec(`
        INSERT INTO vault_entries (
          id, type, category, name, value_enc, tags, collection_id, project, notes, metadata,
          created_at, updated_at, expires_at, last_accessed, access_count, is_active
        )
        SELECT
          id, type, category, name, value_enc, tags, collection_id, project, notes, metadata,
          created_at, updated_at, expires_at, last_accessed, access_count, is_active
        FROM restore_src.vault_entries
        ORDER BY id ASC;
      `);
    }

    if (hasTable('vault_import_exports')) {
      db.exec(`
        INSERT INTO vault_import_exports (id, kind, format, filename, metadata, created_at)
        SELECT id, kind, format, filename, metadata, created_at
        FROM restore_src.vault_import_exports
        ORDER BY id ASC;
      `);
    }

    if (hasTable('audit_log')) {
      db.exec(`
        INSERT INTO audit_log (id, entry_name, action, ip, user_agent, meta, timestamp, prev_hash)
        SELECT id, entry_name, action, ip, user_agent, meta, timestamp, prev_hash
        FROM restore_src.audit_log
        ORDER BY id ASC;
      `);
    }

    if (hasTable('audit_verification_runs')) {
      db.exec(`
        INSERT INTO audit_verification_runs (
          id, source, ok, broken_at, expected_hash, got_hash,
          total_entries, head_id, head_hash, genesis_ok, details, alert_sent, created_at
        )
        SELECT
          id, source, ok, broken_at, expected_hash, got_hash,
          total_entries, head_id, head_hash, genesis_ok, details, alert_sent, created_at
        FROM restore_src.audit_verification_runs
        ORDER BY id ASC;
      `);
    }
  });

  try {
    copy();
  } finally {
    db.exec('DETACH DATABASE restore_src');
    if (tempPath && fs.existsSync(tempPath)) {
      fs.unlinkSync(tempPath);
    }
  }

  const counts = {
    collections: Number(db.prepare<[], { count: number }>('SELECT COUNT(*) AS count FROM vault_collections').get()?.count ?? 0),
    entries: Number(db.prepare<[], { count: number }>('SELECT COUNT(*) AS count FROM vault_entries').get()?.count ?? 0),
    importsExports: Number(db.prepare<[], { count: number }>('SELECT COUNT(*) AS count FROM vault_import_exports').get()?.count ?? 0),
    auditEvents: Number(db.prepare<[], { count: number }>('SELECT COUNT(*) AS count FROM audit_log').get()?.count ?? 0),
    auditVerificationRuns: Number(db.prepare<[], { count: number }>('SELECT COUNT(*) AS count FROM audit_verification_runs').get()?.count ?? 0),
  };

  return { restored: filename, rows: counts };
}

export function restoreBackupDrill(
  filename: string,
  verifyChecksum = true,
  options: { passphrase?: string } = {},
): {
  drill: string;
  rows: Record<string, number>;
  integrityOk: boolean;
  integrityMessage: string;
  encrypted: boolean;
  encryptionMode: 'none' | 'passphrase' | 'kms-envelope';
} {
  const backupPath = toBackupPath(filename);
  if (!fs.existsSync(backupPath)) {
    throw new Error('Backup file not found');
  }

  if (verifyChecksum) {
    const checksum = verifyBackupChecksum(filename);
    if (!checksum.ok) {
      throw new Error('Backup checksum verification failed');
    }
  }

  const meta = readEncryptionMeta(backupPath);
  let attachPath = backupPath;
  let tempPath: string | null = null;

  if (meta) {
    const encrypted = fs.readFileSync(backupPath);
    const iv = Buffer.from(meta.iv, 'base64');
    const tag = Buffer.from(meta.tag, 'base64');

    let plain: Buffer;
    if (meta.mode === 'passphrase') {
      const passphrase = options.passphrase?.trim() || '';
      if (!passphrase) {
        throw new Error('passphrase is required to drill this encrypted backup');
      }
      const salt = Buffer.from(meta.salt ?? '', 'base64');
      const key = crypto.scryptSync(passphrase, salt, 32);
      plain = decryptBufferWithKey(encrypted, key, iv, tag);
    } else {
      const kmsKey = parseKmsMasterKey();
      if (!kmsKey) {
        throw new Error('VAULT_BACKUP_KMS_MASTER_KEY is required to drill kms-envelope backups');
      }
      const wrappedKey = Buffer.from(meta.wrappedKey ?? '', 'base64');
      const wrapIv = Buffer.from(meta.wrapIv ?? '', 'base64');
      const wrapTag = Buffer.from(meta.wrapTag ?? '', 'base64');
      const dataKey = decryptBufferWithKey(wrappedKey, kmsKey, wrapIv, wrapTag);
      plain = decryptBufferWithKey(encrypted, dataKey, iv, tag);
    }

    tempPath = path.join(normalizeBackupDir(), `.drill-${Date.now()}-${Math.random().toString(16).slice(2)}.db`);
    fs.writeFileSync(tempPath, plain);
    attachPath = tempPath;
  }

  const escaped = attachPath.replace(/'/g, "''");
  db.exec(`ATTACH DATABASE '${escaped}' AS restore_drill`);

  try {
    const hasTableStmt = db.prepare<[string], { ok: number }>(
      `SELECT 1 as ok FROM restore_drill.sqlite_master WHERE type='table' AND name=? LIMIT 1`
    );
    const hasTable = (name: string): boolean => Boolean(hasTableStmt.get(name));

    const countFromAttached = (table: string): number => {
      if (!hasTable(table)) return 0;
      const row = db.prepare<[], { count: number }>(`SELECT COUNT(*) AS count FROM restore_drill.${table}`).get();
      return Number(row?.count ?? 0);
    };

    const integrityRows = db.prepare<[], { integrity_check: string }>('PRAGMA restore_drill.integrity_check').all();
    const integrityMessage = integrityRows.map((row) => row.integrity_check).join('; ') || 'unknown';
    const integrityOk = integrityRows.length > 0 && integrityRows.every((row) => row.integrity_check === 'ok');

    return {
      drill: filename,
      rows: {
        collections: countFromAttached('vault_collections'),
        entries: countFromAttached('vault_entries'),
        importsExports: countFromAttached('vault_import_exports'),
        auditEvents: countFromAttached('audit_log'),
        auditVerificationRuns: countFromAttached('audit_verification_runs'),
      },
      integrityOk,
      integrityMessage,
      encrypted: Boolean(meta),
      encryptionMode: meta?.mode ?? 'none',
    };
  } finally {
    db.exec('DETACH DATABASE restore_drill');
    if (tempPath && fs.existsSync(tempPath)) {
      fs.unlinkSync(tempPath);
    }
  }
}

export function backupDirPath(): string {
  return normalizeBackupDir();
}

export function databasePath(): string {
  return DB_PATH;
}
