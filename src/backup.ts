import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { db } from './db.js';

function timestampForFilename(date: Date): string {
  return date.toISOString().replace(/[:]/g, '-').replace(/[.]/g, '_');
}

async function main() {
  const outputDir = process.env.VAULT_BACKUP_DIR ?? './backups';
  fs.mkdirSync(outputDir, { recursive: true });

  const filename = process.env.VAULT_BACKUP_FILENAME ?? `vault-${timestampForFilename(new Date())}.db`;
  const outputPath = path.join(outputDir, filename);

  await db.backup(outputPath);

  const hash = crypto.createHash('sha256').update(fs.readFileSync(outputPath)).digest('hex');
  const checksumPath = `${outputPath}.sha256`;
  fs.writeFileSync(checksumPath, `${hash}  ${path.basename(outputPath)}\n`, 'utf8');

  console.log(`[vault] Backup written to ${outputPath}`);
  console.log(`[vault] SHA256 checksum written to ${checksumPath}`);
}

main().catch((err) => {
  console.error('[vault] Backup failed:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
