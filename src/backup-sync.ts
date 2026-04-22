/**
 * Cloud backup sync — uploads vault backups to S3 or any S3-compatible object store.
 *
 * Required env vars:
 *   VAULT_BACKUP_S3_BUCKET   — target bucket name
 *
 * Optional env vars:
 *   VAULT_BACKUP_S3_REGION   — AWS region (default: us-east-1)
 *   VAULT_BACKUP_S3_PREFIX   — key prefix inside the bucket (default: nexus-vault)
 *   VAULT_BACKUP_S3_ENDPOINT — override endpoint URL for GCS / MinIO / R2 / etc.
 *   AWS_ACCESS_KEY_ID        — credentials (can also come from IAM role / workload identity)
 *   AWS_SECRET_ACCESS_KEY    — credentials
 */

import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import fs from 'fs';
import path from 'path';

export type SyncResult =
  | { uploaded: true; bucket: string; key: string }
  | { uploaded: false; skipped?: true; error?: string };

function buildClient(): S3Client {
  const region = process.env.VAULT_BACKUP_S3_REGION?.trim() ?? 'us-east-1';
  const endpoint = process.env.VAULT_BACKUP_S3_ENDPOINT?.trim();
  return new S3Client({
    region,
    ...(endpoint ? { endpoint, forcePathStyle: true } : {}),
  });
}

/**
 * Uploads a backup file (and its .sha256 checksum) to S3/GCS.
 * Returns { uploaded: false, skipped: true } if VAULT_BACKUP_S3_BUCKET is not set.
 */
export async function syncBackupToCloud(backupPath: string): Promise<SyncResult> {
  const bucket = process.env.VAULT_BACKUP_S3_BUCKET?.trim();
  if (!bucket) {
    return { uploaded: false, skipped: true };
  }

  const prefix = (process.env.VAULT_BACKUP_S3_PREFIX?.trim() ?? 'nexus-vault').replace(/\/$/, '');
  const filename = path.basename(backupPath);
  const key = `${prefix}/${filename}`;

  const client = buildClient();

  try {
    await client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: fs.readFileSync(backupPath),
        ContentType: 'application/octet-stream',
      }),
    );

    // Upload matching checksum file when present.
    const checksumPath = `${backupPath}.sha256`;
    if (fs.existsSync(checksumPath)) {
      await client.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: `${key}.sha256`,
          Body: fs.readFileSync(checksumPath),
          ContentType: 'text/plain',
        }),
      );
    }

    return { uploaded: true, bucket, key };
  } catch (err) {
    return { uploaded: false, error: err instanceof Error ? err.message : String(err) };
  }
}
