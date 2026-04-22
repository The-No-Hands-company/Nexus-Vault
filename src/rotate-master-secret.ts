/**
 * Master Secret Rotation
 *
 * Re-encrypts every vault entry and version with a new VAULT_MASTER_SECRET
 * inside a single atomic SQLite transaction. If any value fails to
 * decrypt/re-encrypt the whole operation is rolled back — the database
 * is never left in a partially rotated state.
 *
 * Usage:
 *   OLD_VAULT_MASTER_SECRET="<current secret>" \
 *   VAULT_MASTER_SECRET="<new secret>" \
 *   tsx src/rotate-master-secret.ts
 *
 * After a successful run:
 *   1. Update VAULT_MASTER_SECRET in your .env / secrets manager.
 *   2. Restart the vault service.
 *   3. Create a fresh backup — old backups are still readable with the
 *      old secret, but new backups will require the new secret.
 */

import { db } from './db.js';
import { encrypt, decrypt } from './crypto.js';

type EntryRow = { id: number; name: string; value_enc: string };
type VersionRow = { id: number; entry_name: string; version: number; value_enc: string };

function main(): void {
  const oldSecret = process.env.OLD_VAULT_MASTER_SECRET?.trim();
  const newSecret = process.env.VAULT_MASTER_SECRET?.trim();

  if (!oldSecret) {
    console.error('[rotate] OLD_VAULT_MASTER_SECRET is required');
    process.exit(1);
  }
  if (!newSecret) {
    console.error('[rotate] VAULT_MASTER_SECRET is required');
    process.exit(1);
  }
  if (oldSecret === newSecret) {
    console.error('[rotate] OLD_VAULT_MASTER_SECRET and VAULT_MASTER_SECRET are identical — nothing to do');
    process.exit(1);
  }

  const entries = db
    .prepare<[], EntryRow>('SELECT id, name, value_enc FROM vault_entries')
    .all();

  const versions = db
    .prepare<[], VersionRow>('SELECT id, entry_name, version, value_enc FROM vault_entry_versions')
    .all();

  console.log(
    `[rotate] Starting rotation: ${entries.length} active entries + ${versions.length} archived versions`,
  );

  const updateEntry = db.prepare<[string, number], void>(
    'UPDATE vault_entries SET value_enc = ? WHERE id = ?',
  );
  const updateVersion = db.prepare<[string, number], void>(
    'UPDATE vault_entry_versions SET value_enc = ? WHERE id = ?',
  );

  let rotated = 0;

  // Single transaction — any failure rolls back the entire operation.
  db.transaction(() => {
    for (const row of entries) {
      let plain: string;
      try {
        plain = decrypt(row.value_enc, oldSecret);
      } catch (err) {
        throw new Error(
          `Failed to decrypt entry "${row.name}" (id=${row.id}): ${err instanceof Error ? err.message : String(err)}. ` +
          'Ensure OLD_VAULT_MASTER_SECRET is correct.',
        );
      }
      updateEntry.run(encrypt(plain, newSecret), row.id);
      rotated++;
    }

    for (const row of versions) {
      let plain: string;
      try {
        plain = decrypt(row.value_enc, oldSecret);
      } catch (err) {
        throw new Error(
          `Failed to decrypt version "${row.entry_name}" v${row.version} (id=${row.id}): ${err instanceof Error ? err.message : String(err)}. ` +
          'Ensure OLD_VAULT_MASTER_SECRET is correct.',
        );
      }
      updateVersion.run(encrypt(plain, newSecret), row.id);
      rotated++;
    }
  })();

  console.log(`[rotate] Done — ${rotated} values re-encrypted successfully.`);
  console.log('[rotate] Next steps:');
  console.log('  1. Update VAULT_MASTER_SECRET in your environment / secrets manager.');
  console.log('  2. Restart the vault service.');
  console.log('  3. Run: npm run backup  (create a fresh backup with the new key).');
}

try {
  main();
} catch (err) {
  console.error('[rotate] ABORTED — database was NOT modified.');
  console.error('[rotate]', err instanceof Error ? err.message : String(err));
  process.exit(1);
}
