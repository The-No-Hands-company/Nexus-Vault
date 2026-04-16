import { getAppliedMigrations, runMigrations } from './db.js';

function main() {
  const executed = runMigrations();
  const applied = getAppliedMigrations();

  if (executed.length) {
    console.log(`[vault] Applied migrations: ${executed.join(', ')}`);
  } else {
    console.log('[vault] No new migrations to apply.');
  }

  console.log(`[vault] Total applied migrations: ${applied.length}`);
}

main();
