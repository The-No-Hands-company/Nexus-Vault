import { getAuditChainStatus, verifyAuditChain } from './db.js';

function main() {
  const status = getAuditChainStatus();
  const result = verifyAuditChain();

  if (!result.ok) {
    console.error('[audit] chain verification FAILED');
    console.error(
      JSON.stringify(
        {
          ...result,
          ...status,
        },
        null,
        2,
      ),
    );
    process.exit(1);
  }

  console.log('[audit] chain verification OK');
  console.log(
    JSON.stringify(
      {
        ...result,
        ...status,
      },
      null,
      2,
    ),
  );
}

main();
