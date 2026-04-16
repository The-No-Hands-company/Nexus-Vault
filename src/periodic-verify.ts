import {
  getAuditChainStatus,
  getLastAuditVerificationRun,
  recordAuditVerificationRun,
  verifyAuditChain,
} from './db.js';
import { sendAuditFailureEmail } from './mail.js';
import { incCounter } from './metrics.js';

export interface VerificationResult {
  timestamp: string;
  ok: boolean;
  status: ReturnType<typeof getAuditChainStatus>;
  verification: ReturnType<typeof verifyAuditChain>;
  details?: string;
}

export interface VerificationOptions {
  source?: 'periodic' | 'startup' | 'manual';
  sendAlertsOnFailure?: boolean;
}

let lastResult: VerificationResult | null = null;
let lastAlertTime = 0;

/**
 * Send alert via webhook or email
 */
async function sendAlert(result: VerificationResult): Promise<boolean> {
  const webhookUrl = process.env.VAULT_ALERT_WEBHOOK_URL?.trim();
  const alertEmail = process.env.VAULT_ALERT_EMAIL?.trim();
  const alertThrottle = parseInt(process.env.VAULT_ALERT_THROTTLE_MINUTES ?? '60', 10);

  // Throttle alerts to prevent spam
  const now = Date.now();
  if (now - lastAlertTime < alertThrottle * 60 * 1000) {
    console.warn('[vault:periodic] Alert throttled (last alert within throttle window)');
    incCounter('vault_alerts_total', 'Total alert attempts and outcomes', 1, {
      channel: 'throttle',
      result: 'throttled',
    });
    return false;
  }

  let anyAlertSent = false;

  const payload = {
    service: 'nexus-vault',
    severity: 'critical',
    type: 'audit-integrity-failure',
    timestamp: result.timestamp,
    status: result.status,
    verification: {
      ok: result.verification.ok,
      ...(result.verification.ok ? {} : {
        brokenAt: (result.verification as any).brokenAt,
        expected: (result.verification as any).expected,
        got: (result.verification as any).got,
      }),
    },
    details: result.details,
  };

  // Webhook alert
  if (webhookUrl) {
    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) {
        console.error(`[vault:periodic] Webhook alert failed: ${response.status} ${response.statusText}`);
        incCounter('vault_alerts_total', 'Total alert attempts and outcomes', 1, {
          channel: 'webhook',
          result: 'failed',
        });
      } else {
        console.log('[vault:periodic] Webhook alert sent successfully');
        incCounter('vault_alerts_total', 'Total alert attempts and outcomes', 1, {
          channel: 'webhook',
          result: 'sent',
        });
        anyAlertSent = true;
        lastAlertTime = now;
      }
    } catch (err) {
      console.error('[vault:periodic] Webhook alert error:', err instanceof Error ? err.message : String(err));
      incCounter('vault_alerts_total', 'Total alert attempts and outcomes', 1, {
        channel: 'webhook',
        result: 'error',
      });
    }
  }

  // Email alert (simplified — would integrate with mail service)
  if (alertEmail) {
    const subject = '[Nexus Vault] Audit Integrity Failure';
    const text = [
      'Nexus Vault detected an audit integrity failure.',
      '',
      `Time: ${result.timestamp}`,
      `Details: ${result.details ?? 'n/a'}`,
      `Total entries: ${result.status.totalEntries}`,
      `Head ID: ${result.status.headId ?? 'none'}`,
      `Genesis OK: ${result.status.genesisOk}`,
    ].join('\n');
    const sent = await sendAuditFailureEmail(alertEmail, subject, text);
    if (sent) {
      incCounter('vault_alerts_total', 'Total alert attempts and outcomes', 1, {
        channel: 'email',
        result: 'sent',
      });
      anyAlertSent = true;
      lastAlertTime = now;
    } else {
      incCounter('vault_alerts_total', 'Total alert attempts and outcomes', 1, {
        channel: 'email',
        result: 'failed',
      });
    }
  }

  return anyAlertSent;
}

/**
 * Perform a single integrity verification
 */
export async function performVerification(options: VerificationOptions = {}): Promise<VerificationResult> {
  const source = options.source ?? 'periodic';
  const sendAlertsOnFailure = options.sendAlertsOnFailure ?? true;
  const status = getAuditChainStatus();
  const verification = verifyAuditChain();

  const result: VerificationResult = {
    timestamp: new Date().toISOString(),
    ok: verification.ok,
    status,
    verification,
    details: verification.ok
      ? `Audit chain verified: ${status.totalEntries} entries, head_id=${status.headId ?? 'none'}`
      : `Audit integrity failure at entry ${(verification as any).brokenAt}: hash mismatch`,
  };

  lastResult = result;
  let alertSent = false;

  // Log result
  if (result.ok) {
    console.log(`[vault:periodic] ✓ Verification passed: ${result.details}`);
    incCounter('vault_audit_verify_runs_total', 'Total audit verification runs', 1, {
      source,
      result: 'ok',
    });
  } else {
    console.error(`[vault:periodic] ✗ Verification failed: ${result.details}`);
    incCounter('vault_audit_verify_runs_total', 'Total audit verification runs', 1, {
      source,
      result: 'failed',
    });
    if (sendAlertsOnFailure) {
      alertSent = await sendAlert(result);
    }
  }

  recordAuditVerificationRun({
    source,
    ok: result.ok,
    status,
    verification,
    details: result.details ?? '',
    alertSent,
  });

  return result;
}

/**
 * Get last verification result
 */
export function getLastVerificationResult(): VerificationResult | null {
  if (lastResult) return lastResult;
  const persisted = getLastAuditVerificationRun();
  if (!persisted) return null;

  return {
    timestamp: persisted.created_at,
    ok: persisted.ok === 1,
    status: {
      totalEntries: persisted.total_entries,
      headId: persisted.head_id,
      headHash: persisted.head_hash,
      genesisOk: persisted.genesis_ok === 1,
    },
    verification: persisted.ok === 1
      ? { ok: true }
      : {
        ok: false,
        brokenAt: persisted.broken_at ?? -1,
        expected: persisted.expected_hash ?? '',
        got: persisted.got_hash ?? '',
      },
    details: persisted.details,
  };
}

/**
 * Reset last verification result (for testing)
 */
export function _resetVerificationResult(): void {
  lastResult = null;
  lastAlertTime = 0;
}

/**
 * Start periodic verification background job
 */
export function startPeriodicVerification(): NodeJS.Timeout | null {
  const enabled = ['1', 'true', 'yes', 'on'].includes(
    (process.env.VAULT_PERIODIC_VERIFY_ENABLED ?? 'true').toLowerCase()
  );

  if (!enabled) {
    console.log('[vault:periodic] Periodic verification disabled');
    return null;
  }

  const intervalHours = parseInt(process.env.VAULT_PERIODIC_VERIFY_INTERVAL_HOURS ?? '24', 10);
  const intervalMs = Math.max(intervalHours * 60 * 60 * 1000, 60 * 1000); // min 1 minute

  console.log(`[vault:periodic] Starting periodic verification (interval: ${intervalHours}h)`);

  // Run immediately on startup
  performVerification().catch((err) => {
    console.error('[vault:periodic] Startup verification error:', err);
  });

  // Run periodically
  const timer = setInterval(() => {
    performVerification().catch((err) => {
      console.error('[vault:periodic] Scheduled verification error:', err);
    });
  }, intervalMs);

  return timer;
}

/**
 * Stop periodic verification background job
 */
export function stopPeriodicVerification(timer: NodeJS.Timeout | null): void {
  if (timer) {
    clearInterval(timer);
    console.log('[vault:periodic] Periodic verification stopped');
  }
}
