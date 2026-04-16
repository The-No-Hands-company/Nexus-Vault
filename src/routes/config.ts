import { Router } from 'express';
import { requireAdminToken } from '../auth.js';

type Severity = 'info' | 'warn' | 'error';

type ConfigFinding = {
  id: string;
  severity: Severity;
  status: 'pass' | 'fail';
  message: string;
  recommendation?: string;
};

export const configRouter = Router();

function envFlag(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const normalized = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function tokenValues(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function checkConfig(): { findings: ConfigFinding[]; summary: Record<string, number> } {
  const findings: ConfigFinding[] = [];

  const add = (finding: ConfigFinding) => findings.push(finding);

  const required = ['VAULT_MASTER_SECRET', 'VAULT_ACCESS_TOKEN', 'VAULT_ADMIN_TOKEN'];
  for (const name of required) {
    const ok = Boolean(process.env[name]?.trim());
    add({
      id: `required.${name}`,
      severity: ok ? 'info' : 'error',
      status: ok ? 'pass' : 'fail',
      message: ok ? `${name} is configured` : `${name} is missing`,
      recommendation: ok ? undefined : `Set ${name} to a strong non-placeholder value`,
    });
  }

  const minTokenLength = Math.max(parseInt(process.env.VAULT_MIN_TOKEN_LENGTH ?? '24', 10) || 24, 8);
  const tokens = [
    ...tokenValues(process.env.VAULT_ACCESS_TOKEN),
    ...tokenValues(process.env.VAULT_ADMIN_TOKEN),
  ];
  const weak = tokens.some((token) => token.length < minTokenLength);
  add({
    id: 'tokens.length',
    severity: weak ? 'error' : 'info',
    status: weak ? 'fail' : 'pass',
    message: weak
      ? `One or more tokens are shorter than minimum length (${minTokenLength})`
      : 'All configured tokens satisfy minimum length policy',
    recommendation: weak ? 'Rotate short tokens and set VAULT_ALLOW_WEAK_TOKENS=false in production' : undefined,
  });

  const verifyOnStart = envFlag('VAULT_VERIFY_AUDIT_ON_START', true);
  add({
    id: 'audit.verifyOnStart',
    severity: verifyOnStart ? 'info' : 'warn',
    status: verifyOnStart ? 'pass' : 'fail',
    message: verifyOnStart ? 'Startup audit verification is enabled' : 'Startup audit verification is disabled',
    recommendation: verifyOnStart ? undefined : 'Enable VAULT_VERIFY_AUDIT_ON_START=true',
  });

  const failOnIntegrity = envFlag('VAULT_FAIL_ON_AUDIT_INTEGRITY_ERROR', true);
  add({
    id: 'audit.failOnIntegrity',
    severity: failOnIntegrity ? 'info' : 'warn',
    status: failOnIntegrity ? 'pass' : 'fail',
    message: failOnIntegrity
      ? 'Process fails closed on audit integrity errors'
      : 'Process continues on audit integrity errors',
    recommendation: failOnIntegrity ? undefined : 'Set VAULT_FAIL_ON_AUDIT_INTEGRITY_ERROR=true',
  });

  const corsOrigin = process.env.CORS_ORIGIN?.trim() ?? '';
  const corsWildcard = corsOrigin === '*';
  const wildcardAllowed = envFlag('CORS_ALLOW_WILDCARD', false);
  const corsUnsafe = corsWildcard && wildcardAllowed;
  add({
    id: 'cors.wildcard',
    severity: corsUnsafe ? 'warn' : 'info',
    status: corsUnsafe ? 'fail' : 'pass',
    message: corsUnsafe ? 'CORS wildcard is enabled' : 'CORS wildcard is not enabled',
    recommendation: corsUnsafe ? 'Use explicit CORS_ORIGIN allowlist in production' : undefined,
  });

  const trustProxy = (process.env.TRUST_PROXY ?? '').trim();
  add({
    id: 'network.trustProxy',
    severity: trustProxy ? 'info' : 'warn',
    status: trustProxy ? 'pass' : 'fail',
    message: trustProxy ? `TRUST_PROXY is configured (${trustProxy})` : 'TRUST_PROXY is not configured',
    recommendation: trustProxy ? undefined : 'Configure TRUST_PROXY when running behind ingress/load-balancers',
  });

  const backupRetention = Math.max(1, parseInt(process.env.VAULT_BACKUP_RETENTION_COUNT ?? '20', 10));
  add({
    id: 'backup.retention',
    severity: backupRetention >= 5 ? 'info' : 'warn',
    status: backupRetention >= 5 ? 'pass' : 'fail',
    message: `Backup retention count is ${backupRetention}`,
    recommendation: backupRetention >= 5 ? undefined : 'Set VAULT_BACKUP_RETENTION_COUNT>=5 for safer recovery posture',
  });

  const smtpHost = process.env.VAULT_SMTP_HOST?.trim();
  const alertEmail = process.env.VAULT_ALERT_EMAIL?.trim();
  const smtpPartial = Boolean(alertEmail) && !smtpHost;
  add({
    id: 'alerts.smtp',
    severity: smtpPartial ? 'warn' : 'info',
    status: smtpPartial ? 'fail' : 'pass',
    message: smtpPartial
      ? 'VAULT_ALERT_EMAIL is set but SMTP host is not configured'
      : 'SMTP alert configuration is internally consistent',
    recommendation: smtpPartial ? 'Set VAULT_SMTP_HOST (and related SMTP credentials) or unset VAULT_ALERT_EMAIL' : undefined,
  });

  const siemWebhook = process.env.VAULT_SIEM_WEBHOOK_URL?.trim();
  const insecureWebhook = Boolean(siemWebhook && !siemWebhook.startsWith('https://'));
  add({
    id: 'siem.webhookProtocol',
    severity: insecureWebhook ? 'warn' : 'info',
    status: insecureWebhook ? 'fail' : 'pass',
    message: insecureWebhook ? 'SIEM webhook URL is not HTTPS' : 'SIEM webhook URL protocol is safe',
    recommendation: insecureWebhook ? 'Use HTTPS webhook endpoints for SIEM export' : undefined,
  });

  const summary = {
    total: findings.length,
    pass: findings.filter((f) => f.status === 'pass').length,
    fail: findings.filter((f) => f.status === 'fail').length,
    errors: findings.filter((f) => f.severity === 'error' && f.status === 'fail').length,
    warnings: findings.filter((f) => f.severity === 'warn' && f.status === 'fail').length,
  };

  return { findings, summary };
}

configRouter.get('/check', requireAdminToken, (_req, res) => {
  const report = checkConfig();
  res.json({
    generatedAt: new Date().toISOString(),
    report,
  });
});
