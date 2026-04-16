import { Router } from 'express';
import { auditQueries, getAuditChainStatus, listAuditVerificationRuns, verifyAuditChain } from '../db.js';
import { requireAdminToken } from '../auth.js';
import { getLastVerificationResult, performVerification } from '../periodic-verify.js';

export const auditRouter = Router();

type SiemTarget = 'generic' | 'splunk' | 'elk';

function asSiemTarget(value: unknown): SiemTarget {
  const v = String(value ?? 'generic').trim().toLowerCase();
  if (v === 'splunk') return 'splunk';
  if (v === 'elk') return 'elk';
  return 'generic';
}

function formatAuditEvent(row: ReturnType<typeof auditQueries.getRecent.all>[number], target: SiemTarget): Record<string, unknown> {
  let parsedMeta: Record<string, unknown> | string = row.meta;
  try {
    const parsed = JSON.parse(row.meta);
    if (parsed && typeof parsed === 'object') parsedMeta = parsed as Record<string, unknown>;
  } catch {
    // Keep raw string fallback.
  }

  if (target === 'splunk') {
    return {
      time: Math.floor(new Date(row.timestamp).getTime() / 1000),
      host: 'nexus-vault',
      source: 'audit_log',
      sourcetype: 'nexus:vault:audit',
      event: {
        id: row.id,
        entry_name: row.entry_name,
        action: row.action,
        ip: row.ip,
        user_agent: row.user_agent,
        timestamp: row.timestamp,
        prev_hash: row.prev_hash,
        meta: parsedMeta,
      },
    };
  }

  if (target === 'elk') {
    return {
      '@timestamp': row.timestamp,
      event: {
        category: 'database',
        kind: 'event',
        action: row.action,
      },
      nexus: {
        service: 'vault',
        audit: {
          id: row.id,
          entry_name: row.entry_name,
          ip: row.ip,
          user_agent: row.user_agent,
          prev_hash: row.prev_hash,
          meta: parsedMeta,
        },
      },
    };
  }

  return {
    timestamp: row.timestamp,
    service: 'nexus-vault',
    source: 'audit_log',
    id: row.id,
    entry_name: row.entry_name,
    action: row.action,
    ip: row.ip,
    user_agent: row.user_agent,
    prev_hash: row.prev_hash,
    meta: parsedMeta,
  };
}

function toNdjson(items: readonly Record<string, unknown>[]): string {
  if (!items.length) return '';
  return `${items.map((row) => JSON.stringify(row)).join('\n')}\n`;
}

auditRouter.get('/', requireAdminToken, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string ?? '100', 10), 500);
  res.json(auditQueries.getRecent.all(limit));
});

auditRouter.get('/stats', requireAdminToken, (_req, res) => {
  res.json(auditQueries.getStats.all());
});

auditRouter.get('/export', requireAdminToken, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string ?? '1000', 10), 10_000);
  const target = asSiemTarget(req.query.target);
  const format = String(req.query.format ?? 'ndjson').toLowerCase();

  const rows = auditQueries.getRecent.all(limit);
  const events = rows.map((row) => formatAuditEvent(row, target));

  if (format === 'json') {
    res.json({
      target,
      count: events.length,
      exportedAt: new Date().toISOString(),
      events,
    });
    return;
  }

  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.send(toNdjson(events));
});

auditRouter.post('/export/siem', requireAdminToken, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.body?.limit ?? '1000', 10), 10_000);
    const target = asSiemTarget(req.body?.target);
    const format = String(req.body?.format ?? 'ndjson').toLowerCase();
    const webhookUrl = String(req.body?.webhookUrl ?? process.env.VAULT_SIEM_WEBHOOK_URL ?? '').trim();

    if (!webhookUrl) {
      res.status(400).json({ error: 'SIEM webhook URL is required (body.webhookUrl or VAULT_SIEM_WEBHOOK_URL)' });
      return;
    }

    const rows = auditQueries.getRecent.all(limit);
    const events = rows.map((row) => formatAuditEvent(row, target));

    const body = format === 'json'
      ? JSON.stringify({ target, count: events.length, exportedAt: new Date().toISOString(), events })
      : toNdjson(events);

    const contentType = format === 'json'
      ? 'application/json'
      : 'application/x-ndjson';

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': contentType,
      },
      body,
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      res.status(502).json({
        error: 'SIEM webhook rejected payload',
        status: response.status,
        statusText: response.statusText,
      });
      return;
    }

    res.json({
      ok: true,
      target,
      format,
      count: events.length,
      webhookStatus: response.status,
    });
  } catch (err) {
    res.status(502).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

auditRouter.get('/verify', requireAdminToken, (_req, res) => {
  const status = getAuditChainStatus();
  const result = verifyAuditChain();
  if (!result.ok) return res.status(409).json({ ...result, ...status });
  res.json({ ...result, ...status });
});

auditRouter.get('/chain', requireAdminToken, (_req, res) => {
  res.json(getAuditChainStatus());
});

auditRouter.get('/verification-history', requireAdminToken, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string ?? '100', 10), 500);
  res.json(listAuditVerificationRuns(limit));
});

auditRouter.get('/verify-now', requireAdminToken, (_req, res) => {
  const lastVerification = getLastVerificationResult();
  res.json(lastVerification || { message: 'No verification has run yet' });
});

auditRouter.post('/verify-now', requireAdminToken, async (_req, res) => {
  const result = await performVerification({ source: 'manual', sendAlertsOnFailure: true });
  if (!result.ok) {
    return res.status(409).json(result);
  }
  return res.status(200).json(result);
});

auditRouter.get('/:key_name', requireAdminToken, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string ?? '50', 10), 200);
  res.json(auditQueries.getForEntry.all(req.params.key_name, limit));
});
