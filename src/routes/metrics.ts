import { Router } from 'express';
import { requireAdminToken } from '../auth.js';
import { renderOtelJson, renderPrometheus } from '../metrics.js';

export const metricsRouter = Router();

function envFlag(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const normalized = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

metricsRouter.get('/metrics', (req, res, next) => {
  const isPublic = envFlag('VAULT_METRICS_PUBLIC', false);
  if (isPublic) return next();
  return requireAdminToken(req, res, next);
}, (req, res) => {
  const format = String(req.query.format ?? 'prometheus').toLowerCase();
  if (format === 'otel' || format === 'json') {
    res.json(renderOtelJson());
    return;
  }

  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(renderPrometheus());
});
