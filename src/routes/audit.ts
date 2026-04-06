import { Router } from 'express';
import { auditQueries } from '../db.js';
import { requireAdminToken } from '../auth.js';

export const auditRouter = Router();

auditRouter.get('/', requireAdminToken, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string ?? '100', 10), 500);
  res.json(auditQueries.getRecent.all(limit));
});

auditRouter.get('/stats', requireAdminToken, (_req, res) => {
  res.json(auditQueries.getStats.all());
});

auditRouter.get('/:key_name', requireAdminToken, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string ?? '50', 10), 200);
  res.json(auditQueries.getForKey.all(req.params.key_name, limit));
});
