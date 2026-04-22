import rateLimit from 'express-rate-limit';

/**
 * General write limit — 30 requests/min.
 * Applied at the router level for /api/keys and /api/ops.
 */
export const writeLimit = rateLimit({
  windowMs: 60_000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many write requests' },
});

/**
 * Strict limit — 5 requests/min.
 * Applied per-route for high-impact operations:
 * backup restore, token rotation.
 */
export const strictLimit = rateLimit({
  windowMs: 60_000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests for this operation' },
});
