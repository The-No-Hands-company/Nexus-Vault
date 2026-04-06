import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';

import { keysRouter } from './routes/keys.js';
import { auditRouter } from './routes/audit.js';

// Validate required env vars
const required = ['VAULT_ACCESS_TOKEN', 'VAULT_ADMIN_TOKEN', 'VAULT_MASTER_SECRET'];
for (const v of required) {
  if (!process.env[v]) {
    console.error(`[vault] Missing required env var: ${v}`);
    process.exit(1);
  }
}

const PORT = parseInt(process.env.PORT ?? '3900', 10);
const app = express();

// ── Security ─────────────────────────────────────────────────────────────────

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],   // dashboard inline scripts
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
    }
  }
}));

app.use(cors({
  origin: process.env.CORS_ORIGIN ?? false,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Authorization', 'Content-Type'],
}));

// Global rate limit — tighten in production
app.use(rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' },
}));

// Stricter limit for write operations
const writeLimit = rateLimit({
  windowMs: 60_000,
  max: 30,
  message: { error: 'Too many write requests' },
});

app.use(express.json({ limit: '64kb' }));

// ── Static dashboard ──────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(__dirname, 'public')));

// ── API routes ────────────────────────────────────────────────────────────────

app.use('/api/keys', writeLimit, keysRouter);
app.use('/api/audit', auditRouter);

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

// SPA fallback — serve dashboard for any unmatched route
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Error handler ─────────────────────────────────────────────────────────────

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[vault]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`\n🔐 DevVault running on http://localhost:${PORT}\n`);
});

export default app;
