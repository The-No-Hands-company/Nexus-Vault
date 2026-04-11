import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';

import { vaultRouter } from './routes/keys.js';
import { auditRouter } from './routes/audit.js';
import cloudRouter from './routes/cloud.js';

const required = ['VAULT_ACCESS_TOKEN', 'VAULT_ADMIN_TOKEN', 'VAULT_MASTER_SECRET'];
for (const v of required) {
  if (!process.env[v]) {
    console.error(`[vault] Missing required env var: ${v}`);
    process.exit(1);
  }
}

const PORT = parseInt(process.env.PORT ?? '3900', 10);
const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
    },
  },
}));

app.use(cors({
  origin: process.env.CORS_ORIGIN ?? false,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Authorization', 'Content-Type'],
}));

app.use(rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' },
}));

const writeLimit = rateLimit({
  windowMs: 60_000,
  max: 30,
  message: { error: 'Too many write requests' },
});

app.use(express.json({ limit: '64kb' }));

const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/keys', writeLimit, vaultRouter);
app.use('/api/audit', auditRouter);
app.use('/', cloudRouter);

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[vault]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`\n🔐 Nexus Vault running on http://localhost:${PORT}\n`);
});

export default app;
