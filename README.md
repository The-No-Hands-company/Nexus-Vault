# 🔐 DevVault

Self-hosted API key registry. One place to store, rotate, and audit all your API keys across all projects.

## Features

- **AES-256-GCM encryption** — every value encrypted at rest with a per-value IV
- **REST pull endpoint** — `GET /api/keys/:name` from any project in any language
- **Tag + project system** — organize keys across all your repos
- **Expiry tracking** — dashboard warns when keys are near expiry
- **Full audit log** — every read, create, update, and delete is logged with IP
- **Usage stats** — see which keys are being hit and how often
- **Docker-first** — single `docker compose up` to run

---

## Quick Start (Docker)

```bash
# 1. Copy and fill in your secrets
cp .env.example .env
# Edit docker-compose.yml — change the three VAULT_* values

# 2. Start
docker compose up -d

# 3. Open dashboard
open http://localhost:3900
```

## Quick Start (Local dev)

```bash
npm install
cp .env.example .env    # fill in values
npm run dev             # tsx watch — hot reload
```

---

## API

All endpoints require `Authorization: Bearer <token>` header.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/keys` | read or admin | List all keys (values redacted) |
| GET | `/api/keys/:name` | read or admin | **Get decrypted value** |
| GET | `/api/keys/search?q=` | read or admin | Search by name/tag/project |
| GET | `/api/keys/expiring?days=7` | admin | Keys expiring within N days |
| POST | `/api/keys` | admin | Create a key |
| PUT | `/api/keys/:name` | admin | Update a key |
| DELETE | `/api/keys/:name` | admin | Soft-delete a key |
| GET | `/api/audit` | admin | Recent audit log |
| GET | `/api/audit/stats` | admin | Access stats per key |

### Pulling a key from a project

```bash
# curl
curl -s http://localhost:3900/api/keys/GITHUB_TOKEN \
  -H "Authorization: Bearer $VAULT_ACCESS_TOKEN" | jq -r .value

# Node.js
const res = await fetch('http://localhost:3900/api/keys/GITHUB_TOKEN', {
  headers: { Authorization: `Bearer ${process.env.VAULT_ACCESS_TOKEN}` }
});
const { value } = await res.json();

# Python
import requests, os
r = requests.get('http://localhost:3900/api/keys/GITHUB_TOKEN',
    headers={'Authorization': f'Bearer {os.environ["VAULT_ACCESS_TOKEN"]}'})
value = r.json()['value']
```

---

## Security Notes

- `VAULT_MASTER_SECRET` is the root of all encryption. Back it up. Losing it = losing all stored values.
- `VAULT_ACCESS_TOKEN` (read-only) and `VAULT_ADMIN_TOKEN` (full admin) are separate. Give projects the read token only.
- All tokens are compared in constant time to prevent timing attacks.
- The vault data dir (`./data/vault.db`) should be excluded from git and backed up separately.
- When moving to hosted infra, enable CORS_ORIGIN and put the service behind a reverse proxy with TLS.

---

## Migrating to PostgreSQL

The DB layer is isolated in `src/db.ts`. When ready to swap to Postgres, replace `better-sqlite3` with `pg` or Prisma and update query syntax. The crypto and routes layers don't change.
