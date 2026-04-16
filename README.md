# Nexus Vault

Nexus Vault is the canonical sovereign secrets system for the Nexus ecosystem.

It combines the former API-key registry and devvault-style secret storage into one unified vault for:

- `api-key`
- `password`
- `note`
- `recovery-code`
- `token`
- `card`
- general `secret`

## Core features

- AES-256-GCM encrypted storage
- collections / folder-like nesting
- tags and categories
- import/export contracts
- audit logging and access stats
- read-only runtime secret pulls
- admin CRUD for vault items and collections
- cloud discovery and registration endpoints for Nexus Cloud

## Cloud contract

Nexus Vault exposes the canonical Nexus Cloud surface:

- `/.well-known/nexus-cloud`
- `/api/cloud/discovery`
- `/api/cloud/register`
- `/api/cloud/client`

The cloud client contract includes both legacy API-key style access and the broader vault entry model.

## API surface

| Method | Path | Description |
|---|---|---|
| GET | `/api/keys` | List vault entries |
| GET | `/api/keys/:name` | Read a single entry |
| GET | `/api/keys/search` | Search entries |
| GET | `/api/keys/expiring` | List expiring entries |
| GET | `/api/keys/types/:type` | List entries by type |
| GET | `/api/keys/categories` | List supported categories |
| GET | `/api/keys/collections` | List collections |
| POST | `/api/keys/collections` | Create collection |
| PUT | `/api/keys/collections/:name` | Update collection |
| DELETE | `/api/keys/collections/:name` | Archive collection |
| GET | `/api/keys/import/export` | List recent import/export records |
| POST | `/api/keys/import` | Import a vault payload (version 1 JSON) |
| POST | `/api/keys/import/env` | Bulk-import from raw `.env` text |
| POST | `/api/keys/import/openclaw` | Import from OpenClaw plugin manifest |
| GET | `/api/keys/export` | Export the vault |
| GET | `/api/audit` | Recent audit log |
| GET | `/api/audit/stats` | Access stats |
| GET | `/api/audit/export` | Export structured audit events (`ndjson` or `json`, Splunk/ELK targets) |
| POST | `/api/audit/export/siem` | Push audit export payload to SIEM webhook |
| GET | `/api/audit/verify` | Verify tamper-evident audit chain |
| GET | `/api/audit/verify-now` | Get most recent verification result (admin only) |
| POST | `/api/audit/verify-now` | Trigger on-demand verification run (admin only) |
| GET | `/api/audit/verification-history` | Persisted verification run history |
| GET | `/api/audit/chain` | Audit chain head/status summary |
| GET | `/api/ops/backups` | List backup inventory and retention info |
| POST | `/api/ops/backups/create` | Create immediate DB backup and enforce retention |
| GET | `/api/ops/state` | Get operational state (maintenance/restore flags) |
| POST | `/api/ops/maintenance` | Toggle maintenance mode and optional reason |
| GET | `/api/ops/tokens/state` | Get token state summary (counts + updatedAt) |
| POST | `/api/ops/tokens/rotate` | Atomic token rotation with audit trail |
| GET | `/api/ops/backups/:filename/checksum` | Verify backup checksum integrity |
| POST | `/api/ops/backups/sign-download` | Create signed backup download token |
| GET | `/api/ops/backups/download?token=...` | Download backup via signed token |
| POST | `/api/ops/backups/sign-upload` | Create signed backup upload token |
| PUT | `/api/ops/backups/upload?token=...` | Upload backup binary via signed token |
| POST | `/api/ops/backups/restore` | Restore DB from a backup file (explicit confirmation required) |
| GET | `/api/metrics` | Structured metrics (`prometheus` text or `otel` JSON) |
| GET | `/api/config/check` | Production safety preflight report (non-secret findings) |
| GET | `/.well-known/nexus-cloud` | Cloud discovery |
| GET | `/api/cloud/discovery` | Cloud discovery payload |
| POST | `/api/cloud/register` | Cloud registration |
| GET | `/api/cloud/client` | Cloud client contract |
| GET | `/api/ready` | Readiness probe (200 ready / 503 draining or not ready) |

## Import contracts

### Bulk `.env` import

```bash
curl -X POST http://localhost:3900/api/keys/import/env \
 -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
  "env": "GITHUB_TOKEN=ghp_xxx\nNOTION_API_KEY=secret_xxx\nOPENAI_API_KEY=sk-xxx",
  "collection": "openclaw",
  "project": "openclaw",
  "tags": ["source:env", "tool:openclaw"]
 }'
```

Response shape:

```json
{
 "ok": true,
 "created": 2,
 "updated": 1,
 "total": 3
}
```

### OpenClaw import

```bash
curl -X POST http://localhost:3900/api/keys/import/openclaw \
 -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
  "project": "openclaw",
  "includePlaceholders": true,
  "plugins": [
   {
    "name": "github",
    "icon": "github",
    "env": ["GITHUB_TOKEN", "GITHUB_USERNAME"],
    "config": ["github.token", "github.username"]
   },
   {
    "name": "notion",
    "icon": "notion",
    "env": ["NOTION_API_KEY"]
   }
  ],
  "values": {
   "GITHUB_TOKEN": "ghp_xxx",
   "NOTION_API_KEY": "secret_xxx"
  }
 }'
```

Response shape:

```json
{
 "ok": true,
 "created": 2,
 "updated": 0,
 "placeholders": 3,
 "plugins": [
  {
   "plugin": "github",
   "entries": ["GITHUB_TOKEN", "GITHUB_USERNAME", "github.token", "github.username"]
  },
  {
   "plugin": "notion",
   "entries": ["NOTION_API_KEY"]
  }
 ]
}
```

## Security notes

- `VAULT_MASTER_SECRET` is required.
- `VAULT_ACCESS_TOKEN` is the read token (comma-separated values supported for token rotation).
- `VAULT_ADMIN_TOKEN` is the admin token (comma-separated values supported for token rotation).
- Tokens are compared with constant-time checks.
- Minimum token length defaults to `24` (`VAULT_MIN_TOKEN_LENGTH`), and weak tokens are blocked unless `VAULT_ALLOW_WEAK_TOKENS=true`.
- Audit entries are chained with HMAC-SHA256 (`prev_hash`) to make tampering detectable; use `/api/audit/verify` for runtime verification.
- Startup performs audit chain verification by default (`VAULT_VERIFY_AUDIT_ON_START=true`) and will fail fast on integrity errors unless explicitly relaxed.
- Periodic background verification runs by default every 24 hours (`VAULT_PERIODIC_VERIFY_ENABLED=true`, `VAULT_PERIODIC_VERIFY_INTERVAL_HOURS=24`) and sends alerts on failures.
- Webhooks for critical alerts can be configured via `VAULT_ALERT_WEBHOOK_URL` (e.g., Slack, Discord).
- Email alerts are delivered via SMTP when `VAULT_ALERT_EMAIL` is set alongside SMTP envs.
- All write endpoints enforce structured schema validation and return `400` with field-level `details` when payloads are invalid.
- Keep the vault data directory backed up separately.

## Operations

```bash
npm run migrate     # apply pending schema migrations
npm run backup      # create a sqlite backup + sha256 checksum in VAULT_BACKUP_DIR
npm run audit:verify # verify tamper-evident audit chain (non-zero exit on failure)
npm run release:check
```

Startup integrity envs:

- `VAULT_VERIFY_AUDIT_ON_START=true|false` — verify audit chain at startup
- `VAULT_FAIL_ON_AUDIT_INTEGRITY_ERROR=true|false` — fail process on integrity errors

Periodic verification & alerting envs:

- `VAULT_PERIODIC_VERIFY_ENABLED=true|false` — enable background verification
- `VAULT_PERIODIC_VERIFY_INTERVAL_HOURS=24` — frequency in hours (min: 1)
- `VAULT_ALERT_WEBHOOK_URL=https://...` — webhook for failure alerts (Slack, Discord, etc.)
- `VAULT_ALERT_EMAIL=ops@example.com` — email alert destination
- `VAULT_ALERT_THROTTLE_MINUTES=60` — prevent alert spam (min seconds between consecutive alerts)

Backup operations envs:

- `VAULT_BACKUP_DIR=./backups` — backup storage location
- `VAULT_BACKUP_RETENTION_COUNT=20` — keep newest backups and prune older files
- `VAULT_BACKUP_MAX_UPLOAD_MB=50` — maximum signed upload payload size
- `VAULT_BACKUP_SIGNING_SECRET=<secret>` — HMAC secret for signed backup upload/download tokens (falls back to admin token if unset)
- `VAULT_BACKUP_KMS_MASTER_KEY=<secret|hex|base64>` — envelope-wrapping key for `kms-envelope` backup encryption mode

Token rotation envs:

- `VAULT_MIN_TOKEN_LENGTH=24` — rotation enforces this minimum unless weak tokens are allowed
- `VAULT_ALLOW_WEAK_TOKENS=true|false` — development override only

Metrics envs:

- `VAULT_METRICS_PUBLIC=true|false` — if true, `/api/metrics` does not require admin token

SIEM export envs:

- `VAULT_SIEM_WEBHOOK_URL=https://...` — default destination for `/api/audit/export/siem`

Deployment hardening envs:

- `TRUST_PROXY=true|false|<hops>|<csv CIDRs/IPs>` — Express proxy trust mode for ingress/load-balancer deployments
- `CORS_ORIGIN=https://app.example.com[,https://admin.example.com]` — CORS allowlist (blank disables CORS)
- `CORS_ALLOW_CREDENTIALS=true|false` — whether to emit credentialed CORS responses
- `CORS_ALLOW_WILDCARD=true|false` — allows `CORS_ORIGIN=*` only when explicitly enabled
- `VAULT_CSP_PRESET=compat|strict` — `compat` for dashboard inline assets, `strict` for API-first lockdown
- `VAULT_ALLOW_EMBED=true|false` — allow framing when embedding Vault UI in another app
- `VAULT_SHUTDOWN_TIMEOUT_MS=15000` — graceful server drain timeout for SIGTERM/SIGINT

SMTP envs for email alerts:

- `VAULT_SMTP_HOST=smtp.example.com`
- `VAULT_SMTP_PORT=587`
- `VAULT_SMTP_SECURE=true|false`
- `VAULT_SMTP_USER=smtp-user`
- `VAULT_SMTP_PASS=smtp-password`
- `VAULT_SMTP_FROM=nexus-vault@example.com`

Nexus Cloud embedding envs (optional):

- `NEXUS_CLOUD_EMBEDDED=true|false` — marks the app as embedded in Nexus Cloud topology metadata
- `NEXUS_CLOUD_REFERENCED=true|false` — marks whether the app is externally referenced
- `NEXUS_CLOUD_BASE_URL=/api` — base path used when generating cloud client/discovery endpoints
- `NEXUS_CLOUD_APP_ID=nexus-vault`
- `NEXUS_CLOUD_APP_NAME=Nexus Vault`
- `NEXUS_CLOUD_APP_ROLE=secrets-layer`
- `NEXUS_CLOUD_PROTOCOL=nexus-cloud/1.0`
- `NEXUS_CLOUD_HUB=Nexus Cloud`
- `NEXUS_CLOUD_REQUIRED_APIS=topology.v1,systems-api.v1`
- `NEXUS_CLOUD_CONSUMES=/api/keys,/api/audit`
- `NEXUS_CLOUD_EXPOSES=/.well-known/nexus-cloud,/api/cloud/discovery,/api/cloud/register,/api/cloud/client`

Cloud registration handshake hardening (optional):

- `NEXUS_CLOUD_REGISTER_SECRET=<shared-secret>` — requires signed registration requests
- `NEXUS_CLOUD_SIGNATURE_MAX_SKEW_SECONDS=300` — timestamp replay tolerance window
- `NEXUS_CLOUD_ALLOW_INSECURE_REGISTRATION_ENDPOINT=true|false` — allow `http://` endpoints for local/dev only
- Registration signature headers:
 	- `X-Nexus-Timestamp: <ISO timestamp>`
 	- `X-Nexus-Signature: <hex HMAC-SHA256(secret,`${timestamp}.${JSON.stringify(body)}`)>`

Container production notes:

- Docker and Compose healthchecks use `/api/ready` so draining instances fail readiness during shutdown.
- Container startup rejects placeholder credentials for `VAULT_MASTER_SECRET`, `VAULT_ACCESS_TOKEN`, and `VAULT_ADMIN_TOKEN`.
- Compose runs with `read_only: true`, `tmpfs: /tmp`, and `no-new-privileges` for stricter runtime posture.

## Development

```bash
npm install
npm run typecheck
npm test
npm run dev
npm run build
```

## Production Smoke Runbook

Use the turnkey smoke script to validate new operational APIs (`/api/ops`), structured audit export (`/api/audit/export`), and config preflight (`/api/config/check`).

```bash
BASE_URL=http://localhost:3900 \
ADMIN_TOKEN='<vault-admin-token>' \
./scripts/smoke-production.sh
```

Optional flags:

- `KEEP_TMP=1` — preserve downloaded audit/backup artifacts
- `SMOKE_RESTORE=1` — include restore step (`POST /api/ops/backups/restore`)
- `VAULT_SIEM_WEBHOOK_URL=...` — exercise `/api/audit/export/siem`

Restore safety guardrails:

- Restore requires explicit confirmation payload: `confirm: "RESTORE <filename>"`.
- Restore accepts optional `passphrase` for encrypted passphrase backups.
- During restore, readiness reports `503` with `restoreInProgress=true`.
- Maintenance mode can be toggled via `POST /api/ops/maintenance` and inspected via `GET /api/ops/state`.

Token rotation safety:

- Rotate via `POST /api/ops/tokens/rotate` with `mode` (`replace` or `append`) and `accessTokens` / `adminTokens` arrays.
- Rotation is atomic in-memory cutover and emits audit event `TOKEN_ROTATE`.
