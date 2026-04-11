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
| GET | `/api/collections` | List collections |
| POST | `/api/collections` | Create collection |
| PUT | `/api/collections/:name` | Update collection |
| DELETE | `/api/collections/:name` | Archive collection |
| GET | `/api/categories` | List supported categories |
| POST | `/api/import` | Import a vault payload |
| GET | `/api/export` | Export the vault |
| GET | `/api/audit` | Recent audit log |
| GET | `/api/audit/stats` | Access stats |
| GET | `/.well-known/nexus-cloud` | Cloud discovery |
| GET | `/api/cloud/discovery` | Cloud discovery payload |
| POST | `/api/cloud/register` | Cloud registration |
| GET | `/api/cloud/client` | Cloud client contract |

## Security notes

- `VAULT_MASTER_SECRET` is required.
- `VAULT_ACCESS_TOKEN` is the read token.
- `VAULT_ADMIN_TOKEN` is the admin token.
- Keep the vault data directory backed up separately.

## Development

```bash
npm install
npm run dev
npm run build
```
