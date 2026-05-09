# Nexus Vault

Nexus-Vault is the secrets, signing, and audit substrate for the ecosystem.

## Standards Enforcement

- Follow ../docs/ENGINEERING_STANDARDS.md as the baseline for TypeScript quality, API behavior, security, and testing.
- Treat this repo as security-sensitive infrastructure. Convenience-driven shortcuts, implicit trust, and silent fallback behavior are defects.
- Preserve Nexus-Cloud as the ecosystem nerve system for registration and coordination. Vault is a protected subsystem, not an isolated island.
- Prefer event-driven audit trails and explicit lifecycle events for secret rotation, backup, migration, and key-state changes.

## Repo Conventions

- Keep request validation strict and explicit.
- Never log secret material.
- Degraded behavior must fail closed for security-sensitive operations.

## Validation Target

- `npm run check`
- `npm test`