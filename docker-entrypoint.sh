#!/bin/sh
set -e

require_env() {
	name="$1"
	value="$(printenv "$name" || true)"
	if [ -z "$value" ]; then
		echo "[entrypoint] Missing required env var: $name" >&2
		exit 1
	fi
}

reject_placeholder() {
	name="$1"
	value="$(printenv "$name" || true)"
	case "$value" in
		change-me*|*your*secret*|*example.com*)
			echo "[entrypoint] Refusing to start with placeholder value for $name" >&2
			exit 1
			;;
	esac
}

require_env "VAULT_MASTER_SECRET"
require_env "VAULT_ACCESS_TOKEN"
require_env "VAULT_ADMIN_TOKEN"

reject_placeholder "VAULT_MASTER_SECRET"
reject_placeholder "VAULT_ACCESS_TOKEN"
reject_placeholder "VAULT_ADMIN_TOKEN"

echo "[entrypoint] Running database migrations..."
node dist/migrate.js

echo "[entrypoint] Starting Nexus Vault..."
exec node dist/index.js
