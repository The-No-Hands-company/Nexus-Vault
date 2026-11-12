#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Nexus-Vault Quality Gate ==="

echo "1. Running unit & integration tests..."
bun test --preload ./src/test-setup.ts --timeout 15000

echo "=== All Nexus-Vault checks passed! ==="
