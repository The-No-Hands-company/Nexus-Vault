#!/usr/bin/env bash
set -euo pipefail

# Turnkey smoke test for production operational endpoints.
# Required:
#   BASE_URL=http://localhost:3900
#   ADMIN_TOKEN=<vault admin token>
# Optional:
#   KEEP_TMP=1

BASE_URL="${BASE_URL:-http://localhost:3900}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
KEEP_TMP="${KEEP_TMP:-0}"

if [[ -z "$ADMIN_TOKEN" ]]; then
  echo "ADMIN_TOKEN is required" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

json_query() {
  local query="$1"
  node -e '
const fs = require("fs");
const q = process.argv[1];
const input = fs.readFileSync(0, "utf8");
const data = JSON.parse(input);
const parts = q.split(".").filter(Boolean);
let cur = data;
for (const p of parts) {
  if (cur == null) break;
  if (/^\d+$/.test(p)) cur = cur[Number(p)];
  else cur = cur[p];
}
if (cur === undefined || cur === null) process.exit(2);
if (typeof cur === "object") process.stdout.write(JSON.stringify(cur));
else process.stdout.write(String(cur));
' "$query"
}

request_json() {
  local method="$1"
  local url="$2"
  local body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -sS -X "$method" "$url" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      --data "$body"
  else
    curl -sS -X "$method" "$url" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json"
  fi
}

echo "[smoke] BASE_URL=$BASE_URL"

# 1) Config preflight
config_report="$(request_json GET "$BASE_URL/api/config/check")"
echo "[smoke] /api/config/check summary: $(printf '%s' "$config_report" | json_query 'report.summary')"

# 2) Create backup + inventory + checksum
created_backup="$(request_json POST "$BASE_URL/api/ops/backups/create" '{}')"
backup_name="$(printf '%s' "$created_backup" | json_query 'created.filename')"
echo "[smoke] Created backup: $backup_name"

inventory="$(request_json GET "$BASE_URL/api/ops/backups")"
echo "[smoke] Backups listed: $(printf '%s' "$inventory" | json_query 'backups.0.filename')"

checksum="$(request_json GET "$BASE_URL/api/ops/backups/$backup_name/checksum")"
checksum_ok="$(printf '%s' "$checksum" | json_query 'ok')"
if [[ "$checksum_ok" != "true" ]]; then
  echo "[smoke] Backup checksum failed" >&2
  exit 1
fi
echo "[smoke] Backup checksum verified"

# 3) Signed download flow
signed_download="$(request_json POST "$BASE_URL/api/ops/backups/sign-download" "{\"filename\":\"$backup_name\",\"expiresSeconds\":300}")"
download_url="$(printf '%s' "$signed_download" | json_query 'downloadUrl')"
tmp_dir="$(mktemp -d)"
download_path="$tmp_dir/$backup_name"
curl -sS "$BASE_URL$download_url" -o "$download_path"
if [[ ! -s "$download_path" ]]; then
  echo "[smoke] Signed backup download failed" >&2
  exit 1
fi
echo "[smoke] Signed download succeeded -> $download_path"

# 4) Signed upload flow (re-upload the downloaded file)
upload_name="smoke-upload-$(date +%s).db"
signed_upload="$(request_json POST "$BASE_URL/api/ops/backups/sign-upload" "{\"filename\":\"$upload_name\",\"expiresSeconds\":300}")"
upload_url="$(printf '%s' "$signed_upload" | json_query 'uploadUrl')"
curl -sS -X PUT "$BASE_URL$upload_url" -H "Content-Type: application/octet-stream" --data-binary "@$download_path" >/dev/null
echo "[smoke] Signed upload succeeded -> $upload_name"

# 5) Audit export (NDJSON + JSON) and optional SIEM webhook push
audit_ndjson="$tmp_dir/audit.ndjson"
curl -sS "$BASE_URL/api/audit/export?format=ndjson&target=elk&limit=50" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -o "$audit_ndjson"
if [[ ! -s "$audit_ndjson" ]]; then
  echo "[smoke] Audit NDJSON export is empty" >&2
  exit 1
fi
echo "[smoke] Audit NDJSON export written -> $audit_ndjson"

audit_json="$(request_json GET "$BASE_URL/api/audit/export?format=json&target=splunk&limit=5")"
echo "[smoke] Audit JSON export count: $(printf '%s' "$audit_json" | json_query 'count')"

if [[ -n "${VAULT_SIEM_WEBHOOK_URL:-}" ]]; then
  siem_push="$(request_json POST "$BASE_URL/api/audit/export/siem" '{"format":"ndjson","target":"elk","limit":25}')"
  echo "[smoke] SIEM webhook push status: $(printf '%s' "$siem_push" | json_query 'webhookStatus')"
else
  echo "[smoke] Skipping SIEM webhook push (VAULT_SIEM_WEBHOOK_URL not set)"
fi

# 6) Optional restore dry-run (guarded by explicit flag)
if [[ "${SMOKE_RESTORE:-0}" == "1" ]]; then
  restore_result="$(request_json POST "$BASE_URL/api/ops/backups/restore" "{\"filename\":\"$backup_name\",\"verifyChecksum\":true}")"
  echo "[smoke] Restore completed: $(printf '%s' "$restore_result" | json_query 'restored')"
else
  echo "[smoke] Restore skipped (set SMOKE_RESTORE=1 to enable)"
fi

if [[ "$KEEP_TMP" != "1" ]]; then
  rm -rf "$tmp_dir"
else
  echo "[smoke] KEEP_TMP=1 -> preserving $tmp_dir"
fi

echo "[smoke] Completed successfully"
