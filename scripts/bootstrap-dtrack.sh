#!/usr/bin/env bash
set -euo pipefail

# Automates the one-time Dependency-Track bootstrap that dtrack itself
# requires and cannot skip (see README's "Optional: Dependency-Track
# integration" section, and DTRACK_PLAN.md's "Confidence check" — verified
# there's no env var / config property to pre-seed the admin password or an
# API key; this really is a manual first-boot flow on dtrack's side):
#
#   1. Changes the default admin/admin password (forced on first login).
#   2. Grants the Automation team the three permissions Magnolia's sync
#      loop actually needs (verified live: BOM_UPLOAD alone is NOT enough
#      for autoCreate to work — PROJECT_CREATION_UPLOAD is required too).
#   3. Generates an API key and writes it to .env as DTRACK_API_KEY, which
#      docker-compose.yml reads via `${DTRACK_API_KEY:-}` — no manual
#      editing of any tracked file.
#
# Usage:
#   docker compose --profile dtrack up -d          # start dtrack first
#   DTRACK_ADMIN_PASSWORD='pick-one' ./scripts/bootstrap-dtrack.sh
#   docker compose --profile dtrack up -d api       # pick up the new key
#
# Safe to re-run with the same DTRACK_ADMIN_PASSWORD: if the password was
# already changed, this logs in with it instead of trying to change it
# again, and reuses the existing key instead of minting a new one (pass
# --new-key to force a fresh one; each call to the key-creation endpoint
# mints an *additional* key, so this is deliberately not the default).
#
# Container mode: if DTRACK_BOOTSTRAP_KEY_FILE is set, the key is written
# there as a raw value (no .env touched at all) — this is what
# docker-compose.dtrack.yml's one-shot bootstrap service uses, so `api`
# (started only after this container exits successfully) can read the key
# straight from that shared-volume file via DTRACK_API_KEY_FILE.

DTRACK_URL="${DTRACK_URL:-http://localhost:8080}"
TEAM_NAME="${DTRACK_TEAM:-Automation}"
NEW_ADMIN_PASSWORD="${DTRACK_ADMIN_PASSWORD:-}"
NEW_KEY=false

for arg in "$@"; do
  case "$arg" in
    --new-key) NEW_KEY=true ;;
    --url=*) DTRACK_URL="${arg#--url=}" ;;
    -h|--help)
      sed -n '2,25p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

if [ -z "$NEW_ADMIN_PASSWORD" ]; then
  echo "Set DTRACK_ADMIN_PASSWORD to the password you want dtrack's 'admin'" >&2
  echo "account to use — pick once, reuse on every re-run of this script:" >&2
  echo "  DTRACK_ADMIN_PASSWORD='pick-one' $0" >&2
  exit 1
fi

if ! command -v python3 > /dev/null 2>&1; then
  echo "python3 is required (used to parse dtrack's JSON responses)" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"

echo "==> Waiting for dtrack at $DTRACK_URL ..."
ready=false
for _ in $(seq 1 30); do
  if curl -sf "$DTRACK_URL/api/version" > /dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
if [ "$ready" != true ]; then
  echo "dtrack did not become reachable at $DTRACK_URL — is 'docker compose --profile dtrack up -d' running?" >&2
  exit 1
fi
echo "    up."

login() {
  local resp status
  resp="$(curl -s -w '\n%{http_code}' -X POST "$DTRACK_URL/api/v1/user/login" \
    --data-urlencode "username=admin" \
    --data-urlencode "password=$NEW_ADMIN_PASSWORD")"
  status="$(echo "$resp" | tail -n1)"
  if [ "$status" = "200" ]; then
    echo "$resp" | sed '$d'
  fi
}

echo "==> Logging in ..."
JWT="$(login)"

if [ -z "$JWT" ]; then
  echo "    not yet bootstrapped (or DTRACK_ADMIN_PASSWORD doesn't match) — trying the default admin/admin password-change flow ..."
  CHANGE_STATUS="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$DTRACK_URL/api/v1/user/forceChangePassword" \
    --data-urlencode "username=admin" \
    --data-urlencode "password=admin" \
    --data-urlencode "newPassword=$NEW_ADMIN_PASSWORD" \
    --data-urlencode "confirmPassword=$NEW_ADMIN_PASSWORD")"
  if [ "$CHANGE_STATUS" != "200" ]; then
    echo "could not log in with DTRACK_ADMIN_PASSWORD, and changing the default admin/admin password also failed (HTTP $CHANGE_STATUS)." >&2
    echo "If dtrack's admin password is already something else, re-run with that value in DTRACK_ADMIN_PASSWORD." >&2
    exit 1
  fi
  JWT="$(login)"
fi

if [ -z "$JWT" ]; then
  echo "could not obtain a login token" >&2
  exit 1
fi
echo "    logged in."

echo "==> Finding team '$TEAM_NAME' ..."
TEAM_JSON="$(curl -sf -H "Authorization: Bearer $JWT" "$DTRACK_URL/api/v1/team")"
TEAM_UUID="$(echo "$TEAM_JSON" | python3 -c "
import json, sys
name = sys.argv[1]
for t in json.load(sys.stdin):
    if t['name'] == name:
        print(t['uuid'])
        break
" "$TEAM_NAME")"
if [ -z "$TEAM_UUID" ]; then
  echo "team '$TEAM_NAME' not found (set DTRACK_TEAM to an existing team name)" >&2
  exit 1
fi
echo "    $TEAM_UUID"

echo "==> Granting permissions (BOM_UPLOAD, PROJECT_CREATION_UPLOAD, VIEW_VULNERABILITY) ..."
for perm in BOM_UPLOAD PROJECT_CREATION_UPLOAD VIEW_VULNERABILITY; do
  STATUS="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $JWT" \
    "$DTRACK_URL/api/v1/permission/$perm/team/$TEAM_UUID")"
  if [ "$STATUS" = "200" ]; then
    echo "    $perm: granted"
  else
    echo "    $perm: HTTP $STATUS (likely already granted — safe to ignore)"
  fi
done

EXISTING_KEY=""
if [ -n "${DTRACK_BOOTSTRAP_KEY_FILE:-}" ]; then
  if [ -f "$DTRACK_BOOTSTRAP_KEY_FILE" ]; then
    EXISTING_KEY="$(cat "$DTRACK_BOOTSTRAP_KEY_FILE")"
  fi
elif [ -f "$ENV_FILE" ]; then
  EXISTING_KEY="$(grep -m1 '^DTRACK_API_KEY=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)"
fi

if [ -n "$EXISTING_KEY" ] && [ "$NEW_KEY" = false ]; then
  echo "==> a DTRACK_API_KEY already exists — leaving it as-is (pass --new-key to mint a fresh one)."
else
  echo "==> Generating a new API key for '$TEAM_NAME' ..."
  API_KEY="$(curl -sf -X PUT -H "Authorization: Bearer $JWT" "$DTRACK_URL/api/v1/team/$TEAM_UUID/key" \
    | python3 -c "import json, sys; print(json.load(sys.stdin)['key'])")"
  if [ -z "$API_KEY" ]; then
    echo "failed to generate an API key" >&2
    exit 1
  fi
  if [ -n "${DTRACK_BOOTSTRAP_KEY_FILE:-}" ]; then
    mkdir -p "$(dirname "$DTRACK_BOOTSTRAP_KEY_FILE")"
    printf '%s' "$API_KEY" > "$DTRACK_BOOTSTRAP_KEY_FILE"
    echo "    written to $DTRACK_BOOTSTRAP_KEY_FILE"
  else
    touch "$ENV_FILE"
    if grep -q '^DTRACK_API_KEY=' "$ENV_FILE" 2>/dev/null; then
      TMP="$(mktemp)"
      sed "s|^DTRACK_API_KEY=.*|DTRACK_API_KEY=$API_KEY|" "$ENV_FILE" > "$TMP" && mv "$TMP" "$ENV_FILE"
    else
      echo "DTRACK_API_KEY=$API_KEY" >> "$ENV_FILE"
    fi
    echo "    written to $ENV_FILE"
  fi
fi

if [ -n "${DTRACK_BOOTSTRAP_KEY_FILE:-}" ]; then
  echo
  echo "==> Done."
else
  cat <<'EOF'

==> Done. Restart the api service to pick it up:
      docker compose --profile dtrack up -d api

    Verify with:
      curl -H "Authorization: Bearer <your-magnolia-key>" http://localhost:3000/api/v1/config
      (should show "dtrack_enabled":true)
EOF
fi
