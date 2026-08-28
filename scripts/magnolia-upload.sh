#!/usr/bin/env bash
set -euo pipefail

# Uploads an SBOM to Magnolia (POST /api/v1/upload). Settings are read from
# a `Magnoliafile` (searched for by walking up from $PWD, like git finds
# .git), overridable per-flag on the command line -- flags always win, since
# --version is expected to change on every CI run while tenant_url/
# namespace/format/sbom usually don't.
#
# Usage, piped straight from curl (note `bash -s --` is required to pass
# flags through a pipe -- otherwise they're swallowed by curl, not bash):
#   curl -fsSL https://magnolia.acme.example/install.sh | bash -s -- --version=2.0.0
#
# Or run locally against a checked-out Magnoliafile:
#   MAGNOLIA_API_KEY='<key_id>:<secret>' ./magnolia-upload.sh
#
# Flags (all optional -- fall back to the Magnoliafile, then to computed
# defaults where noted below):
#   --tenant-url=URL      e.g. https://acme.magnolia.example
#   --tenant-domain=DOMAIN REQUIRED -- target tenant's domain, see note below
#   --namespace=PATH      e.g. /product/v1
#   --sbom=PATH           path to the SBOM file to upload
#   --format=FORMAT       cyclonedx|spdx (default: cyclonedx)
#   --version=VERSION     free-text release label (see fallback order below)
#   --file=PATH           path to the Magnoliafile (default: search upward
#                          from $PWD)
#
# tenant_domain is REQUIRED (in the Magnoliafile or via --tenant-domain) --
# a human-readable domain (e.g. acme.example), not a UUID -- the script
# refuses to run without it, deliberately, so it never silently uploads
# under whatever tenant MAGNOLIA_API_KEY happens to imply (that's how
# uploads ended up hitting the platform/bootstrap tenant and getting a 400
# earlier). Before uploading, the script calls GET /api/v1/whoami with
# MAGNOLIA_API_KEY and compares its own domain against the configured one --
# a mismatch (wrong key for the intended tenant) is caught right here with
# a clear message, instead of surfacing as a generic 400/403 from the
# upload endpoint itself. Purely a client-side check -- the API's own
# auth/tenant-scoping (`effective_tenant` in handlers.rs) is untouched: if
# the key's own domain matches, the upload is a normal same-tenant request
# (no UUID lookup needed at all). Only when the key is the platform
# super_admin legitimately acting on a *different* tenant does the script
# resolve tenant_domain to a UUID via `GET /api/v1/tenants` (super_admin
# only) and add `?tenant_id=` to the request.
#
# version resolution order when --version is not given:
#   1. `version=` in the Magnoliafile
#   2. the exact git tag on HEAD, if there is one
#   3. `git describe --tags --always --dirty` (falls back to a bare short
#      commit hash if the repo has no tags at all)
#
# Auth: the API key is read only from the MAGNOLIA_API_KEY env var (never a
# CLI flag and never the Magnoliafile) so it can't leak via shell history or
# `ps`. Get one with `POST /api/v1/keys` against your own tenant.

TENANT_URL=""
TENANT_DOMAIN=""
NAMESPACE=""
SBOM=""
FORMAT=""
VERSION=""
MAGNOLIAFILE=""

for arg in "$@"; do
  case "$arg" in
    --tenant-url=*)    TENANT_URL="${arg#--tenant-url=}" ;;
    --tenant-domain=*) TENANT_DOMAIN="${arg#--tenant-domain=}" ;;
    --namespace=*)  NAMESPACE="${arg#--namespace=}" ;;
    --sbom=*)       SBOM="${arg#--sbom=}" ;;
    --format=*)     FORMAT="${arg#--format=}" ;;
    --version=*)    VERSION="${arg#--version=}" ;;
    --file=*)       MAGNOLIAFILE="${arg#--file=}" ;;
    -h|--help)
      sed -n '2,53p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

# --- locate the Magnoliafile (unless --file was given) ---------------------
if [ -z "$MAGNOLIAFILE" ]; then
  dir="$PWD"
  while [ "$dir" != "/" ]; do
    if [ -f "$dir/Magnoliafile" ]; then
      MAGNOLIAFILE="$dir/Magnoliafile"
      break
    fi
    dir="$(dirname "$dir")"
  done
fi

# --- read the Magnoliafile: plain KEY=value, never `source`d, so nothing
# in a repo-controlled file can execute shell code -----------------------
file_get() {
  [ -n "$MAGNOLIAFILE" ] && [ -f "$MAGNOLIAFILE" ] || return 0
  grep -m1 -E "^$1=" "$MAGNOLIAFILE" 2>/dev/null | cut -d= -f2- || true
}

[ -n "$TENANT_URL" ]    || TENANT_URL="$(file_get tenant_url)"
[ -n "$TENANT_DOMAIN" ] || TENANT_DOMAIN="$(file_get tenant_domain)"
[ -n "$NAMESPACE" ]  || NAMESPACE="$(file_get namespace)"
[ -n "$SBOM" ]       || SBOM="$(file_get sbom)"
[ -n "$FORMAT" ]     || FORMAT="$(file_get format)"
[ -n "$VERSION" ]    || VERSION="$(file_get version)"
FORMAT="${FORMAT:-cyclonedx}"

# --- version fallback: Magnoliafile -> exact git tag -> git describe -----
if [ -z "$VERSION" ]; then
  if git describe --tags --exact-match >/dev/null 2>&1; then
    VERSION="$(git describe --tags --exact-match)"
  else
    VERSION="$(git describe --tags --always --dirty 2>/dev/null || true)"
  fi
fi

# --- validate ----------------------------------------------------------
missing=()
[ -n "$TENANT_URL" ]    || missing+=(tenant_url)
[ -n "$TENANT_DOMAIN" ] || missing+=(tenant_domain)
[ -n "$NAMESPACE" ]  || missing+=(namespace)
[ -n "$SBOM" ]       || missing+=(sbom)
[ -n "$VERSION" ]    || missing+=(version)
if [ ${#missing[@]} -gt 0 ]; then
  echo "missing required setting(s): ${missing[*]} (set in Magnoliafile or pass --<name>=...)" >&2
  exit 1
fi
if [ -z "${MAGNOLIA_API_KEY:-}" ]; then
  echo "MAGNOLIA_API_KEY is not set (export MAGNOLIA_API_KEY='<key_id>:<secret>')" >&2
  exit 1
fi
if [ ! -f "$SBOM" ]; then
  echo "sbom file not found: $SBOM" >&2
  exit 1
fi

# --- pre-flight: verify MAGNOLIA_API_KEY's own domain against the
# configured tenant_domain -- catches "wrong key for the intended tenant"
# here, with a clear message, instead of a generic 400/403 from the upload
# call.
if ! command -v python3 > /dev/null 2>&1; then
  echo "python3 is required (used to parse JSON responses)" >&2
  exit 1
fi

WHOAMI="$(curl -s -w '\n%{http_code}' "$TENANT_URL/api/v1/whoami" \
  -H "Authorization: Bearer $MAGNOLIA_API_KEY")"
WHOAMI_STATUS="$(echo "$WHOAMI" | tail -n1)"
WHOAMI_BODY="$(echo "$WHOAMI" | sed '$d')"
if [ "$WHOAMI_STATUS" != "200" ]; then
  echo "could not verify MAGNOLIA_API_KEY (whoami returned HTTP $WHOAMI_STATUS): $WHOAMI_BODY" >&2
  exit 1
fi
KEY_DOMAIN="$(printf '%s' "$WHOAMI_BODY" | python3 -c "import json, sys; print(json.load(sys.stdin)['domain'])")"
KEY_IS_PLATFORM="$(printf '%s' "$WHOAMI_BODY" | python3 -c "import json, sys; print(json.load(sys.stdin)['is_platform_tenant'])")"

if [ "$KEY_DOMAIN" = "$TENANT_DOMAIN" ]; then
  UPLOAD_URL="$TENANT_URL/api/v1/upload"
elif [ "$KEY_IS_PLATFORM" = "True" ]; then
  # legitimate cross-tenant case: platform super_admin acting on another
  # tenant -- the API only honors ?tenant_id= from exactly this key type,
  # and only as a UUID, so resolve tenant_domain via GET /api/v1/tenants
  # (also super_admin-only, so this reuses the same privilege we already
  # confirmed via KEY_IS_PLATFORM).
  TENANTS="$(curl -s -w '\n%{http_code}' "$TENANT_URL/api/v1/tenants" \
    -H "Authorization: Bearer $MAGNOLIA_API_KEY")"
  TENANTS_STATUS="$(echo "$TENANTS" | tail -n1)"
  TENANTS_BODY="$(echo "$TENANTS" | sed '$d')"
  if [ "$TENANTS_STATUS" != "200" ]; then
    echo "could not list tenants to resolve tenant_domain (HTTP $TENANTS_STATUS): $TENANTS_BODY" >&2
    exit 1
  fi
  RESOLVED_TENANT_ID="$(printf '%s' "$TENANTS_BODY" | python3 -c "
import json, sys
domain = sys.argv[1]
for t in json.load(sys.stdin):
    if t['domain'] == domain:
        print(t['id'])
        break
" "$TENANT_DOMAIN")"
  if [ -z "$RESOLVED_TENANT_ID" ]; then
    echo "tenant_domain '$TENANT_DOMAIN' not found via GET /api/v1/tenants" >&2
    exit 1
  fi
  UPLOAD_URL="${TENANT_URL}/api/v1/upload?tenant_id=${RESOLVED_TENANT_ID}"
else
  echo "tenant mismatch: MAGNOLIA_API_KEY belongs to domain '$KEY_DOMAIN', but tenant_domain is set to '$TENANT_DOMAIN'." >&2
  echo "Use the key that belongs to '$TENANT_DOMAIN', fix tenant_domain, or use a platform super_admin key to act cross-tenant." >&2
  exit 1
fi

echo "==> uploading $SBOM to ${TENANT_URL}${NAMESPACE} @ $VERSION ($FORMAT) [tenant_domain=$TENANT_DOMAIN]"
RESP="$(curl -s -w '\n%{http_code}' -X POST "$UPLOAD_URL" \
  -H "Authorization: Bearer $MAGNOLIA_API_KEY" \
  -F "sbom_file=@${SBOM}" \
  -F "format=${FORMAT}" \
  -F "namespace=${NAMESPACE}" \
  -F "version=${VERSION}")"
STATUS="$(echo "$RESP" | tail -n1)"
BODY="$(echo "$RESP" | sed '$d')"

if [ "$STATUS" != "200" ]; then
  echo "upload failed (HTTP $STATUS): $BODY" >&2
  exit 1
fi
echo "$BODY"
