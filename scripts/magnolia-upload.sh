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
#   --tenant-url=URL    e.g. https://acme.magnolia.example
#   --tenant-id=UUID    explicit target tenant (see note below)
#   --namespace=PATH    e.g. /product/v1
#   --sbom=PATH         path to the SBOM file to upload
#   --format=FORMAT     cyclonedx|spdx (default: cyclonedx)
#   --version=VERSION   free-text release label (see fallback order below)
#   --file=PATH         path to the Magnoliafile (default: search upward
#                        from $PWD)
#
# --tenant-id only matters if MAGNOLIA_API_KEY is a platform super_admin
# key (the bootstrap key) -- it lets that key upload on behalf of a real
# tenant instead of its own, since uploads to the platform tenant itself
# are always rejected (HTTP 400 "uploads are not allowed to the platform
# tenant"). For a normal tenant key, leave this unset -- the tenant is
# already implied by the key, and setting it anyway gets a 403 ("only the
# platform super_admin can act on another tenant").
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
TENANT_ID=""
NAMESPACE=""
SBOM=""
FORMAT=""
VERSION=""
MAGNOLIAFILE=""

for arg in "$@"; do
  case "$arg" in
    --tenant-url=*) TENANT_URL="${arg#--tenant-url=}" ;;
    --tenant-id=*)  TENANT_ID="${arg#--tenant-id=}" ;;
    --namespace=*)  NAMESPACE="${arg#--namespace=}" ;;
    --sbom=*)       SBOM="${arg#--sbom=}" ;;
    --format=*)     FORMAT="${arg#--format=}" ;;
    --version=*)    VERSION="${arg#--version=}" ;;
    --file=*)       MAGNOLIAFILE="${arg#--file=}" ;;
    -h|--help)
      sed -n '2,30p' "$0"
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

[ -n "$TENANT_URL" ] || TENANT_URL="$(file_get tenant_url)"
[ -n "$TENANT_ID" ]  || TENANT_ID="$(file_get tenant_id)"
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
[ -n "$TENANT_URL" ] || missing+=(tenant_url)
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

UPLOAD_URL="$TENANT_URL/api/v1/upload"
[ -z "$TENANT_ID" ] || UPLOAD_URL="${UPLOAD_URL}?tenant_id=${TENANT_ID}"

echo "==> uploading $SBOM to ${TENANT_URL}${NAMESPACE} @ $VERSION ($FORMAT)${TENANT_ID:+ [tenant_id=$TENANT_ID]}"
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
