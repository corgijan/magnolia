#!/usr/bin/env sh
# Bring up the AISE stack with the CVE-reachability analyser pointed at an
# OpenAI-compatible endpoint, and wait until it is actually usable.
#
# Why this exists: `reach` refuses to bind its port unless a real test
# completion succeeds against REACH_AI_BASE_URL (see reach/src/main.rs), and
# compose reads only the ROOT .env — never reach/.env, which is not copied
# into the image. A plain `docker compose up` with no REACH_AI_* in the root
# .env therefore falls back to the profile-gated `ollama` service, cannot
# reach it, and the container exits before its HEALTHCHECK can ever run.
#
#   ./scripts/stack-up.sh --frontend           # the full stack (recommended):
#                                              #    db, api, reach, web UI on
#                                              #    :4000, and Dependency-Track
#                                              #    (which produces the findings
#                                              #    reachability attaches to)
#   ./scripts/stack-up.sh                      # same, without the web UI
#   ./scripts/stack-up.sh --frontend --no-dtrack
#                                              # without Dependency-Track: no
#                                              #    findings, so no analyses
#   ./scripts/stack-up.sh --frontend --test-mode
#                                              # reach returns CANNED reports
#                                              #    and needs no model
#                                              #    (REACH_TEST_MODE)
#
# Set REACH_AI_BASE_URL / REACH_AI_MODEL / REACH_AI_API_KEY in the root .env.
# To reuse whatever a native `cargo run` already uses:
#     grep -E '^REACH_AI_' reach/.env >> .env
set -eu

cd "$(dirname "$0")/.."

PROFILES=""
WANT_DTRACK=1
TEST_MODE=0
for arg in "$@"; do
    case "$arg" in
        --frontend) PROFILES="$PROFILES --profile frontend" ;;
        --dtrack)   WANT_DTRACK=1 ;;   # the default; kept for old invocations
        --no-dtrack) WANT_DTRACK=0 ;;
        --test-mode) TEST_MODE=1 ;;
        # Print the header comment block and stop at the first line of code,
        # so the help text can never drift out of sync with a fixed range.
        -h|--help)  awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
        *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done

if [ ! -f .env ]; then
    echo "error: no .env — copy .env.example and fill it in first" >&2
    exit 1
fi

# Dependency-Track comes in through its override file, which also runs the
# one-time bootstrap (admin password, API key) in a container on the compose
# network and hands the key to `api` through a shared volume — no host port
# and no manual step. Every compose call below uses the same file set, so
# `ps`/`logs` see the dtrack services too.
COMPOSE="docker compose -f docker-compose.yml"
if [ "$WANT_DTRACK" -eq 1 ]; then
    COMPOSE="$COMPOSE -f docker-compose.dtrack.yml"
fi

# Exported either way, so the flag (not a stale .env line) decides this run.
if [ "$TEST_MODE" -eq 1 ]; then
    export REACH_TEST_MODE=true
    echo "==> TEST MODE: reach will return canned reports; nothing is analysed"
else
    export REACH_TEST_MODE=
fi

# Fail before a five-minute build rather than after it: an unset base URL
# means reach will probe the ollama service that this script does not start.
if [ "$TEST_MODE" -eq 0 ] && ! grep -q '^REACH_AI_BASE_URL=..*' .env; then
    cat >&2 <<'EOF'
error: REACH_AI_BASE_URL is not set in .env, so `reach` would probe
       http://ollama:11434 (a service this script does not start), fail its
       startup check, and exit.

       To use the same endpoint a native `cargo run` uses:
           grep -E '^REACH_AI_' reach/.env >> .env

       To use a local model instead:
           docker compose --profile ollama up -d ollama
           docker compose exec ollama ollama pull gemma3:4b
           # then set REACH_AI_BASE_URL=http://ollama:11434 in .env
EOF
    exit 1
fi


echo "==> building and starting"
# shellcheck disable=SC2086
$COMPOSE $PROFILES up -d --build

# The startup check is a real generation, so it can take a while — and `reach`
# now restarts rather than staying dead, so a transient failure shows up as
# repeated restarts instead of an exit. Poll for `healthy`, which the process
# only reaches after binding, which it only does after the check passed.
echo "==> waiting for reach to pass its inference-endpoint check"
i=0
while [ "$i" -lt 60 ]; do
    cid=$($COMPOSE ps -q reach 2>/dev/null || true)
    if [ -z "$cid" ]; then
        echo "error: no reach container" >&2
        exit 1
    fi
    health=$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo "")
    restarts=$(docker inspect --format '{{.RestartCount}}' "$cid" 2>/dev/null || echo 0)

    if [ "$health" = "healthy" ]; then
        echo "==> reach is up"
        break
    fi
    # A restart loop means the check is failing for a real reason, not a slow
    # model. Say so instead of waiting out the full five minutes.
    if [ "${restarts:-0}" -ge 2 ]; then
        echo "error: reach has restarted $restarts times — its startup check keeps failing:" >&2
        $COMPOSE logs reach --tail 25 >&2
        exit 1
    fi
    i=$((i + 1))
    sleep 5
done

if [ "$i" -ge 60 ]; then
    echo "warning: reach still not healthy after 5 minutes; last log lines:" >&2
    $COMPOSE logs reach --tail 20 >&2
fi

if [ "$WANT_DTRACK" -eq 1 ]; then
    # `api` only starts after dtrack-bootstrap has exited, so by now its
    # outcome is in its log. It always exits 0 (a failed bootstrap must not
    # block Magnolia), so read the log rather than the exit code.
    echo "==> Dependency-Track bootstrap"
    # `api` may have been recreated a moment ago; give it a few seconds to
    # log whether it found a key before judging.
    j=0
    until $COMPOSE logs api 2>/dev/null | grep -q 'Dependency-Track integration'; do
        j=$((j + 1)); [ "$j" -ge 15 ] && break; sleep 1
    done
    if $COMPOSE logs dtrack-bootstrap 2>/dev/null | grep -q 'dtrack bootstrap succeeded'; then
        echo "    ok — api reads the key from the shared volume"
    elif $COMPOSE logs api 2>/dev/null | grep -q 'Dependency-Track integration enabled'; then
        echo "    bootstrap did not complete, but api found an existing key — integration enabled"
    else
        echo "warning: Dependency-Track is running but the integration is not enabled:" >&2
        $COMPOSE logs dtrack-bootstrap --tail 8 >&2
        echo "  (an admin password already changed to something other than DTRACK_ADMIN_PASSWORD" >&2
        echo "   is the usual cause; see docs/OPERATIONS.md, \"Dependency-Track integration\")" >&2
    fi
    echo "    first start: Dependency-Track downloads its vulnerability databases before"
    echo "    findings appear, which can take a long while; give Docker several GB of memory"
fi

echo
$COMPOSE $PROFILES ps --format '{{.Service}}\t{{.State}}\t{{.Status}}'
echo
echo "api        http://localhost:${API_PORT:-3000}"
case "$PROFILES" in *frontend*) echo "web UI     http://localhost:${FRONTEND_PORT:-4000}" ;; esac
[ "$WANT_DTRACK" -eq 1 ] && echo "dtrack     internal only (http://dependency-track:8080)"
echo "analyser   internal only (http://reach:3100 on the compose network)"
echo
echo "the analyser's own inference-endpoint status:"
echo "  $COMPOSE logs reach | grep 'startup check'"
