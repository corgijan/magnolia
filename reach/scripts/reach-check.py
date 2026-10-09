#!/usr/bin/env python3
"""reach-check.py — one-shot CLI for the `reach` CVE-reachability analyser.

The service's own API already does everything this script does
(`POST /api/v1/analyses`, poll `GET /api/v1/analyses/{id}`) — this exists
purely to remove the one piece of friction between "I have a public repo URL
and some vulnerability text" and a result: `reach` deliberately refuses to
analyse a moving branch, so it needs an exact commit id, not just a repo URL.
This script resolves that (via `git ls-remote`, no clone) and polls to
completion so you can run one command instead of two API calls glued
together by hand.

Examples
--------
Advisory text inline, HEAD of the default branch:
    ./reach-check.py --repo https://github.com/acme/app \\
        --advisory "The \\`unsafeLoad\\` function instantiates arbitrary \\
constructors named in the document, allowing remote code execution."

Advisory text from a file, a specific tag, piped through jq:
    ./reach-check.py --repo https://github.com/acme/app --ref v2.1.0 \\
        --advisory-file cve-2024-1234.txt --json | jq .report.priority

Advisory text from stdin (no --advisory/--advisory-file given):
    curl -s https://api.osv.dev/v1/vulns/GHSA-xxxx | jq -r .details \\
        | ./reach-check.py --repo https://github.com/acme/app

Exit codes: 0 analysis completed (regardless of the priority it reports —
that is evidence, not a pass/fail verdict); 1 usage error; 2 could not talk
to the reach server; 3 the analysis could not run (repo/commit problem); 4
timed out waiting for it to finish.

--experimental-verdict
--------------------------------------------------------------------------
NOT PART OF THE `reach` SERVICE. NOT COMPLIANT WITH THIS PROJECT'S OWN
STATED REQUIREMENTS. DO NOT USE FOR THE GRADED SUBMISSION.

`reach` itself, by explicit design (see CLAUDE.md and reach/README.md),
never produces an exploitability verdict and never shows a raw model
confidence as if it were a calibrated probability — "evidence for an
analyst, never an automated verdict" is stated as a hard requirement, and
the whole pipeline (prompts, rubric, eval suite) is built to enforce it.

This exists only because it was explicitly requested after that tradeoff
was raised and acknowledged, and it is now ON BY DEFAULT (pass
--no-experimental-verdict to turn it off). It makes a SEPARATE, ad-hoc call
straight to the configured inference endpoint (bypassing `reach` entirely)
asking the model to render a yes/no applicability judgement and a bare
percentage. That percentage is not calibrated against anything — it is
whatever number the model happens to emit when asked for one — and it is
printed with a loud warning every time it runs. Reads REACH_AI_BASE_URL /
REACH_AI_MODEL / REACH_AI_API_KEY from reach/.env automatically (same file
the server reads, same names), or from the real environment, or pass
--verdict-base-url etc. directly.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

def _load_dotenv_fallback() -> None:
    """Best-effort: read reach/.env (this script's parent directory) for any
    vars not already exported in the real environment -- mirrors what
    `reach`'s own server does via dotenvy, so this script picks up the same
    config file without needing everything exported by hand first. Real env
    vars always win; a missing or unreadable file is silently fine."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip()


_load_dotenv_fallback()

DEFAULT_URL = os.environ.get("REACH_URL", "http://127.0.0.1:3100")
DEFAULT_TOKEN = os.environ.get("REACH_API_TOKEN", "")


def die(message: str, code: int = 1) -> None:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(code)


def resolve_commit(repo_url: str, ref: str) -> str:
    """Full commit object id for `ref` in `repo_url`, via `git ls-remote` —
    no clone, matching how `reach` itself only ever wants an exact revision.

    Same hardening `reach`'s own fetcher applies: no interactive credential
    prompt (a hang here would look like the script itself is broken), and a
    bounded timeout so an unreachable host fails fast rather than hanging
    the whole run.
    """
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="", SSH_ASKPASS="")
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--exit-code", repo_url, ref],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
    except FileNotFoundError:
        die("git is required to resolve a commit id (not found on PATH)")
    except subprocess.TimeoutExpired:
        die(f"timed out resolving {ref!r} on {repo_url} (30s) — check the URL and your network")

    if result.returncode != 0:
        die(
            f"could not resolve {ref!r} on {repo_url}: "
            f"{result.stderr.strip() or f'git exited {result.returncode}'}"
        )

    first_line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    sha = first_line.split("\t", 1)[0].strip() if first_line else ""
    if len(sha) not in (40, 64) or not all(c in "0123456789abcdefABCDEF" for c in sha):
        die(f"git ls-remote returned something that isn't a commit id: {first_line!r}")
    return sha.lower()


def read_advisory(inline: str | None, path: str | None) -> str:
    if inline and path:
        die("--advisory and --advisory-file are mutually exclusive")
    if inline:
        return inline
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except OSError as e:
            die(f"could not read {path}: {e}")
    if sys.stdin.isatty():
        die(
            "no advisory text given — pass --advisory TEXT, --advisory-file FILE, "
            "or pipe it in on stdin"
        )
    return sys.stdin.read()


def api_request(url: str, token: str, method: str, path: str, body: dict | None = None):
    req = urllib.request.Request(url.rstrip("/") + path, method=method)
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, data=data, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"error": raw}
    except urllib.error.URLError as e:
        die(f"could not reach {url}: {e.reason} — is reach running there?", code=2)


def create_analysis(url: str, token: str, request_body: dict) -> str:
    status, payload = api_request(url, token, "POST", "/api/v1/analyses", request_body)
    if status >= 400:
        die(f"reach rejected the request (HTTP {status}): {payload.get('error', payload)}", code=2)
    return payload["id"]


def poll_until_done(url: str, token: str, analysis_id: str, poll_interval: float, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    last_status = None
    while True:
        status, payload = api_request(url, token, "GET", f"/api/v1/analyses/{analysis_id}")
        if status >= 400:
            die(f"lost track of the analysis (HTTP {status}): {payload.get('error', payload)}", code=2)

        current = payload.get("status")
        if current != last_status:
            print(f"[{analysis_id}] {current}", file=sys.stderr)
            last_status = current

        if current in ("completed", "failed"):
            return payload

        if time.monotonic() >= deadline:
            die(
                f"gave up after {timeout:.0f}s waiting for the analysis to finish "
                f"(still {current}) — raise --timeout for a slow local model, "
                f"or check on it later with:\n  {url}/api/v1/analyses/{analysis_id}",
                code=4,
            )
        time.sleep(poll_interval)


def print_human_report(view: dict) -> None:
    report = view.get("report")
    if not report:
        print(f"status: {view.get('status')}")
        if view.get("error"):
            print(f"error:  {view['error']}")
        return

    print(f"priority: {report['priority']}  —  {report['priority_description']}")
    print(f"\n{report['disclaimer']}\n")

    # Always shown, even when empty — an empty ruleset ("the advisory named
    # no specific symbol") is explicitly a *correct* answer in this
    # pipeline's design, not a failure, so it must never look like the
    # report simply has nothing to say. A blank gap here is indistinguishable
    # from a rendering bug; a stated "(none)" is not.
    ruleset = report.get("ruleset") or {}
    print(f"advisory summary: {ruleset.get('summary') or '(none given)'}")
    print(f"searched for:      {', '.join(ruleset.get('vulnerable_symbols', [])) or '(no symbols extracted)'}")
    if ruleset.get("nested_calls"):
        compositions = ", ".join(f"{p['outer']}(...{p['inner']}(...)...)" for p in ruleset["nested_calls"])
        print(f"compositions:      {compositions}")
    if ruleset.get("preconditions"):
        print(f"preconditions:     {'; '.join(ruleset['preconditions'])}")
    if ruleset.get("notes"):
        print(f"model notes:       {'; '.join(ruleset['notes'])}")
    print()

    if report.get("package_present") is not None:
        print(f"package present: {report['package_present']}")
        for line in report.get("package_evidence", []):
            print(f"  - {line}")
        print()

    sites = report.get("sites", [])
    print(f"{len(sites)} occurrence(s){':' if sites else ' — nothing to search for, or nothing found.'}")
    for s in sites:
        label = s.get("label") or "not classified"
        print(f"\n  {s['path']}:{s['line']}  [{label}]  (matched `{s['term']}`)")
        if s.get("reasoning"):
            print(f"    {s['reasoning']}")
        for line in s["snippet"].splitlines():
            print(f"    {line}")

    # Every stage, not just degraded/failed ones -- an *Ok* stage B that
    # extracted nothing is exactly the case that most needs its own detail
    # line surfaced, since that is the actual explanation for an empty
    # report, and "Ok" must not be read as "nothing worth telling you".
    print("\npipeline stages:")
    for st in report.get("stages", []):
        print(f"  {st['stage']} {st['name']} [{st['status']}]: {st['detail']}")


# ============================================================================
# --experimental-verdict — see the module docstring. Not part of the reach
# service; makes its own separate call straight to the inference endpoint.
# Everything below this line is that isolated, clearly-non-compliant path.
# ============================================================================

VERDICT_WARNING = """\
################################################################################
# --experimental-verdict:
################################################################################"""


def format_all_sites_for_prompt(sites: list) -> str:
    """Every occurrence reach found, regardless of how it found it (an
    independent lexical name match, or a structural nested-call match — the
    `term` field alone doesn't say which, and this function doesn't need to
    care). The model gets to look at all of them together and decide which
    one actually matters, instead of a Python heuristic pre-picking one
    before the model ever sees the rest."""
    if not sites:
        return "(no occurrences were found)"
    blocks = []
    for i, s in enumerate(sites):
        label = s.get("label") or "not scored"
        snippet = "\n".join(s.get("snippet", "").splitlines()[:20])
        block = (
            f"[{i}] {s['path']}:{s['line']}  label={label}  matched=`{s['term']}`\n"
            f"{('reasoning: ' + s['reasoning']) if s.get('reasoning') else ''}\n"
            f"{snippet}"
        )
        blocks.append(block)
    return "\n\n".join(blocks)


def call_llm_directly(base_url: str, api_key: str, model: str, prompt: str, max_tokens: int) -> str:
    """A raw OpenAI-compatible chat completion, made by this script directly
    — not through `reach`, which never makes a call shaped like this one."""
    req = urllib.request.Request(
        base_url.rstrip("/") + "/v1/chat/completions",
        method="POST",
        data=json.dumps(
            {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
            }
        ).encode("utf-8"),
    )
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            envelope = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        die(f"--experimental-verdict: could not reach the inference endpoint: {e}", code=2)

    try:
        message = envelope["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        die(f"--experimental-verdict: unusable response envelope: {envelope}", code=2)

    content = message.get("content")
    if content:
        return content

    # Same failure `reach`'s own client now detects and names specifically:
    # a reasoning model (content: null) whose whole token budget went to
    # hidden chain-of-thought before it wrote an answer. This ad-hoc call
    # has no repair-retry, so the only thing to do is say so plainly.
    reasoning = message.get("reasoning") or message.get("reasoning_content")
    if reasoning:
        die(
            "--experimental-verdict: the model spent its whole token budget on internal "
            f"reasoning and never wrote an answer (raise --verdict-max-tokens, currently "
            f"{max_tokens}). Captured reasoning: {reasoning[:200]!r}",
            code=2,
        )
    return ""


def print_experimental_verdict(
    report: dict, base_url: str, api_key: str, model: str, max_tokens: int
) -> None:
    print(f"\n{VERDICT_WARNING}\n")

    sites = report.get("sites", [])
    ruleset = report.get("ruleset") or {}
    prompt = (
        "You are reviewing every occurrence a static-analysis tool found for one advisory, and "
        "picking which one actually matters, then giving a final applicability judgement -- for "
        "a user who has explicitly asked for one and understands it is not independently "
        "verified. Some occurrences below were found by matching an individual symbol name; "
        "others by matching a specific pattern of one call nested inside another. Judge each "
        "on what its own code actually shows, not on how it was found.\n\n"
        f"Advisory: {ruleset.get('summary', '(not available)')}\n"
        f"Reachability evidence priority: {report['priority']} — {report['priority_description']}\n\n"
        f"All occurrences found ({len(sites)}):\n\n{format_all_sites_for_prompt(sites)}\n\n"
        'Reply with ONLY a JSON object: {"most_relevant_index": <integer index from the list '
        'above, or null if none apply>, "applicable": "yes"|"no"|"uncertain", '
        '"confidence_percent": <integer 0-100>, "explanation": "<one or two sentences>"}'
    )
    raw = call_llm_directly(base_url, api_key, model, prompt, max_tokens)
    try:
        start, end = raw.index("{"), raw.rindex("}") + 1
        verdict = json.loads(raw[start:end])
    except (ValueError, json.JSONDecodeError):
        print(f"(could not parse a verdict out of the model's response: {raw[:300]!r})")
        print(f"\n{VERDICT_WARNING}")
        return

    # The printed snippet always comes from reach's own report, never from
    # anything the model might paraphrase back -- an index is just a
    # pointer, and an out-of-range or missing one degrades to "none picked"
    # rather than guessing.
    idx = verdict.get("most_relevant_index")
    site = sites[idx] if isinstance(idx, int) and 0 <= idx < len(sites) else None

    print("_" * 78)
    print("MOST LIKELY RELEVANT PLACE (picked by the model, from all occurrences shown above)")
    print("_" * 78)
    if site:
        print(f"{site['path']}:{site['line']}  (matched `{site['term']}`)")
        if site.get("reasoning"):
            print(f"  {site['reasoning']}")
        if site.get("snippet"):
            print()
            for line in site["snippet"].splitlines():
                print(f"    {line}")
    else:
        print("(the model did not point at a specific occurrence)")

    print()
    print("_" * 78)
    print("AI VERDICT — UNCALIBRATED, EXPERIMENTAL, NOT PART OF reach")
    print("_" * 78)
    print(f"applicable to this codebase: {verdict.get('applicable', '?')}")
    print(f"confidence (model's own, uncalibrated number): {verdict.get('confidence_percent', '?')}%")
    if verdict.get("explanation"):
        print(f"explanation: {verdict['explanation']}")
    print(f"\n{VERDICT_WARNING}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Queue and wait for a reach CVE-reachability analysis against a public git repo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Exit codes")[0],
    )
    parser.add_argument("--repo", required=True, help="https:// git URL (or an absolute local path)")
    parser.add_argument("--ref", default="HEAD", help="branch/tag to resolve if --commit is not given (default: HEAD)")
    parser.add_argument("--commit", help="exact commit id — skips the git ls-remote resolution step")
    parser.add_argument("--subpath", help="monorepo subdirectory to scan")
    advisory = parser.add_mutually_exclusive_group()
    advisory.add_argument("--advisory", help="advisory text, inline")
    advisory.add_argument("--advisory-file", help="path to a file containing the advisory text")
    parser.add_argument("--osv-id", help="e.g. GHSA-xxxx-xxxx-xxxx or CVE-2024-1234")
    parser.add_argument("--package", help="affected package name, if known")
    parser.add_argument("--ecosystem", help="npm, PyPI, Maven, crates.io, ...")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"reach base URL (default: {DEFAULT_URL}, or $REACH_URL)")
    parser.add_argument("--token", default=DEFAULT_TOKEN, help="bearer token (default: $REACH_API_TOKEN)")
    parser.add_argument("--poll-interval", type=float, default=3.0, help="seconds between status polls (default: 3)")
    parser.add_argument("--timeout", type=float, default=900.0, help="max seconds to wait (default: 900)")
    parser.add_argument("--json", action="store_true", help="print the raw JSON result instead of a summary")
    parser.add_argument(
        "--experimental-verdict",
        dest="experimental_verdict",
        action="store_true",
        default=True,
        help="NOT PART OF reach, NOT COMPLIANT with this project's own no-verdict/no-probability "
        "rule (see CLAUDE.md) — prints an extra, separately-generated applicability verdict and "
        "an uncalibrated confidence %%. ON BY DEFAULT; see --no-experimental-verdict to disable, "
        "and the module docstring before using the output for anything.",
    )
    parser.add_argument(
        "--no-experimental-verdict",
        dest="experimental_verdict",
        action="store_false",
        help="disable the verdict+confidence output (which is on by default)",
    )
    parser.add_argument("--verdict-base-url", default=os.environ.get("REACH_AI_BASE_URL", ""))
    parser.add_argument("--verdict-model", default=os.environ.get("REACH_AI_MODEL", ""))
    parser.add_argument("--verdict-api-key", default=os.environ.get("REACH_AI_API_KEY", ""))
    parser.add_argument(
        "--verdict-max-tokens",
        type=int,
        default=int(os.environ.get("REACH_AI_MAX_TOKENS", "4000") or 4000),
        help="token budget for the --experimental-verdict call (default: $REACH_AI_MAX_TOKENS or "
        "4000 — reasoning models need real headroom here or they never reach an answer)",
    )
    args = parser.parse_args()

    if args.experimental_verdict and not (args.verdict_base_url and args.verdict_model):
        die(
            "the verdict output needs REACH_AI_BASE_URL and REACH_AI_MODEL — set them in "
            "reach/.env, export them, or pass --verdict-base-url/--verdict-model directly. "
            "Use --no-experimental-verdict to skip this output instead."
        )

    advisory_text = read_advisory(args.advisory, args.advisory_file)
    commit = args.commit or resolve_commit(args.repo, args.ref)

    body = {
        "advisory_text": advisory_text,
        "repo_url": args.repo,
        "commit": commit,
    }
    for key, value in [
        ("osv_id", args.osv_id),
        ("package_name", args.package),
        ("ecosystem", args.ecosystem),
        ("subpath", args.subpath),
    ]:
        if value:
            body[key] = value

    print(f"analysing {args.repo} @ {commit}", file=sys.stderr)
    analysis_id = create_analysis(args.url, args.token, body)
    view = poll_until_done(args.url, args.token, analysis_id, args.poll_interval, args.timeout)

    if args.json:
        print(json.dumps(view, indent=2))
    else:
        print_human_report(view)

    if args.experimental_verdict and view.get("report"):
        print_experimental_verdict(
            view["report"],
            args.verdict_base_url,
            args.verdict_api_key,
            args.verdict_model,
            args.verdict_max_tokens,
        )

    sys.exit(0 if view.get("status") == "completed" else 3)


if __name__ == "__main__":
    main()
