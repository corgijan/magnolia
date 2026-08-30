#!/usr/bin/env python3
"""Uploads an SBOM to Magnolia (POST /api/v1/upload), or checks one against
a tenant's CI policy gate without storing it (POST /api/v1/verify).

Python port of magnolia-upload.sh — same behavior, same flags, same exit
codes, same Magnoliafile format. Stdlib only (json, urllib, subprocess,
argparse, ...) — nothing to `pip install`.

Settings are read from a `Magnoliafile` (searched for by walking up from
the current directory, like git finds .git), overridable per-flag on the
command line — flags always win, since --version is expected to change on
every CI run while tenant-url/namespace/format/sbom usually don't.

Usage:
    MAGNOLIA_API_KEY='mag_<secret>' ./magnolia-upload.py
    MAGNOLIA_API_KEY='mag_<secret>' ./magnolia-upload.py verify

Or piped straight from curl:
    curl -fsSL https://magnolia.acme.example/install.py | python3 - --version=2.0.0
    curl -fsSL https://magnolia.acme.example/install.py | python3 - verify --sbom=out.cdx.json

Subcommands (first positional argument; default: upload):
    upload   POST /api/v1/upload -- stores the SBOM and appends it to the
             transparency log. Requires --namespace and a resolvable
             --version.
    verify   POST /api/v1/verify -- runs the same schema/compliance/
             license-policy checks as upload, plus a synchronous
             malicious-package check, but nothing is stored: no Merkle
             leaf, no manifest record. Prints the check results, then exits
             non-zero when the verdict is "fail" -- wire this into a CI
             pipeline step. Does not need --namespace/--version.

tenant-domain is REQUIRED (in the Magnoliafile or via --tenant-domain) — a
human-readable domain (e.g. acme.example), not a UUID — the script refuses
to run without it, deliberately, so it never silently uploads under
whatever tenant MAGNOLIA_API_KEY happens to imply. Before uploading or
verifying, the script calls GET /api/v1/whoami with MAGNOLIA_API_KEY and
compares its own domain against the configured one — a mismatch (wrong key
for the intended tenant) is caught here with a clear message, instead of
surfacing as a generic 400/403 from the upload/verify endpoint itself. Only
when the key is the platform super_admin legitimately acting on a
*different* tenant does the script resolve tenant-domain to a UUID via
GET /api/v1/tenants (super_admin only) and add ?tenant_id= to the request.

Version resolution order when --version is not given (upload only):
    1. version= in the Magnoliafile
    2. the exact git tag on HEAD, if there is one
    3. `git describe --tags --always --dirty` (falls back to a bare short
       commit hash if the repo has no tags at all)

Auth: the API key is read only from the MAGNOLIA_API_KEY environment
variable (never a CLI flag and never the Magnoliafile) so it can't leak via
shell history or `ps`. Get one with POST /api/v1/keys against your own
tenant.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

DEFAULT_FORMAT = "cyclonedx"
MAGNOLIAFILE_NAME = "Magnoliafile"


def die(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------- config --


@dataclass(frozen=True)
class Config:
    mode: str  # "upload" | "verify"
    tenant_url: str
    tenant_domain: str
    sbom: Path
    format: str
    namespace: str
    version: str
    json_output: bool
    verbose: bool


def find_magnoliafile(explicit_path: str | None) -> Path | None:
    """Resolves the Magnoliafile to read: `explicit_path` if given
    (regardless of whether it exists — a bad --file should fail loudly
    later, not fall back silently), otherwise the nearest Magnoliafile
    found by walking up from the current directory, like git finds .git."""
    if explicit_path:
        return Path(explicit_path)
    for directory in (Path.cwd(), *Path.cwd().parents):
        candidate = directory / MAGNOLIAFILE_NAME
        if candidate.is_file():
            return candidate
    return None


def read_magnoliafile_value(path: Path | None, key: str) -> str:
    """Plain `key=value` lookup — the first line starting with `key=` wins,
    everything after that `=` (verbatim, no quote/whitespace stripping) is
    the value. Never `source`d/executed, so nothing in a repo-controlled
    file can run shell or Python code. Missing file or missing key both
    just mean "no value" — not an error, since every setting can also come
    from a CLI flag."""
    if path is None or not path.is_file():
        return ""
    prefix = f"{key}="
    for line in path.read_text().splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    return ""


def _run_git(args: list[str]) -> str | None:
    """Runs a git command, returning its stripped stdout on success or
    `None` on any failure — a non-zero exit, git itself not being
    installed, or this not being a git repository all collapse to the same
    "couldn't determine a version this way" outcome for the caller."""
    try:
        result = subprocess.run(
            ["git", *args], capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def resolve_version(explicit_or_magnoliafile: str) -> str:
    """Version fallback, upload-only: an explicit value (from --version or
    the Magnoliafile) wins outright; otherwise the exact git tag on HEAD,
    falling back to `git describe --tags --always --dirty`."""
    if explicit_or_magnoliafile:
        return explicit_or_magnoliafile
    exact_tag = _run_git(["describe", "--tags", "--exact-match"])
    if exact_tag:
        return exact_tag
    return _run_git(["describe", "--tags", "--always", "--dirty"]) or ""


def build_config(args: argparse.Namespace) -> Config:
    magnoliafile = find_magnoliafile(args.file)

    def setting(flag_value: str | None, key: str) -> str:
        return flag_value or read_magnoliafile_value(magnoliafile, key)

    tenant_url = setting(args.tenant_url, "tenant_url")
    tenant_domain = setting(args.tenant_domain, "tenant_domain")
    namespace = setting(args.namespace, "namespace")
    sbom = setting(args.sbom, "sbom")
    fmt = setting(args.format, "format") or DEFAULT_FORMAT
    version = ""
    if args.mode == "upload":
        version = resolve_version(setting(args.version, "version"))

    missing = [
        name
        for name, value in [
            ("tenant_url", tenant_url),
            ("tenant_domain", tenant_domain),
            ("sbom", sbom),
            *([("namespace", namespace)] if args.mode == "upload" else []),
            *([("version", version)] if args.mode == "upload" else []),
        ]
        if not value
    ]
    if missing:
        die(
            f"missing required setting(s): {' '.join(missing)} "
            "(set in Magnoliafile or pass --<name>=...)"
        )
    if not os.environ.get("MAGNOLIA_API_KEY"):
        die("MAGNOLIA_API_KEY is not set (export MAGNOLIA_API_KEY='mag_<secret>')")
    sbom_path = Path(sbom)
    if not sbom_path.is_file():
        die(f"sbom file not found: {sbom}")

    return Config(
        mode=args.mode,
        tenant_url=tenant_url.rstrip("/"),
        tenant_domain=tenant_domain,
        sbom=sbom_path,
        format=fmt,
        namespace=namespace,
        version=version,
        json_output=args.json,
        verbose=args.verbose,
    )


# ------------------------------------------------------------------ http --


def api_key() -> str:
    return os.environ["MAGNOLIA_API_KEY"]


def http_get(url: str) -> tuple[int, str]:
    request = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {api_key()}"}
    )
    return _send(request)


def http_post_multipart(
    url: str, fields: dict[str, str], file_field: str, file_path: Path
) -> tuple[int, str]:
    body, content_type = _encode_multipart(fields, file_field, file_path)
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key()}",
            "Content-Type": content_type,
        },
    )
    return _send(request)


def _send(request: urllib.request.Request) -> tuple[int, str]:
    """Runs one HTTP request, returning `(status, body)` for both success
    and HTTP-error responses alike (mirroring curl's `-w '%{http_code}'`
    behavior of always capturing status+body regardless of status class) —
    callers decide what counts as failure, this layer never raises for a
    non-2xx response. Only a genuine connection failure (DNS, TLS,
    connection refused, timeout) is a hard error."""
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        die(f"could not reach {request.full_url}: {e.reason}")


def _encode_multipart(
    fields: dict[str, str], file_field: str, file_path: Path
) -> tuple[bytes, str]:
    """Hand-rolled multipart/form-data body — the standard library has no
    built-in equivalent of `requests`' `files=`. The file part is written
    *first*, before `fields`: the server reads whichever multipart field
    arrives first as the SBOM bytes, regardless of that part's own `name`
    (see `upload_sbom`/`verify_sbom` in handlers.rs) — the same reason the
    original bash version always lists `-F "sbom_file=@..."` before every
    other `-F` flag. Sending the fields first would make the server parse
    e.g. the `format` value as the SBOM content."""
    boundary = uuid.uuid4().hex
    parts: list[bytes] = []
    content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{file_field}"; '
        f'filename="{file_path.name}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n".encode()
        + file_path.read_bytes()
        + b"\r\n"
    )
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n".encode()
        )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


# --------------------------------------------------------- tenant lookup --


def resolve_target_url(config: Config) -> str:
    """Pre-flight: confirms MAGNOLIA_API_KEY actually belongs to
    `config.tenant_domain` before making the real upload/verify call, and
    returns the exact URL to call. See the module docstring's "tenant
    lookup" section for why this exists and how the platform-super_admin
    cross-tenant case is handled."""
    status, body = http_get(f"{config.tenant_url}/api/v1/whoami")
    if status != 200:
        die(
            f"could not verify MAGNOLIA_API_KEY (whoami returned HTTP {status}): {body}"
        )
    whoami = json.loads(body)
    key_domain = whoami["domain"]
    base_url = f"{config.tenant_url}/api/v1/{config.mode}"

    if key_domain == config.tenant_domain:
        return base_url
    if not whoami["is_platform_tenant"]:
        die(
            f"tenant mismatch: MAGNOLIA_API_KEY belongs to domain '{key_domain}', "
            f"but tenant_domain is set to '{config.tenant_domain}'.\n"
            f"Use the key that belongs to '{config.tenant_domain}', fix tenant_domain, "
            "or use a platform super_admin key to act cross-tenant."
        )

    status, body = http_get(f"{config.tenant_url}/api/v1/tenants")
    if status != 200:
        die(f"could not list tenants to resolve tenant_domain (HTTP {status}): {body}")
    tenant_id = next(
        (t["id"] for t in json.loads(body) if t["domain"] == config.tenant_domain),
        None,
    )
    if tenant_id is None:
        die(f"tenant_domain '{config.tenant_domain}' not found via GET /api/v1/tenants")
    return f"{base_url}?tenant_id={tenant_id}"


# ------------------------------------------------------------- commands --


def run_upload(config: Config, target_url: str) -> int:
    print(
        f"==> uploading {config.sbom} to {config.tenant_url}{config.namespace} "
        f"@ {config.version} ({config.format}) [tenant_domain={config.tenant_domain}]",
        file=sys.stderr,
    )
    status, body = http_post_multipart(
        target_url,
        {
            "format": config.format,
            "namespace": config.namespace,
            "version": config.version,
        },
        "sbom_file",
        config.sbom,
    )
    if status != 200:
        die(f"upload failed (HTTP {status}): {body}")
    print(body)
    return 0


def run_verify(config: Config, target_url: str) -> int:
    print(
        f"==> verifying {config.sbom} against {config.tenant_url} ({config.format}) "
        f"[tenant_domain={config.tenant_domain}]",
        file=sys.stderr,
    )
    status, body = http_post_multipart(
        target_url, {"format": config.format}, "sbom_file", config.sbom
    )
    if status != 200:
        die(f"verify request failed (HTTP {status}): {body}")

    if config.json_output:
        print(body)
        return 0 if json.loads(body)["verdict"] == "pass" else 1

    result = json.loads(body)
    for check in result["checks"]:
        if config.verbose:
            print(
                f"[{check['status']:^13}] {check['id']} (enforce_level={check['enforce_level']})"
            )
            for detail in check["details"]:
                print(f"    - {detail}")
        elif check["status"] == "fail":
            print(f"{check['id']} failed")
    print(f"verdict: {result['verdict']}")
    return 0 if result["verdict"] == "pass" else 1


# ------------------------------------------------------------------ cli --


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="magnolia-upload.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["upload", "verify"],
        default="upload",
        help="upload (default) or verify",
    )
    parser.add_argument("--tenant-url", help="e.g. https://acme.magnolia.example")
    parser.add_argument("--tenant-domain", help="REQUIRED -- target tenant's domain")
    parser.add_argument("--namespace", help="e.g. /product/v1 (upload only)")
    parser.add_argument("--sbom", help="path to the SBOM file to upload/verify")
    parser.add_argument("--format", help=f"cyclonedx|spdx (default: {DEFAULT_FORMAT})")
    parser.add_argument("--version", help="free-text release label (upload only)")
    parser.add_argument(
        "--file", help="path to the Magnoliafile (default: search upward from cwd)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="verify only: print the raw /verify JSON response on stdout instead of "
        'the human-readable summary (still exits non-zero on a "fail" verdict)',
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="verify only, human-readable mode: print every check's full status, "
        "not just failing ones",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = build_config(args)
    target_url = resolve_target_url(config)
    if config.mode == "upload":
        return run_upload(config, target_url)
    return run_verify(config, target_url)


if __name__ == "__main__":
    sys.exit(main())
