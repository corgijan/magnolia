#!/usr/bin/env python3
"""Runs every real-world SBOM in test-sboms/ through the real CLI
(scripts/magnolia-upload.py) against a live Magnolia instance's
POST /api/v1/verify — the same dry-run policy gate a CI pipeline would
call, exercising the actual schema validator, compliance profiles, and
license-policy evaluation against genuine, syft-generated dependency
graphs instead of hand-crafted fixtures. See test-sboms/README.md for how
those files were produced.

Nothing here is a fake/mocked implementation of the verify logic — every
assertion is against the JSON a real server actually returned to a real
CLI invocation, so this only passes if the whole path (CLI → HTTP →
schema/compliance/license checks) genuinely works end to end.

Requires a running Magnolia instance. Configure via environment variables
(all optional, default to a fresh local `docker compose up` setup):
    MAGNOLIA_TEST_URL            default: http://127.0.0.1:3000
    MAGNOLIA_TEST_TENANT_DOMAIN  default: test.example
    MAGNOLIA_TEST_API_KEY        REQUIRED — a `mag_...` key for the target
                                  tenant; tests skip if it isn't set
    MAGNOLIA_TEST_SBOM_DIR       default: test-sboms/ next to this repo

Run:
    python3 tests/test_real_sboms.py
    python3 -m unittest tests.test_real_sboms -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
UPLOAD_SCRIPT = REPO_ROOT / "scripts" / "magnolia-upload.py"

TENANT_URL = os.environ.get("MAGNOLIA_TEST_URL", "http://127.0.0.1:3000")
TENANT_DOMAIN = os.environ.get("MAGNOLIA_TEST_TENANT_DOMAIN", "test.example")
# No default: there is no well-known bootstrap key any more (see
# .env.example), so this must be supplied explicitly. Tests skip rather
# than fail when it's absent -- an unconfigured environment isn't a
# regression.
API_KEY = os.environ.get("MAGNOLIA_TEST_API_KEY", "")
SBOM_DIR = Path(os.environ.get("MAGNOLIA_TEST_SBOM_DIR", REPO_ROOT / "test-sboms"))

VALID_CHECK_STATUSES = {"pass", "fail", "warn", "not_evaluated"}


def detect_format(path: Path) -> str:
    """SPDX fixtures are named `*spdx*.json`, everything else here is
    CycloneDX — matches test-sboms/'s own naming convention (see its
    README), not a general-purpose sniffer."""
    return "spdx" if "spdx" in path.name.lower() else "cyclonedx"


def discover_sboms() -> list[Path]:
    if not SBOM_DIR.is_dir():
        return []
    return sorted(SBOM_DIR.glob("*.json"))


class RealSbomVerifyTests(unittest.TestCase):
    """One `subTest` per file per assertion, rather than one dynamically
    generated test method per file: keeps this readable as a fixed set of
    properties every real SBOM must satisfy, while `unittest` still reports
    exactly which file(s) failed which property."""

    @classmethod
    def setUpClass(cls) -> None:
        if not API_KEY:
            raise unittest.SkipTest(
                "MAGNOLIA_TEST_API_KEY is not set — export the key from your .env "
                "(BOOTSTRAP_SUPER_ADMIN_KEY) or any key for the target tenant"
            )
        cls.sboms = discover_sboms()
        if not cls.sboms:
            raise unittest.SkipTest(
                f"no SBOMs found in {SBOM_DIR} — see test-sboms/README.md"
            )

    def test_schema_validation_accepts_every_real_sbom(self) -> None:
        """Schema acceptance is the one thing that must never fail for a
        well-formed, spec-compliant document a real generator produced —
        unlike compliance/license/malicious-package findings, which can
        legitimately warn or fail depending on tenant policy."""
        for sbom in self.sboms:
            with self.subTest(sbom=sbom.name):
                result = self._verify(sbom)
                schema = self._check(result, "schema")
                self.assertEqual(
                    schema["status"],
                    "pass",
                    f"{sbom.name}: schema check failed: {schema['details']}",
                )

    def test_response_is_well_formed_for_every_real_sbom(self) -> None:
        """Structural sanity on /verify's response shape, independent of
        what any individual check concludes."""
        for sbom in self.sboms:
            with self.subTest(sbom=sbom.name):
                result = self._verify(sbom)
                self.assertIn(result["verdict"], ("pass", "fail"))
                self.assertIsInstance(result["checks"], list)
                self.assertGreater(
                    len(result["checks"]), 0, f"{sbom.name}: no checks returned"
                )
                for check in result["checks"]:
                    self.assertIn(check["status"], VALID_CHECK_STATUSES)
                    self.assertIsInstance(check["details"], list)

    def test_compliance_profiles_evaluate_every_real_sbom(self) -> None:
        """Both bundled compliance profiles (BSI TR-03183-2, NTIA minimum
        elements) apply to both formats, so `compliance` should never come
        back empty for these fixtures — an empty list here would mean
        component/profile extraction silently broke for this generator's
        output shape."""
        for sbom in self.sboms:
            with self.subTest(sbom=sbom.name):
                result = self._verify(sbom)
                self.assertGreater(
                    len(result.get("compliance", [])),
                    0,
                    f"{sbom.name}: no compliance profiles evaluated",
                )

    # -- helpers ----------------------------------------------------------

    def _verify(self, sbom: Path) -> dict:
        proc = subprocess.run(
            [
                sys.executable,
                str(UPLOAD_SCRIPT),
                "verify",
                "--tenant-url",
                TENANT_URL,
                "--tenant-domain",
                TENANT_DOMAIN,
                "--sbom",
                str(sbom),
                "--format",
                detect_format(sbom),
                "--json",
            ],
            env={**os.environ, "MAGNOLIA_API_KEY": API_KEY},
            capture_output=True,
            text=True,
            timeout=120,
        )
        # 0 (verdict pass) and 1 (verdict fail) are both legitimate outcomes
        # of a real check — only anything else means the CLI itself broke.
        self.assertIn(
            proc.returncode,
            (0, 1),
            f"{sbom.name}: magnolia-upload.py exited {proc.returncode} unexpectedly: {proc.stderr}",
        )
        lines = proc.stdout.strip().splitlines()
        self.assertTrue(
            lines, f"{sbom.name}: no stdout from verify --json (stderr: {proc.stderr})"
        )
        return json.loads(lines[-1])

    def _check(self, result: dict, check_id: str) -> dict:
        for check in result["checks"]:
            if check["id"] == check_id:
                return check
        self.fail(f"no '{check_id}' check in response: {json.dumps(result)[:500]}")


if __name__ == "__main__":
    unittest.main()
