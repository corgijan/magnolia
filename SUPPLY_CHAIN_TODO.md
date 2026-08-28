# Supply-chain-monitoring gaps — what's left

## Done this round

- VEX hardening (constrained justification codes + comment, OpenVEX export endpoint,
  two-way dtrack analysis sync) — see `VEX_TODO.md`.
- SBOM diffing between manifest versions — `GET /api/v1/manifest/:manifest_hash/diff`
  (optional `?against=<hash>`, defaults to the previous manifest in the same
  namespace). Reuses the `sbom_components` index built at upload time; identity for
  matching across versions is `purl` (version stripped) or component name. Surfaced
  in the SBOM detail view as a collapsible "Component changes" panel.

## Left to do, in no particular order

- **Continuous vuln/CVE monitoring & alerting** — findings only update when the sync
  loop runs or someone opens the SBOM/Findings tab; no push notification when a *new*
  CVE lands against something already archived.
- **Build provenance / SLSA attestations** — verifying *how* an artifact was built
  (source repo, builder identity, reproducibility), not just that its SBOM was signed
  after upload. The right primitives already exist (DSSE envelopes, in-toto statement
  types in `magnolia-core`) — not yet wired to ingest/verify provenance attestations
  themselves.
- **Malicious/typosquat package detection** — flagging packages that look like known
  supply-chain attacks (dependency confusion, compromised maintainer takeover), a
  different signal than CVE-matching or compliance checks.
- **Package reputation scoring** — e.g. OpenSSF Scorecard-style signals (maintainer
  count, publish recency, funding) layered onto components in `sbom_components`.
- **Remediation workflows** — auto-opening a PR/ticket for a vulnerable dependency
  instead of only surfacing the finding for a human to act on.
- **Notification integrations** — Slack/email/webhook on new findings or failed
  compliance checks, instead of pull-only via the UI/API.
