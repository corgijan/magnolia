# Deliverables

Every course deliverable, linked to where it is. Status: ✅ done ·
⚠️ partly done · ❌ missing. Details: [README.md](README.md).

## Start here

| | |
|---|---|
| Project overview | [README.md](README.md) |
| Architecture and data flow | [ARCHITECTURE.md](ARCHITECTURE.md) · [README → 4](README.md#4-architecture-and-data-flow) |
| AI component | [reach/README.md](reach/README.md) · [README → 8](README.md#8-the-ai-component) |
| Presentation | [slides/talk.md](slides/talk.md) (Marp source) · [slides/talk.html](slides/talk.html) |
| Demo walkthrough | [README → 3, Demo data](README.md#3-the-implemented-core-scenario) · [demo/shop-api/](demo/shop-api/) · [scripts/demo-repo.sh](scripts/demo-repo.sh) |

## Application

| Requirement | Status | Where |
|---|---|---|
| Problem and responsibility | ✅ | [README → 1](README.md#1-problem-and-responsibility) |
| Core user scenarios | ✅ | [README → 2](README.md#2-core-user-scenarios), [3](README.md#3-the-implemented-core-scenario) |
| Application logic beyond LLM calls | ✅ | [crates/](crates/) (log, proofs, DSSE, policies, VEX, compliance) |
| Persistence (PostgreSQL + `reach` SQLite) | ✅ | [README → 5](README.md#5-persistence) · [migrations/](migrations/) |
| Web UI (React) | ✅ | [README → 6](README.md#6-user-interface) · [frontend/](frontend/) |
| REST API | ✅ | [README → 7](README.md#7-api-and-integration-points) · [docs/API.md](docs/API.md) |
| OpenAPI spec: `reach` | ✅ | generated, `GET /openapi.json`, Swagger UI at `/docs` ([reach/README.md](reach/README.md#running-it)) |
| OpenAPI spec: Magnolia API |  ✅ | only the hand-written [docs/API.md](docs/API.md) |
| Health endpoint | ✅ | `GET /health` on both services |
| Configuration via env vars | ✅ | [README → 10](README.md#10-configuration) · [.env.example](.env.example) |
| Docker / Compose | ✅ | [Dockerfile](Dockerfile) · [frontend/Dockerfile](frontend/Dockerfile) · [reach/Dockerfile](reach/Dockerfile) · [docker-compose.yml](docker-compose.yml) · [scripts/stack-up.sh](scripts/stack-up.sh) |
| Build, test and start instructions | ✅ | [README → 11](README.md#11-build-test-and-start) · [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Audit logging | ✅ | [README → 5](README.md#5-persistence) (audit log table, Audit Log view) |

## AI component

| Requirement | Status | Where |
|---|---|---|
| Feature: CVE reachability evidence | ✅ | [reach/](reach/) · [README → 8](README.md#8-the-ai-component) |
| OpenAI-compatible API only, configured by env | ✅ | [reach/src/ai/](reach/src/ai/) · [README → 10](README.md#10-configuration) |
| Local model and inference server |  ✅  | [README → 9](README.md#9-local-model-and-inference-server) (`qwen3.8:27b` on Ollama) |
| Failure handling (unavailable, timeout, invalid output, processing) | ✅ | [README → Failure handling](README.md#failure-handling) |
| Evidence not verdict; labels not probabilities | ✅ | [README → Evidence, not a verdict](README.md#evidence-not-a-verdict-uncertainty) |
| Responsible design (privacy, security, misuse) | ✅ | [README → 13](README.md#13-responsible-design) |

## Evaluation

| Requirement | Status | Where |
|---|---|---|
| ≥ 10 cases (incl. ambiguous, injection, malformed, out-of-scope) | ✅ 13 | [reach/eval/cases/](reach/eval/cases/) · [reach/eval/fixtures/](reach/eval/fixtures/) |
| Reproducible script | ✅ | `cd reach && cargo run --bin eval` · [reach/eval/README.md](reach/eval/README.md) |
| Aggregated metrics + non-AI baseline | ✅ | [README → Evaluation](README.md#evaluation) |
| Results as artifacts | ✅ | [reach/eval/results/](reach/eval/results/) |

## Tests

| Requirement | Status | Where |
|---|---|---|
| Unit tests: workspace | ✅ 192 | `cargo test --workspace` |
| Unit tests: `reach` | ✅ 227 | `cd reach && cargo test` |
| Tests over real data | ✅ | [tests/test_real_sboms.py](tests/test_real_sboms.py) · [test-sboms/](test-sboms/) |
| CI running the tests | ✅ | [.github/workflows/ci.yml](.github/workflows/ci.yml): workspace and `reach` tests, baseline eval, frontend build, real-SBOM tests against a live server |

## AI-assisted development

| Requirement | Status | Where |
|---|---|---|
| AI development log (5–8 episodes required) | ✅ 14 | [docs/AI_DEVLOG.md](docs/AI_DEVLOG.md) |
| Sandboxed agent setup | ✅ | [README → 12](README.md#12-sandboxed-agent-setup) |
| Roadmap / status log | ✅ | [ROADMAP.md](ROADMAP.md) |
| Licence | ✅ | [LICENSE](LICENSE) (GPL-3.0-or-later) |

**What the AI development log is.** [docs/AI_DEVLOG.md](docs/AI_DEVLOG.md) records how the
project was built *with* an AI coding agent (Claude Code). It is separate from the product's own AI
component (`reach`). Each episode records: task given, the agent's proposed contribution,
tools/permissions used, verification, accepted/modified/rejected, and observed benefits,
failures and risks. Episodes 1–8 were reconstructed afterwards from session transcripts and
notes (the log says so at the top); episodes 9–14 were written in the same session as the work.
