# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

The project is a Python 3.11+ package declared in `pyproject.toml` (setuptools build backend, ruff + black + mypy + pytest configured).

```bash
# Install (editable with dev extras)
pip install -e ".[dev]"

# Lint / format / type-check
ruff check .
black .
mypy vulnsuite

# Tests (pytest is configured with --cov=vulnsuite by default)
pytest
pytest tests/path/to/test_file.py::test_name      # single test
pytest -m "not integration and not azure"          # skip tests needing binaries/cloud
pytest -m integration                              # only tests that require scanner binaries
pytest -m azure                                    # only tests that require Azure creds

# Full-stack dev run (Postgres, Redis, API, worker, beat, dashboard)
docker compose -f deploy/docker-compose.yml up -d
#   API:       http://localhost:8000/docs
#   Dashboard: http://localhost:8501

# Run components individually (after `pip install -e .`)
uvicorn vulnsuite.api.main:app --reload --port 8000
celery -A vulnsuite.workers.celery_app worker --loglevel=INFO \
  --queues=vulnsuite.default,vulnsuite.scan,vulnsuite.discovery,vulnsuite.report
celery -A vulnsuite.workers.celery_app beat --loglevel=INFO
streamlit run vulnsuite/dashboard/streamlit_app.py
```

`deploy/Dockerfile` is a two-stage build: stage 1 pulls every pinned scanner binary; stage 2 layers `python:3.12-slim`, system libs (Pango/Cairo for WeasyPrint, OpenJDK for ZAP), CLI clients (kubectl, helm, bicep, aws, gcloud), and pip-installed scanners (semgrep, bandit, pip-audit, prowler, checkov). The same image runs API/worker/beat/dashboard — compose `command:` selects the role. Bumping a scanner version is a security-review event: edit the `ARG <TOOL>_VERSION` lines and rebuild.

## Architecture — big picture

The suite is a **pipeline** with one integration seam (`core/orchestrator.py`) and one data contract (`core/schema.py`). Everything else hangs off those two files.

### Data contract (read `core/schema.py` first)
All collectors emit `ScanResult` envelopes containing `Finding` objects. `Finding` is the canonical shape — tool-specific fields go inside `evidence` (free-form dict), never as new top-level fields. Enums: `Severity`, `Module` (sca/sast/secrets/network/cloud/container/discovery), `AssetType`, `ExposureFactor` (0.3/0.6/1.0). `Asset.criticality` is 1–5, business-assigned.

### Pipeline (orchestrator → dedup → risk → post-process → persist)
`Orchestrator.run(asset, collector_calls, post_processors=...)` in `core/orchestrator.py` is the integration point:
1. Fan-out with `asyncio.Semaphore(max_parallel_collectors)` (default 4) and a per-collector timeout (default 1800s). A crashing/timing-out collector is logged and dropped — it never fails the run.
2. Aggregate raw findings; bubble per-tool errors into `RunReport.errors`.
3. **Cross-tool dedup** via `core/dedup.py`. Keying rules are module-specific (see the docstring at the top of `dedup.py`); Phase 2 added keys for `iac` (check_id + file + resource), `kubernetes` (control + namespace + kind + name), `asm` (host + port + scheme + fingerprint), `api_security` (rule + method + url), and `supply_chain` (cve | rule_id | component, scoped by purl/digest). Losing tools are appended to `evidence.raw.corroborated_by` — do not drop that trail; auditors use it.
4. **Risk enrichment** happens before post-processors, so scoring reflects the merged view. Formula in `core/risk_engine.py`: `CVSS × EPSS × (criticality/5) × exposure`, bucketed `P0 ≥ 7.0` (triggers the CERT-In 6-hour clock) / `P1 ≥ 4.5` / `P2 ≥ 2.0` / `P3 ≥ 0.5` / else `P4`. Missing CVSS falls back to a severity-derived value; missing EPSS uses `cfg.epss_floor` (0.05).
5. **Post-processors** run last (currently used by `VEXProcessor.apply` to downgrade VEX-suppressed findings to INFO/P4). They are the right place for tenant-policy overrides, exception lists, and risk-acceptance treatments — *not* the collector layer.
6. Persist through `tenant_session(tenant_id)` in `core/db.py`.

Collectors are plug-ins satisfying `async scan(...) -> ScanResult`. They are constructed and wrapped into zero-arg coroutines *in the worker layer* (`workers/tasks.py::scan_asset`) — the orchestrator stays ignorant of collector signatures. Add a new collector by (a) implementing `scan()` under `collectors/<module>/`, (b) wiring it into `scan_asset`, (c) adding any new target field to `ScanTargets` in `core/schema.py`, and (d) extending `dedup.py` keying only if the new module isn't already covered.

### Module catalogue (12 modules, ~22 tools)
`core/schema.py::Module` enumerates: `sca`, `sast`, `secrets`, `network`, `cloud`, `container`, `discovery`, `iac`, `kubernetes`, `asm`, `api_security`, `supply_chain`. AssetTypes follow: `repo`/`host`/`image`/`cloud_resource`/`cloud_account`/`endpoint`/`database`/`domain`/`kubernetes_cluster`/`artifact`. Adding a Module requires a matching dedup rule and an RBI mapping entry in `compliance/rbi_mapping.py::map_finding`.

### ScanTargets is the typed scan-request surface
`core/schema.py::ScanTargets` is the single Pydantic model that defines what a scan can target. The API binds JSON request bodies to it; the worker re-validates server-side and `validate_dast_targets` enforces DAST allowlist + active-scan opt-in *both* in the API and in the Celery task (defense-in-depth — a bypassed API check still gets caught at worker time). When adding a target type: extend `ScanTargets`, the validator if relationship rules apply (e.g. `dast_mode` requires `api_base_urls`), and the relevant worker branch.

### Phase 2 collector wiring contract (workers/tasks.py)
Several Phase 2 collectors emit findings with one tool's natural module that need re-tagging:
- Trivy image scans driven by the K8s inventory pass are re-labelled to `Module.KUBERNETES` via `_rewrite_result_module(result, Module.KUBERNETES, {...cluster/namespace/kind/name})` so cluster + image findings group under the workload.
- TestSSL/Nmap runs initiated from ASM subdomain enumeration are re-labelled to `Module.ASM` with `asm_source: "subfinder"`.
- SBOM-mode Trivy (`TrivyCollector().scan(path, "sbom", ...)`) is naturally `Module.SUPPLY_CHAIN` (handled inside Trivy's `_module_for_kind`).
Preserve this pattern — the dashboard, PDF compliance snapshot, and CERT-In export all key off `module`, so a misclassified finding silently disappears from the right view.

### Discovery → upsert pattern
Every discovery collector returns `list[Asset]` with a stable identity tag (`azure_id`, `aws_arn`, `gcp_full_name`, `cluster`, `domain`, `artifact_digest`). `core/db.py::upsert_assets` keys on `(asset_type, external_id, name)` so re-running discovery is idempotent and won't multiply assets across runs. Discovery tasks (`discover_aws_assets`, `discover_gcp_assets`, `discover_domains`, `discover_kubernetes_clusters`, `discover_assets` for Azure) are individual Celery tasks routable to the `vulnsuite.discovery` queue.

### Multi-tenancy is enforced in Postgres, not Python
`core/db.py` defines `AssetRow` and `FindingRow` with RLS policies keyed on `current_setting('app.tenant_id')::uuid`. Every DB interaction MUST go through `tenant_session(tenant_id)`, which runs `SET LOCAL app.tenant_id` before yielding the session. An app-code bug cannot leak across tenants because the DB kernel does the filtering. Preserve this: don't open raw sessions or bypass `tenant_session`.

### Async/sync seam
Collectors, orchestrator, DB, and FastAPI are async (SQLAlchemy 2.0 async + asyncpg). Streamlit and Celery are sync — `workers/tasks.py::_run_async` bridges them. The dashboard uses `psycopg2-binary` (sync) against the same Postgres.

### Config and secrets
`core/config.py` is the single Pydantic Settings root (`VULNSUITE_*` env vars, `.env` file supported). `get_settings()` is `lru_cache`'d — treat it as a singleton. `settings.validate_production()` gates startup in FastAPI; respect it. In prod, secrets come from Azure Key Vault via managed identity and are injected as env vars by an init container — never bake them into images.

### Air-gap / offline mode is a first-class concern
`ScanningSettings.offline_mode` plus `offline_*_db` / `offline_epss_csv` / `offline_semgrep_rules` paths propagate to each collector's offline flag. When touching a collector: preserve the offline path, keep `--metrics off`-style telemetry disables in place (Semgrep), and don't assume outbound network. Phase 2 wiring respects this by emitting `_skip_call` (a stub `ScanResult` with `errors=["not run: <reason>"]`) rather than failing the run when offline mode disables a collector — kubescape, subfinder, httpx, ZAP, and nuclei all guard this way. For Cosign in air-gap, configure `VULNSUITE_SUPPLYCHAIN_COSIGN_PUBLIC_KEY_PATH` so the policy falls back to key-based verification.

### Passive-only enforcement (and the DAST exception)
Aggressive scan flags (nmap `T4`/`T5`, SYN scan, vuln scripts, OS fingerprinting) are rejected at collector `__init__`, not config. Secrets collectors must never persist raw secret values to the findings DB (gitleaks uses `--redact`; TruffleHog values are stripped before emit).

DAST (ZAP active scan, nuclei) is the only intentionally-active surface and is *triple-gated*: (1) `ScanTargets.dast_mode` must be set to `baseline` or `active`; (2) every `api_base_urls` host must match `VULNSUITE_APISEC_DAST_ALLOWLIST` (suffix match on FQDN); (3) `dast_mode=active` additionally requires `VULNSUITE_APISEC_ALLOW_ACTIVE_SCAN=true`. The check runs both in `api/main.py::trigger_scan` and inside `workers/tasks.py::scan_asset` — never collapse this to a single check, defense-in-depth is the point.

### Services (deploy/docker-compose.yml)
`postgres` (16, RLS) · `redis` (7, Celery broker + EPSS L2 cache) · `api` (FastAPI uvicorn) · `worker` (Celery, 4 queues: default/scan/discovery/report; mounts `reports:` and `offline-db:` volumes; 8GB RAM, 4 CPU) · `beat` (nightly Azure discovery per `celery_app.py::beat_schedule`) · `dashboard` (Streamlit). Task routing by queue is declared in `workers/celery_app.py`.

### Compliance layer
`compliance/rbi_mapping.py` annotates findings with RBI CSF Annex-I clauses (6.2 crypto, 6.3 patching, 6.4 hardening, 6.5 certs, 6.13 cloud, 6.14 SDLC, 6.15 secrets, 6.16 DB). `compliance/certin_export.py` auto-emits a JSON incident report for every P0 finding. `reporting/pdf_report.py` uses Jinja2 + WeasyPrint and stamps every PDF with a SHA-256 content hash in the footer — keep that footer; it's the tamper-evidence contract.

## Conventions to preserve

- Collector failures aggregate into `ScanResult.errors` / `RunReport.errors`; never raise out of a collector's `scan()`.
- Tool-specific data goes in `Evidence` (has `extra="allow"`), not new `Finding` fields.
- Severity floors matter: gitleaks findings never below HIGH; TruffleHog verified-live hits auto-escalate to CRITICAL (triggers CERT-In language).
- `use_enum_values=True` is set on `Finding`/`Asset`; serialization produces string enums. Dedup/compare on string values.
- Ruff ignores `S603`/`S607` intentionally — collectors invoke scanner binaries via `subprocess` on purpose.
