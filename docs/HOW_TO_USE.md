# VulnSuite 0.4 — How to Use (Process Document)

**Classification:** CONFIDENTIAL — INTERNAL USE ONLY
**Audience:** CISO office, Security Operations, Platform / DevOps, Internal Audit
**Release:** 0.4 hardening build, package date 2026-10-19
**Scope:** Vulnerability-assessment platform (API, workers, scheduler, database). The server-protection module has its own guides, listed in section 10.

---

## 1. What is in the package

The zip contains the complete, current source tree. Nothing needs to be downloaded from a code repository.

| Folder / file | What it is |
|---|---|
| `vulnsuite/` | Application code: `core/` (schema, risk engine, database, triage, scopes, cloud bindings), `api/` (FastAPI service, OIDC auth, audit trail), `workers/` (Celery tasks and scheduler), `collectors/` (22 scanner integrations), `ai/`, `compliance/`, `reporting/`, `protection/`, `dashboard/` |
| `vulnsuite/deploy/` | `Dockerfile`, `docker-compose.yml`, `auth.env.example`, `checksums.sha256` (pinned scanner downloads), `postgres/` (role bootstrap and migration SQL), helper scripts |
| `tests/` | Automated test suite (unit, security boundary and deployment checks) |
| `vulnsuite/README.md` | Executive summary, architecture, scanner coverage, compliance mapping |
| `vulnsuite/FEATURES.md` | Feature and module catalogue |
| `vulnsuite/CLAUDE.md` | Engineering manual: pipeline, conventions, every security control and where it is enforced |
| `vulnsuite/deploy/AUTH_DEPLOYMENT.md` | Identity, database roles and existing-database migration guide |
| `vulnsuite/protection/README.md`, `OPERATIONS.md`, `deploy/protection/` | Server intrusion monitoring and response module (separate service) |
| `docs/HOW_TO_USE.md` | This document |

The executive briefing deck is shared separately as an attachment and is not part of this zip.

Integrity: a `.sha256` file is supplied next to the zip. Verify before use:

```bash
sha256sum -c VulnSuite_v0.4_hardening_2026-10-19.zip.sha256
```

---

## 2. Prerequisites

| Item | Requirement |
|---|---|
| Host | Linux x86-64 (amd64). The scanner binaries are pinned for linux/amd64 only. |
| Container runtime | Docker Engine 24+ with Docker Compose v2 (`docker compose`) |
| Sizing | Worker service is limited to 4 CPU / 8 GB RAM in Compose. Plan 6 CPU / 12 GB for the whole stack. |
| Identity provider | An OIDC provider (Entra ID, Keycloak, Okta, etc.) that issues RS256 access tokens with a tenant claim (UUID) and a roles claim |
| Network at build time | Outbound HTTPS to GitHub releases, PyPI, dl.k8s.io, get.helm.sh, awscli.amazonaws.com and dl.google.com. Every download is checksum-verified. |
| Network at run time | Outbound HTTPS for vulnerability databases and EPSS, unless air-gap mode is configured (section 8.4) |
| Ingress | HTTPS reverse proxy in front of port 8000 (nginx, Traefik, Azure App Gateway). The API itself serves plain HTTP. |
| For running tests locally | Python 3.11 or 3.12 |

---

## 3. Installation process (fresh deployment)

All commands run from the `vulnsuite/` directory inside the unzipped package, the one that contains `pyproject.toml` and `deploy/`.

**Step 1. Unpack and verify**

```bash
sha256sum -c VulnSuite_v0.4_hardening_2026-10-19.zip.sha256
unzip VulnSuite_v0.4_hardening_2026-10-19.zip
cd VulnSuite/vulnsuite
```

**Step 2. Create the private environment file** (outside the source tree, mode 600)

```bash
mkdir -p "$HOME/.config/vulnsuite"
install -m 600 deploy/auth.env.example "$HOME/.config/vulnsuite/compose.env"
```

Fill in the file. Generate every password separately with `openssl rand -hex 32`.

| Variable | Required | Purpose |
|---|---|---|
| `DB_PASSWORD` | Yes | Runtime database role `vulnsuite_app` (DML only). 32–128 chars, letters/digits/`_`/`-`. |
| `DB_MIGRATOR_PASSWORD` | Yes | Schema-owner role `vulnsuite_migrator`, used only by the API at start-up to create tables and policies |
| `POSTGRES_BOOTSTRAP_PASSWORD` | Yes | PostgreSQL bootstrap superuser. Stays inside the database container. Must differ from the other two. |
| `REDIS_PASSWORD` | Yes | Redis broker and cache authentication |
| `OIDC_ISSUER` | Yes | Exact HTTPS issuer URL of the identity provider |
| `OIDC_JWKS_URL` | Yes | HTTPS JWKS endpoint used to verify token signatures |
| `OIDC_AUDIENCE` | No (default `vulnsuite-api`) | Expected `aud` claim |
| `OIDC_TENANT_CLAIM`, `OIDC_ROLES_CLAIM` | No (defaults `tenant_id`, `roles`) | Claim names carrying the tenant UUID and application roles |
| `API_CORS_ORIGINS` | No (default `[]`) | JSON list of browser origins allowed to call the API, e.g. `["https://console.example.com"]`. The wildcard `*` is rejected. |
| `SCHEDULED_DISCOVERY_TENANTS` | No (default `[]`) | JSON list of tenant UUIDs for the nightly Azure discovery job |
| `DAST_ALLOWLIST`, `DAST_ALLOW_ACTIVE` | No (off) | Opt-in gates for dynamic API testing (section 6.4) |
| `ASM_ALLOW_NMAP` | No (`false`) | Allow nmap validation during attack-surface discovery |
| `AZURE_*`, `AWS_*`, `GCP_PROJECT_ID`, `KUBECONFIG_HOST_PATH`, `GCP_CREDS_HOST_PATH` | No | Ambient cloud credentials for discovery. Tenant scans use per-tenant bindings instead (section 6.2). |
| `COSIGN_IDENTITY`, `COSIGN_OIDC_ISSUER` | No | Supply-chain signature policy for artifact verification |

**Step 3. Validate the configuration without printing secrets**

```bash
docker compose --env-file "$HOME/.config/vulnsuite/compose.env" \
  -f deploy/docker-compose.yml config --quiet
```

Compose stops with a clear message if any required variable is missing.

**Step 4. Build and start**

```bash
docker compose --env-file "$HOME/.config/vulnsuite/compose.env" \
  -f deploy/docker-compose.yml up -d --build
```

The first build downloads and verifies 18 pinned scanner binaries plus Python dependencies and takes 15–30 minutes. A checksum mismatch aborts the build. This is intended and must be investigated, not bypassed.

**Step 5. Confirm health**

```bash
docker compose -f deploy/docker-compose.yml ps
curl -fsS http://localhost:8000/healthz
```

Expected: `postgres`, `redis`, `api`, `worker`, `beat` all `healthy` or `running`; the health endpoint returns `{"status": "ok", ...}`. Interactive API documentation is at `http://localhost:8000/docs`.

**Step 6. Put HTTPS ingress in front of port 8000.** Browser login and MFA belong to the identity provider.

### 3.1 Upgrading an existing database

Start-up creates new tables but never adds columns to existing ones and cannot change table ownership. If a database from an earlier VulnSuite release exists:

1. Take and verify a backup.
2. Run `deploy/postgres/migrations/0001_triage_columns_and_schema_owner.sql` as the bootstrap superuser. Read the commented sections in the file first; the role-creation statements must be uncommented with the real migrator password.
3. Follow "Existing PostgreSQL volumes" in `deploy/AUTH_DEPLOYMENT.md` for role and ownership checks.
4. Only then start the new API.

---

## 4. Access model

Every API call carries two headers:

```http
Authorization: Bearer <access token from the identity provider>
X-Tenant-Id: <tenant UUID, must equal the token's tenant claim>
```

An optional `X-Request-Id` is honoured and always echoed back, so calls can be correlated with the audit trail.

| Role | Can do |
|---|---|
| `admin` | Everything below, plus bind cloud accounts, authorise scopes, run discovery, delete bindings |
| `analyst` | Register assets, trigger scans, triage findings, request reports, read everything except audit events |
| `auditor` | Read findings, cloud bindings, scopes and the audit trail; request reports. No changes. |
| `viewer` | Read assets and findings, use the copilot |

Roles come from the identity provider's roles claim. There are no local users or passwords in VulnSuite.

Tenant isolation is enforced by PostgreSQL Row-Level Security on every table, bound to the tenant in the verified token. Application code cannot read or write another tenant's rows even if it tries.

---

## 5. One-time tenant setup (admin)

**5.1 Register assets.** Each scan target is an asset with a business criticality (1–5) and an exposure factor: `1.0` internet-facing, `0.6` internal, `0.3` isolated. Both feed the risk score.

```bash
curl -X POST https://vulnsuite.example/api/v1/assets \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $TENANT" \
  -H "Content-Type: application/json" \
  -d '{"name":"payments-api","asset_type":"repo","criticality":5,"exposure":1.0,"owner":"payments-team"}'
```

**5.2 Bind cloud accounts.** Cloud scans never run on the worker's own identity. Bind each account to the tenant with a credential *reference*. Secrets are rejected by the API.

| Provider | Reference fields |
|---|---|
| AWS | `role_arn` (read-only role in the target account) and `external_id` |
| GCP | `credentials_file` (service-account JSON path mounted into the worker) |
| Azure | `secret_env_prefix`; the worker reads `<PREFIX>_AZURE_CLIENT_ID`, `_CLIENT_SECRET`, `_TENANT_ID` from its environment |

```bash
curl -X POST https://vulnsuite.example/api/v1/cloud-accounts ... \
  -d '{"provider":"aws","account_id":"123456789012","display_name":"Prod",
       "credentials":{"role_arn":"arn:aws:iam::123456789012:role/VulnSuiteReadOnly","external_id":"..."}}'
```

**5.3 Authorise public scopes.** Private address space can always be scanned. A public IP, CIDR, or hostname that resolves to a public address is scanned only inside a scope the admin has approved. This is the ownership attestation.

```bash
curl -X POST https://vulnsuite.example/api/v1/scopes ... \
  -d '{"kind":"domain","value":"example-bank.in","note":"Owned; approved by CISO 2026-10-19"}'
curl -X POST https://vulnsuite.example/api/v1/scopes ... \
  -d '{"kind":"network","value":"203.0.113.0/24","note":"DMZ range"}'
```

List with `GET /api/v1/cloud-accounts` and `GET /api/v1/scopes`; remove with `DELETE .../{id}`.

---

## 6. Day-to-day operating process

### 6.1 Trigger a scan (analyst or admin)

```bash
curl -X POST https://vulnsuite.example/api/v1/scans ... \
  -d '{"asset_id":"<asset uuid>",
       "targets":{"repo":"/var/lib/vulnsuite/workspace/payments-api","image":"registry.example/payments:1.4.2"}}'
```

Target fields: `repo`, `image`, `host`, `tls_endpoint`, `azure`, `iac_paths`, `terraform_plan_paths`, `helm_chart_paths`, `kube_context`, `kubeconfig_path`, `root_domains`, `api_specs`, `api_base_urls`, `sbom_paths`, `vex_paths`, `artifacts`, `aws_accounts`, `gcp_projects`, `dast_mode`.

The request is accepted (HTTP 202) and runs on the worker. It is refused when:

| Response | Reason |
|---|---|
| 400 | No targets, malformed target (shell characters, leading `-`, bad hostname), or DAST requested without the allowlist |
| 403 | Cloud account not bound to this tenant, or a public host outside an authorised scope |
| 404 | Asset not found in this tenant |

The same checks run again inside the worker, so a bypassed API check still fails closed.

### 6.2 Cloud and discovery

- `POST /api/v1/discover/azure`, `/aws`, `/gcp`, `/domains`, `/kubernetes` (admin) inventory assets and upsert them idempotently.
- The `beat` scheduler runs Azure discovery nightly for the tenants listed in `SCHEDULED_DISCOVERY_TENANTS`.
- Cloud scans run once per bound account, each under that account's credentials only.

### 6.3 Review findings

```bash
GET /api/v1/findings?bucket=P0&status=open&limit=100
GET /api/v1/findings/new          # first seen in the latest scan
GET /api/v1/findings/summary      # counts by bucket and module
```

Risk score = CVSS × EPSS × (criticality / 5) × exposure. Buckets:

| Bucket | Score | Meaning |
|---|---|---|
| P0 | ≥ 7.0 | Starts the CERT-In 6-hour reporting clock; a CERT-In incident JSON is generated automatically |
| P1 | ≥ 4.5 | Fix in the current sprint |
| P2 | ≥ 2.0 | Planned remediation |
| P3 | ≥ 0.5 | Backlog |
| P4 | below | Informational / VEX-suppressed |

Each finding records the tools that corroborated it, the RBI Cyber Security Framework clause, and optional AI advisory signals (false-positive likelihood, known-exploited status, suggested bucket). AI signals never change the deterministic score.

### 6.4 Dynamic API testing (DAST) is off by default

Three gates must all pass: `dast_mode` set to `baseline` or `active` in the request, every `api_base_urls` host inside `DAST_ALLOWLIST`, and for `active` additionally `DAST_ALLOW_ACTIVE=true`. Everything else in VulnSuite is passive.

### 6.5 Triage workflow (analyst or admin)

```bash
PATCH /api/v1/findings/{finding_id}
{"status":"accepted","note":"Compensating control: WAF rule 4471 blocks the vector","owner":"payments-team","accepted_until":"2027-01-31T00:00:00+05:30"}
```

| Status | Who sets it | Rules |
|---|---|---|
| `open` | scanner / analyst | Default |
| `triaged` | analyst | Reviewed, owner assigned |
| `accepted` | analyst | Needs a justification of at least 10 characters and an `accepted_until` date no more than 365 days ahead. Reopened automatically, with a note, when it expires. |
| `false_positive` | analyst | Needs a justification of at least 10 characters. Never auto-closed or reopened by re-scans. |
| `fixed` | scanner only | Set when a tool that previously reported the finding completes without it |

A finding is auto-closed only when the tool that reported it ran successfully and no longer reports it. A tool that crashed or timed out never closes anything.

### 6.6 Reports

`POST /api/v1/reports` (admin, analyst, auditor) queues a PDF report for the tenant. Every PDF carries a SHA-256 content hash in its footer; store that hash with the report for tamper evidence.

### 6.7 Audit trail (admin, auditor)

Every authenticated API call is recorded: who (subject, email, roles), tenant, method, path, status, outcome (`success`, `denied`, `rejected`, `error`), client IP, request id, duration, and handler detail such as the targets requested or the triage change made.

```bash
GET /api/v1/audit-events?outcome=denied&limit=200
GET /api/v1/audit-events?actor=<subject>
```

Rows cannot be updated or deleted: the runtime database role has only insert and select on the table and a trigger rejects rewrites. Set `VULNSUITE_AUDIT_INCLUDE_READS=false` to record only changes.

### 6.8 Copilot (optional)

`POST /api/v1/copilot/query` with `{"question": "..."}` answers questions over the tenant's findings using Claude. It is advisory and disabled automatically when no API key is configured.

---

## 7. Verification and testing process

### 7.1 Automated test suite

Run from the top folder of the package (the one containing `vulnsuite/` and `tests/`):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install "./vulnsuite[dev]"        # installs runtime and test dependencies
python -m pytest tests -q -m "not integration and not azure"
```

The tests import the `vulnsuite` package from the current directory, so run them from the top folder. Expected result for this package: all tests pass (442 passed, 7 skipped at packaging time on 2026-10-19; the skips are tests that need scanner binaries or cloud credentials).

| Suite | What it proves |
|---|---|
| `tests/security/test_tenant_database.py` | Tenant binding on every transaction, forced row-level security on all five tables, audit immutability trigger, runtime role gets DML only, bad role names rejected |
| `tests/security/test_auth.py` | OIDC token validation, role checks, tenant header binding |
| `tests/test_scan_targets_hardening.py` | Every scan target field rejects shell-unsafe input; paths confined to the workspace |
| `tests/test_cloud_accounts.py` | Secrets rejected in bindings, unbound accounts refused, ambient credentials stripped |
| `tests/test_tenant_scopes.py` | Public hosts refused outside scope, hostnames resolved before the check, ASM roots filtered |
| `tests/test_audit_trail.py` | One row per call, outcomes classified, request id echoed, failed audit never fails the request |
| `tests/test_triage.py` | Justification and expiry rules, expired acceptance reopens, analyst statuses survive re-scans |
| `tests/test_scan_lifecycle.py` | EPSS prefetch, auto-close only on successful tool runs |
| `tests/test_deploy_hardening.py` | Every download pinned, no `curl | sh`, no `latest`, non-root runtime, Redis password, separate schema owner, explicit CORS |
| `tests/test_worker_wiring.py` | Every Celery queue routed in code is consumed by the Compose worker |
| `tests/protection/` | Server-protection module |

### 7.2 Staging acceptance checklist (manual, before production)

1. Fresh-volume start-up completes and `/healthz` is OK.
2. With two tokens from two different tenants, confirm each sees only its own assets and findings, and that a mismatched `X-Tenant-Id` is rejected.
3. Trigger a scan of a public hostname without a scope: expect 403 and a `denied` audit row.
4. Add the scope, re-run: expect 202, findings appear, audit row `success` with the targets listed.
5. Trigger a cloud scan with no binding: expect 403. Bind the account, re-run.
6. Accept a finding with `accepted_until` in the past: expect 400. Accept with a valid date, re-scan, confirm it stays accepted.
7. As `auditor`, attempt a triage call: expect 403.
8. Query `psql` as `vulnsuite_app` and attempt `DELETE FROM audit_events`: expect permission denied.
9. Generate a report and verify the SHA-256 in the footer matches the file content hash.

---

## 8. Maintenance process

### 8.1 Updating a scanner version (security-review event)

1. Edit the `ARG <TOOL>_VERSION` line in `deploy/Dockerfile`.
2. Run `deploy/pin-checksums.sh`. It prefers the publisher's checksum file and marks the line `published`; where none exists it hashes the download and marks it `computed`.
3. Review the diff of `deploy/checksums.sha256` like any dependency change, then rebuild.
4. `tests/test_deploy_hardening.py` fails the build if any download lacks a pin.

### 8.2 Python dependency lock

Run `deploy/lock-deps.sh` (needs `pip-tools`) to produce `requirements.lock` with hashes. When present, the image installs with `--require-hashes`. This file is not included in the package and should be generated on the build host.

### 8.3 Credential rotation

Database and Redis passwords: rotate in the identity store, update the private env file, restart the affected services. Changing Compose variables does not rotate passwords inside an existing PostgreSQL volume; use `ALTER ROLE ... PASSWORD` as described in `deploy/AUTH_DEPLOYMENT.md`.

### 8.4 Air-gap mode

Set `VULNSUITE_SCAN_OFFLINE_MODE=true` and mount offline databases into the `offline-db` volume (Trivy DB, OSV DB, Semgrep rules, EPSS CSV). Collectors that cannot run offline are skipped and reported in the run's error list instead of failing the scan. For artifact signature verification offline, set `VULNSUITE_SUPPLYCHAIN_COSIGN_PUBLIC_KEY_PATH`.

### 8.5 Backups

Back up the `pgdata` volume (findings, assets, bindings, scopes, audit events) and the `reports` volume. Redis holds only queue state and cache and can be rebuilt.

---

## 9. Security controls summary

| Control | Where enforced |
|---|---|
| OIDC bearer tokens, RS256, audience and lifetime checks, four least-privilege roles | `api/auth.py` |
| Tenant isolation by PostgreSQL forced Row-Level Security on assets, findings, cloud bindings, scopes, audit events | `core/db.py`, verified in `tests/security/` |
| Separate schema-owner and runtime database roles; runtime role cannot alter policies or audit rows | `deploy/postgres/10-application-role.sh`, `core/db.py` |
| Immutable audit trail of every authenticated API call | `api/audit.py`, database trigger |
| Scan targets validated for format and shell safety; paths confined to a workspace root | `core/targets.py`, `workers/tasks.py` |
| Public targets require an admin-approved scope; hostnames resolved before the check | `core/scopes.py`, checked in API and worker |
| Cloud scans run only under tenant-bound, reference-only credentials; ambient credentials stripped | `core/cloud_accounts.py`, checked in API and worker |
| Passive-only scanning; DAST triple-gated and off by default | collector constructors, `validate_dast_targets` |
| Analyst triage with justification and expiry; expired acceptances reopen | `core/triage.py` |
| Auto-close only after a successful run of the reporting tool | `core/db.py::reconcile_findings` |
| Secrets never stored in findings (gitleaks `--redact`, TruffleHog values stripped) | secrets collectors |
| Every scanner binary SHA-256 pinned and verified at build; non-root container; no `latest` tags; no pipe-to-shell | `deploy/Dockerfile`, `fetch-verified.sh`, `checksums.sha256` |
| Redis authenticated; CORS explicit, wildcard rejected | `docker-compose.yml`, `core/config.py` |
| Tamper-evident PDF reports (SHA-256 footer); CERT-In 6-hour incident JSON for every P0 | `reporting/`, `compliance/` |
| No telemetry egress from scanners; full offline mode | collector flags, `ScanningSettings` |

---

## 10. Known limitations and open items

- Validation of the deployment files is static. The container image build, a live PostgreSQL start-up with both roles, and the identity-provider integration have not been exercised in this packaging run and must be done in staging (section 7.2).
- `requirements.lock` must be generated on the build host (section 8.2) before the hash-verified install takes effect.
- Trivy and ZAP were moved to versions 0.76.0 and 2.17.0 because the earlier releases are no longer published. Review these bumps.
- The Streamlit dashboard is a legacy, localhost-only profile with manual tenant selection. The supported operator UI is the protection service's authenticated console.
- The `vulnsuite` command-line entry point is a placeholder; use the API.
- The audit trail is tamper-resistant at the database-role level, not cryptographically chained.
- Only linux/amd64 scanner binaries are pinned.

## 11. Related documents in this package

| Document | Use it for |
|---|---|
| `vulnsuite/README.md` | Executive overview, scanner coverage, compliance mapping |
| `vulnsuite/FEATURES.md` | Feature-by-feature catalogue for audit |
| `vulnsuite/CLAUDE.md` | Engineering reference for every control and convention |
| `vulnsuite/deploy/AUTH_DEPLOYMENT.md` | Identity and database setup, existing-volume migration |
| `vulnsuite/deploy/postgres/migrations/0001_*.sql` | Upgrade SQL for existing databases |
| `vulnsuite/protection/README.md`, `OPERATIONS.md` | Server protection module deployment and operations |
| `deploy/protection/windows/README.md`, `ISOLATION.md`, `QUARANTINE.md` | Windows response setup and recovery |
