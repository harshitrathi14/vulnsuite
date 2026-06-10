# VulnSuite — Features & Module Catalogue

**Classification:** CONFIDENTIAL — INTERNAL USE ONLY
**Audience:** CISO, Security Architecture, Internal Audit, Compliance

---

## 1. Platform Features

| Feature | Description |
|---|---|
| **Multi-tool corroboration** | 11 scanners across 6 modules; findings cross-verified and merged via the dedup engine so auditors see "3 independent tools agree" rather than 3× noise. |
| **Risk-prioritized output** | `CVSS × EPSS × criticality × exposure` formula collapses 20,000+ raw criticals into an actionable P0–P4 queue. |
| **Multi-tenant SaaS-ready** | PostgreSQL Row-Level Security enforces tenant isolation at the DB kernel, not in app code. |
| **Air-gap mode** | Every network-dependent component has an offline fallback (Trivy DB, OSV DB, Semgrep rules, EPSS CSV). |
| **Passive-only enforcement** | Aggressive scan modes are rejected at object construction, not runtime. |
| **Compliance-native** | RBI CSF, CERT-In, ISO 27001, CIS, NIST, OWASP citations ride inside every finding. |
| **Board-ready PDF reports** | Jinja2 + WeasyPrint, SHA-256 content hash for tamper evidence, classification banner. |
| **Automated CERT-In incident export** | JSON packet ready for upload to incident@cert-in.org.in on every P0. |
| **CISO dashboard** | Streamlit view with P0–P4 KPI strip, CERT-In countdown, module/tool/compliance tabs. |
| **Async orchestration** | Celery workers run up to 4 collectors per asset in parallel with timeout discipline. |
| **Structured logging** | structlog JSON output; ships directly to Splunk / Sentinel / ELK. |
| **Audit trail** | All API actions, scans, and reports retain operator, timestamp, and tenant for CERT-In 180-day retention. |

---

## 2. Module Catalogue

### 2.1 SCA — Software Composition Analysis
Finds CVEs in third-party libraries across languages.

- **Trivy** — broad multi-ecosystem scanner; NVD-first CVSS; container + filesystem; 15-min hard timeout; offline DB support.
- **pip-audit** — PyPA Advisory DB specialist for Python; consumes requirements.txt, pyproject.toml, or live venv; promotes unpatched CVEs to HIGH.
- **OSV-Scanner** — Google's multi-language scanner querying OSV.dev (often fresher than NVD for npm, Maven, crates.io, Go); walks nested advisory events to extract fix versions.

**Value:** triple-corroboration pattern explicitly sought by BFSI auditors; dedup keyed on `(asset, cve, pkg, version)` keeps the dashboard clean.

### 2.2 Secrets Scanning
Detects hardcoded credentials and leaked API keys.

- **gitleaks** — regex-based, redact-by-default, captures commit and author for blame workflow; severity never below HIGH.
- **TruffleHog** — live credential verification against AWS/GCP/Azure/Slack/Stripe/GitHub; verified-live hits auto-escalate to CRITICAL and trigger CERT-In incident reporting language in the remediation text.

**Value:** combines regex breadth with active verification — the industry-standard pairing. Raw secret values are never persisted to the findings DB.

### 2.3 SAST — Static Application Security Testing
Scans source code for insecure patterns.

- **Semgrep** — multi-language; `p/default`, `p/security-audit`, `p/owasp-top-ten`, `p/secrets` rule packs; `--metrics off` mandatory for BFSI; promotes HIGH+HIGH (impact+confidence) to CRITICAL.
- **Bandit** — Python-specific AST-driven linter; 3×3 severity×confidence matrix; curated remediation for 10 BFSI-critical checks (MD5, DES, ECB, `verify=False`, old TLS, `yaml.load`, `shell=True`, SQL concat).

**Value:** generic SAST + Python-specialist; maps cleanly to RBI CSF 6.14 (SDLC).

### 2.4 Network (Passive)
Maps exposed services and TLS hygiene without exploitation.

- **nmap (passive)** — `-sT -sV` only, no SYN, no vuln scripts, no OS fingerprinting, T2 "polite" timing ceiling; refuses public CIDRs unless explicitly opted in; BFSI-tuned severity table flags Telnet/FTP/rsh/RDP/MongoDB/Redis.
- **testssl.sh** — TLS protocol, cipher, certificate, HSTS, and vulnerability checks; every finding carries a direct **RBI-CSF Annex-I** clause citation (6.2 crypto, 6.3 patching, 6.4 hardening, 6.5 certificates); curated remediation for each family (legacy protocols, weak ciphers, Heartbleed/POODLE/ROBOT, cert expiry).

**Value:** the only layer where regulatory citations are embedded directly at the collector level.

### 2.5 Cloud Posture — Azure-First
CSPM checks against Azure subscriptions.

- **Prowler Azure** — read-only service principal (Reader + Security Reader); CIS Azure 2.0 + ISO 27001 + NIST 800-53 frameworks enabled by default; OCSF JSON output; only failing checks become findings.

**Value:** aligned to your Azure-first BFSI stack; credentials mandated to come from Azure Key Vault via managed identity.

### 2.6 Container Hardening
Image configuration and CIS Docker Benchmark checks.

- **Dockle** — CIS Docker Benchmark compliance; curated remediation for the 10 most common violations (non-root USER, pinned tags, Content Trust, HEALTHCHECK, setuid bits, COPY vs ADD, runtime secrets, `--privileged`).

**Value:** complements Trivy's CVE scanning with hardening checks; together they cover the full container attack surface.

### 2.7 Asset Discovery
Auto-inventories cloud resources into VulnSuite `Asset` objects.

- **Azure Resource Graph** — KQL queries across all accessible subscriptions; `DefaultAzureCredential` chain; infers criticality from `environment`/`tier` tags (prod → 5, staging → 3, dev → 1); flags public-facing resource types (PublicIP, AppGateway, FrontDoor, CDN, WebApp, APIM) as exposure = INTERNET.
- **AWS CLI inventory** — describes ELBv2 load balancers and Elastic IPs; `internet-facing` LBs and any EIP get exposure = INTERNET; tags carry `aws_arn` for stable identity in `db.upsert_assets`.
- **gcloud asset search** — `gcloud asset search-all-resources --scope projects/<id>`; ForwardingRule / Cloud Run / API Gateway / Address resources flagged INTERNET; tags carry `gcp_full_name`.
- **Subfinder (passive)** — multi-source subdomain enumeration capped per root by `VULNSUITE_ASM_MAX_SUBDOMAINS_PER_ROOT`; emits `Asset(asset_type=DOMAIN)`.
- **kubectl contexts** — every kubeconfig context becomes an `Asset(asset_type=KUBERNETES_CLUSTER)`.

**Value:** closes the "what do we own?" gap — the RBI CSF 6.1 control — across all four hosting domains (Azure, AWS, GCP, Kubernetes) plus the public-facing domain surface.

### 2.8 IaC — Infrastructure-as-Code
Catches misconfigurations before they ship to production.

- **Checkov** — Terraform (incl. plan JSON), Bicep, Helm, raw Kubernetes manifests, Kustomize, OpenAPI; `--download-external-modules false` by default for air-gap safety; ~1500 policies covering CIS, NIST, PCI-DSS, SOC 2, ISO.
- **Trivy config** — corroborating misconfiguration scanner with AVD-ID-keyed dedup; pairs with Checkov so every IaC misconfig has cross-tool agreement.

**Value:** RBI CSF 6.4 (secure configuration) and 6.14 (SDLC) shift left — the CISO sees an IaC misconfiguration at the PR stage, not after it lands in production.

### 2.9 Kubernetes Posture & Runtime Image Coverage
Closes the gap between cluster posture and the workloads actually running there.

- **Kubescape** — NSA + CIS Kubernetes benchmarks; live-cluster mode with namespace exclusions (`kube-system` etc. by default); per-control YAML evidence for auditors.
- **Kubernetes inventory** — `kubectl get deploy,statefulset,daemonset,pod -A -o json` extracts every container image actually running; each image is fed back through Trivy under `Module.KUBERNETES` so cluster + image findings live on the same asset.

**Value:** RBI CSF 6.13 (cloud) + 6.3 (patching) for the container runtime — and "what's actually running" matches "what we scanned" because the inventory pass drives the scan plan.

### 2.10 External Attack-Surface Management
Continuously maps what the internet sees of you.

- **Subfinder** — passive sources only (Censys, VirusTotal, AlienVault, etc.) so no probing traffic leaves the perimeter; respects per-root cap; outputs feed both ASM enrichment and asset discovery.
- **httpx** — fingerprints discovered hosts (status, title, web server, tech stack, TLS); HTTP-only services on standard ports auto-escalate to MEDIUM (BFSI baseline forbids cleartext for production endpoints).
- **TestSSL + nmap (passive, opt-in)** — every discovered host is run through TestSSL automatically; nmap validation is opt-in via `VULNSUITE_ASM_ALLOW_NMAP_VALIDATION=true` because public scans need a vetted target list.

**Value:** the "shadow IT" RBI CSF 6.1 + 6.2 coverage — discovers internet-exposed assets the inventory might miss, enriches them with TLS posture, and ties everything back to a `DOMAIN` asset.

### 2.11 API Security & Gated DAST
Tests live API surfaces against attack patterns — gated by allowlist so production is never accidentally hit.

- **Nuclei** — community + custom YAML templates; severity floor configurable (default `medium`); CVE-tagged hits inherit EPSS so the risk engine treats them as proper exploits.
- **OWASP ZAP Automation Framework** — driven by an in-process YAML plan: ingest OpenAPI specs, spider, passive wait, then optionally active scan; report templated as JSON for normalization.
- **Two-layer DAST gating** — `dast_mode` (off / baseline / active), `VULNSUITE_APISEC_DAST_ALLOWLIST` (only matching FQDNs are allowed), and `VULNSUITE_APISEC_ALLOW_ACTIVE_SCAN` (active mode requires explicit opt-in). Validation happens both at API request time and inside the Celery task — a misconfigured tenant cannot bypass it.

**Value:** RBI CSF 6.14 with active testing without the BFSI nightmare of an outsourced scanner accidentally hitting prod — by design the system fails closed.

### 2.12 Supply Chain — SBOM, Provenance, Signed Artifacts
Pulls dependency identity, exploitability stance, and build trust into one pipeline.

- **Syft** — generates CycloneDX SBOMs from images/filesystems and ingests pre-existing SBOMs; flags components missing PURL or version (incomplete identity ⇒ unverifiable provenance).
- **Trivy SBOM scan** — every emitted SBOM is re-scanned in `sbom` mode under `Module.SUPPLY_CHAIN`, so SBOM dependency CVEs corroborate filesystem SCA findings on the same asset.
- **Cosign** — three verification modes auto-selected: keyless (Sigstore/Fulcio identity + OIDC issuer policy), key-based (offline air-gap PEM), and `verify-attestation` for SLSA provenance / SBOM / VEX predicates. Missing required attestation is HIGH (RBI CSF 6.14).
- **VEX (CycloneDX VEX + OpenVEX)** — auto-detects format per file; `not_affected` / `resolved` / `fixed` statements downgrade matched findings to INFO/P4 *after* risk scoring (post-processor pass), with the original VEX state preserved on the finding evidence for audit.

**Value:** auditors get the full chain — "this dependency is in our SBOM, the artifact is signed by our build pipeline, the provenance attestation matches, and where we accept residual risk it's documented as a VEX statement, not a forgotten ticket."

### 2.13 Cloud Posture — AWS + GCP Parity
Phase 1 was Azure-first; Phase 2 brings the other two hyperscalers up to feature parity.

- **Prowler AWS** — CIS AWS 1.5 + NIST 800-53 Rev 5 by default; account scoping via `--aws-account-id` (without scoping, prowler walks the entire org).
- **Prowler GCP** — read-only project scan via `--project-ids`; OCSF JSON output normalizes alongside Azure/AWS into the same `Module.CLOUD` finding shape, so the dashboard and PDF treat all three uniformly.

**Value:** multi-cloud BFSI tenants get a single risk view across hyperscalers, with the same RBI CSF 6.13 mapping logic and CERT-In treatment regardless of cloud.

---

## 3. Integration & Operations

| Component | Technology | Role |
|---|---|---|
| API | FastAPI + OIDC/JWT + RBAC | REST surface; 4 roles; tenant-scoped routes |
| Workers | Celery (Redis broker) | Async scan, discover, report; 4 queues |
| Scheduler | Celery Beat | Nightly Azure discovery |
| Store | PostgreSQL 16 + RLS | Multi-tenant findings + assets |
| Cache | Redis 7 | EPSS L2 cache, Celery broker |
| Reports | Jinja2 + WeasyPrint | Offline PDF generation |
| Dashboard | Streamlit + pandas | CISO view |
| Deployment | Docker Compose (Helm TBD) | 6-service stack |

---

## 4. What Makes VulnSuite Different

1. **BFSI-native, not BFSI-bolted-on.** RBI CSF clauses and CERT-In timing are first-class data model concerns, not post-processing.
2. **Multi-tool by design.** Three SCA tools, two secrets scanners, two SAST tools — the belt-and-braces pattern auditors explicitly look for.
3. **Passive is enforced in code.** Aggressive timing flags are rejected at `__init__`, not config.
4. **Air-gap is a first-class mode**, not a retrofit — every online dependency has a documented offline path.
5. **Risk math over severity math.** CVSS alone produces 20k criticals; CVSS × EPSS × business context produces ~50 actionable P0s.
6. **Findings are actionable, not just alerts.** Curated, library-specific remediation text ships with every finding from Bandit, Dockle, testssl, and TruffleHog.

---

## 5. Phase 3 — AI Enrichment (Claude Fable 5)

Every capability is **advisory and additive**: AI verdicts ride inside
`evidence.raw["ai_*"]`; deterministic scores, buckets, and statuses stay
authoritative. The layer is **off by default** (`VULNSUITE_AI_ENABLED=true`
to opt in) and force-disabled in air-gap mode regardless of flags.

| Capability | Module | What it does |
|---|---|---|
| AI Triage | `ai/triage.py` | Per-finding false-positive likelihood, calibrated confidence, evidence-based exploitability. Batches API (50% price) above 50 findings. |
| Remediation Plans | `ai/remediate.py` | Concrete steps + patch diffs + validation commands for P0/P1 findings. |
| Attack-Chain Correlation | `ai/correlate.py` | Feeds the asset's full finding set into one high-effort call; surfaces multi-finding attack paths the independent risk formula cannot see. |
| RBI CSF Mapping | `ai/compliance.py` | Control mapping with per-control rationale; deterministic heuristic remains the fallback. |
| Report Narratives | `ai/narrate.py` | Board-level executive briefing in the PDF; CERT-In incident draft (human sign-off gate unchanged). |
| Security Copilot | `ai/copilot.py` + `POST /api/v1/copilot/query` | Natural-language questions over findings via read-only, RLS-scoped query tools — the model never writes SQL. |
| Dedup Assist | `ai/dedup_assist.py` | Merge *suggestions* for unkeyed modules (network/cloud/discovery); never auto-merges. Opt-in. |
| Live Threat Intel | `ai/threat_intel.py` | Web-grounded exploitation status for P0/P1 CVEs — CISA KEV, in-the-wild reports, public PoCs — via Fable 5 server-side web search with dynamic filtering. Only CVE IDs leave the boundary. |

**Guardrails (non-configurable):**
- `ai/redaction.py` masks secret material (AWS keys, PEM blocks, JWTs,
  tokens, URL credentials, password assignments) before any byte leaves
  the boundary; SECRETS-module evidence is force-masked.
- Every request is tenant-tagged; tenants are never mixed in one call.
- Every stage degrades to a no-op on failure — findings always flow.

**Pipeline:** `scan_asset` → persist → enqueue `ai_enrich_findings`
(queue `vulnsuite.ai`) → triage → **threat intel** → remediate → correlate
(coverage-first finder at `effort: max` with a 64K task budget, then an
**adversarial verifier** that refutes weak chains) → map → suggest →
evidence updates written back under RLS.

**Fable 5 capabilities in use:** adaptive thinking; `effort` tiers up to
`max`; task budgets (beta) on the deep correlation call; structured
outputs everywhere; Batches API at 50% price; prompt-cached frozen
system prompts; server-side `web_search`/`web_fetch` with dynamic
filtering (threat intel + copilot, which searches CVE IDs and product
names only — never tenant data).
