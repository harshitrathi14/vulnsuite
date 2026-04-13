# 🛡️ VulnSuite

**A BFSI-tuned, multi-tool, risk-prioritized cybersecurity vulnerability analysis platform.**

> Passive-only. Own-assets. Multi-tenant. Air-gap ready. RBI CSF & CERT-In aligned.

---

## 📌 Executive Summary

VulnSuite unifies **eleven industry-standard security scanners** behind a single **risk engine** that prioritizes findings using `CVSS × EPSS × asset criticality × exposure` — transforming tens of thousands of raw CVEs into a **focused P0–P4 queue** a CISO can actually action.

Built for Indian BFSI from day one: **RBI Cyber Security Framework** controls and **CERT-In 6-hour incident reporting** are embedded in every finding, not bolted on later.

---

## 🧭 Architecture

<p align="center">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 360" width="800">
  <style>
    .box{fill:#0a2540;stroke:#0a2540;}
    .box2{fill:#1a4d7a;stroke:#1a4d7a;}
    .box3{fill:#2e86ab;stroke:#2e86ab;}
    .txt{fill:#fff;font-family:Helvetica,Arial;font-size:13px;font-weight:bold;text-anchor:middle;}
    .small{fill:#fff;font-family:Helvetica,Arial;font-size:10px;text-anchor:middle;}
    .arrow{stroke:#555;stroke-width:2;fill:none;marker-end:url(#a);}
  </style>
  <defs><marker id="a" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#555"/></marker></defs>

  <rect class="box" x="20" y="20" width="150" height="60" rx="6"/>
  <text class="txt" x="95" y="45">Collectors (11)</text>
  <text class="small" x="95" y="62">SCA · SAST · Secrets</text>
  <text class="small" x="95" y="75">Net · Cloud · Container</text>

  <rect class="box2" x="220" y="20" width="150" height="60" rx="6"/>
  <text class="txt" x="295" y="45">Orchestrator</text>
  <text class="small" x="295" y="62">parallel · dedup</text>
  <text class="small" x="295" y="75">risk-score · persist</text>

  <rect class="box3" x="420" y="20" width="150" height="60" rx="6"/>
  <text class="txt" x="495" y="45">Risk Engine</text>
  <text class="small" x="495" y="62">CVSS × EPSS × crit</text>
  <text class="small" x="495" y="75">× exposure → P0-P4</text>

  <rect class="box" x="620" y="20" width="150" height="60" rx="6"/>
  <text class="txt" x="695" y="45">PostgreSQL</text>
  <text class="small" x="695" y="62">RLS · multi-tenant</text>
  <text class="small" x="695" y="75">+ DuckDB archive</text>

  <line class="arrow" x1="170" y1="50" x2="220" y2="50"/>
  <line class="arrow" x1="370" y1="50" x2="420" y2="50"/>
  <line class="arrow" x1="570" y1="50" x2="620" y2="50"/>

  <rect class="box2" x="20" y="140" width="150" height="60" rx="6"/>
  <text class="txt" x="95" y="165">FastAPI</text>
  <text class="small" x="95" y="182">OIDC · RBAC · REST</text>

  <rect class="box2" x="220" y="140" width="150" height="60" rx="6"/>
  <text class="txt" x="295" y="165">Celery Workers</text>
  <text class="small" x="295" y="182">scan · discover · report</text>

  <rect class="box2" x="420" y="140" width="150" height="60" rx="6"/>
  <text class="txt" x="495" y="165">Streamlit Dashboard</text>
  <text class="small" x="495" y="182">CISO view · trends</text>

  <rect class="box2" x="620" y="140" width="150" height="60" rx="6"/>
  <text class="txt" x="695" y="165">PDF + CERT-In</text>
  <text class="small" x="695" y="182">board-ready · audit hash</text>

  <rect class="box3" x="120" y="260" width="560" height="60" rx="6"/>
  <text class="txt" x="400" y="285">Compliance Layer</text>
  <text class="small" x="400" y="302">RBI CSF Annex-I · CERT-In 6h · ISO 27001 · NIST · CIS Azure · CIS Docker</text>
</svg>
</p>

---

## 🎯 The Risk Formula

<p align="center">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 720 130" width="720">
  <style>
    .f{font-family:"Courier New",monospace;font-size:20px;fill:#0a2540;font-weight:bold;}
    .l{font-family:Helvetica,Arial;font-size:11px;fill:#555;}
  </style>
  <text class="f" x="360" y="50" text-anchor="middle">risk_score = CVSS × EPSS × (criticality/5) × exposure</text>
  <text class="l" x="120" y="85" text-anchor="middle">0–10</text>
  <text class="l" x="120" y="100" text-anchor="middle">technical</text>
  <text class="l" x="260" y="85" text-anchor="middle">0–1</text>
  <text class="l" x="260" y="100" text-anchor="middle">exploitability</text>
  <text class="l" x="440" y="85" text-anchor="middle">0.2–1.0</text>
  <text class="l" x="440" y="100" text-anchor="middle">business impact</text>
  <text class="l" x="620" y="85" text-anchor="middle">0.3 / 0.6 / 1.0</text>
  <text class="l" x="620" y="100" text-anchor="middle">blast radius</text>
</svg>
</p>

**Buckets:** P0 ≥ 7.0 (CERT-In clock) · P1 ≥ 4.5 · P2 ≥ 2.0 · P3 ≥ 0.5 · P4 otherwise.

---

## 🔬 Scanner Coverage

| Module | Tools | Coverage |
|---|---|---|
| **SCA** | Trivy · pip-audit · OSV-Scanner | NVD + PyPA + OSV.dev, triple-corroborated |
| **Secrets** | gitleaks · TruffleHog | Regex breadth + live credential verification |
| **SAST** | Semgrep · Bandit | Multi-language + Python deep crypto checks |
| **Network** | nmap (passive) · testssl.sh | Service/version + TLS hygiene (RBI Annex-I 6.2) |
| **Cloud** | Prowler Azure | CIS Azure 2.0 + ISO 27001 + NIST 800-53 |
| **Container** | Trivy image · Dockle | Image CVEs + CIS Docker Benchmark hardening |
| **Discovery** | Azure Resource Graph | Auto-inventory with tag-based criticality inference |

---

## 🏛️ Compliance Mapping

Every finding carries a **regulatory citation** in its evidence block:

- **RBI Cyber Security Framework** — Annex-I controls 6.2 (crypto/TLS), 6.3 (patching), 6.4 (hardening), 6.5 (certificates), 6.13 (cloud), 6.14 (SDLC), 6.15 (secrets), 6.16 (database)
- **CERT-In Directions 28 Apr 2022** — auto-generated 6-hour incident report for every P0 finding
- **ISO 27001:2013** — Annex A control mapping via Prowler
- **CIS Benchmarks** — Azure 2.0, Docker
- **NIST 800-53 Rev 5** — via Prowler compliance packs
- **OWASP Top 10** — via Semgrep rule packs

---

## 🏗️ Repository Layout

```
vulnsuite/
├── core/                 # schema, db, risk engine, orchestrator, dedup, EPSS, config
├── collectors/
│   ├── sca/              # trivy, pip_audit, osv_scanner
│   ├── secrets/          # gitleaks, trufflehog
│   ├── sast/             # semgrep, bandit
│   ├── network/          # nmap_passive, testssl
│   ├── cloud/            # prowler_azure
│   ├── container/        # dockle
│   └── discovery/        # azure_inventory
├── api/                  # FastAPI app + OIDC/RBAC
├── workers/              # Celery app + tasks
├── reporting/            # PDF generator (Jinja2 + WeasyPrint)
├── compliance/           # rbi_mapping, certin_export
├── dashboard/            # Streamlit CISO view
├── deploy/               # docker-compose.yml (+ Helm chart TBD)
├── pyproject.toml
└── README.md
```

---

## 🛡️ Security & Privacy by Design

1. **Passive-only mode** — no exploitation, no auth probing, no aggressive timing. Enforced in code (nmap collector refuses `T4`/`T5` at construction time).
2. **Multi-tenant isolation via PostgreSQL Row-Level Security** — a bug in application code cannot leak Tenant A's findings to Tenant B.
3. **Secrets never stored in findings DB** — TruffleHog raw values are explicitly redacted; gitleaks uses `--redact`.
4. **Air-gap support on every network-dependent component** — Trivy offline DB, OSV-Scanner local DB, Semgrep offline rules, EPSS offline CSV.
5. **No telemetry egress** — Semgrep `--metrics off`, Bandit offline, Trivy `--skip-db-update` option.
6. **Audit-stamped PDFs** — every generated report carries an SHA-256 content hash in the footer.
7. **Read-only cloud credentials** — Prowler Azure uses Reader + Security Reader roles only.
8. **OIDC + RBAC** — four roles (admin, analyst, viewer, auditor) with least-privilege route guards.

---

## 🚀 Quick Start

```bash
# Clone and build
git clone <repo> && cd vulnsuite
cp .env.example .env  # then fill in DB/Azure/OIDC secrets

# Bring up the full stack
docker compose -f deploy/docker-compose.yml up -d

# Access
# API:       http://localhost:8000/docs
# Dashboard: http://localhost:8501
```

---

## 📊 Observability

- **Structured JSON logs** via structlog — ship to Splunk/Sentinel/ELK
- **Per-tool scan error capture** — failures aggregate into `RunReport.errors`, never crash the pipeline
- **MTTR & aging metrics** on the Streamlit dashboard
- **DuckDB cold-store archive** for historical trend queries without burdening PostgreSQL

---

## 🗺️ Roadmap

| Phase | Status | Scope |
|---|---|---|
| 1 | ✅ Done | Schema, DB, risk engine, SCA + Secrets + SAST collectors, orchestrator, dedup, EPSS |
| 2 | ✅ Done | Network collectors, PDF reporting |
| 3 | ✅ Done | Cloud + container + discovery collectors, compliance layer |
| 4 | ✅ Done | API, workers, dashboard, docker-compose deployment |
| 5 | 🔜 | Helm chart, Alembic migrations, AWS Prowler, SIEM connectors (Splunk/Sentinel), automated remediation playbooks |

---

## 📜 License

Proprietary — internal BFSI deployment only. Contact the security team for external-use licensing.

**Classification:** CONFIDENTIAL — INTERNAL USE ONLY
