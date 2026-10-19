"""Build the introductory CISO briefing materials from structured content.

Run from this repository root: python3 build_updated_collateral.py [output_dir]
Writes VulnSuite_Executive_Deck_FINAL.pptx, VulnSuite_Executive_Deck_Review.pdf,
VulnSuite_Intro_Email.txt/.html and vulnsuite/ciso_email.txt. The deck and the
email describe the complete platform as a first introduction.
"""
import sys
from html import escape
from pathlib import Path

from PIL import ImageFont
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_AUTO_SIZE
from pptx.oxml.xmlchemy import OxmlElement
from pptx.util import Inches, Pt
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent
NAVY, ORANGE, INK, MUTED, PANEL = '0A2540', 'F38020', '334155', '64748B', 'F3F6FA'
FONT = 'DejaVu Sans'
FONT_FILE = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
BOLD_FILE = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
DATE = '19 October 2026'
TESTS = '442 automated tests passed'

# (title, kicker, (left heading, bullets), (right heading, bullets), footnote)
SLIDES = [
('VulnSuite', 'VULNERABILITY ASSESSMENT + SERVER PROTECTION + SECURITY OPERATIONS',
 ('What the suite does', ['Finds vulnerabilities across code, cloud, containers, hosts and APIs', 'Scores and prioritises them by business risk', 'Monitors Linux and Windows servers for intrusion', 'Coordinates investigation and approved response']),
 ('How it is governed', ['Identity-provider login, four least-privilege roles', 'Tenant isolation enforced inside PostgreSQL', 'Immutable audit trail of every API action', 'Passive by default; scans need explicit authorisation']),
 'Introducing VulnSuite | Built for Indian BFSI: RBI Cyber Security Framework and CERT-In obligations are embedded in every finding.'),
('What the suite addresses', 'SECURITY OUTCOMES',
 ('Reduce exposure', ['Find vulnerable software and unsafe configurations', 'Assess exposed services, APIs, TLS and cloud posture', 'Turn thousands of raw CVEs into a short P0–P4 queue', 'Track remediation, acceptance and false positives']),
 ('Investigate and respond', ['Connect host alerts with vulnerability findings', 'Assign incidents, review evidence and track action', 'Approve bounded containment and inspect receipts', 'Answer auditors from one evidence trail']),
 'Selected detection signals support investigation; coverage is not equivalent to a complete EDR platform.'),
('Platform coverage', '12 ASSESSMENT MODULES, 22 TOOLS, 2 HOST PLATFORMS',
 ('Assessment modules', ['SCA, secrets and static code analysis', 'Network, cloud, containers and asset discovery', 'IaC, Kubernetes and external attack surface', 'API testing and software supply-chain checks']),
 ('Protection and operations', ['Linux audit and Windows event adapters', 'Access, process, malware and integrity signals', 'SOC console, investigations and agent lifecycle', 'Signed notifications and approved response plans']),
 'Assessment and protection services retain separate persistence and deployment boundaries.'),
('Risk prioritisation and compliance', 'CVSS × EPSS × CRITICALITY × EXPOSURE',
 ('One score, five buckets', ['Every finding scored on exploit likelihood and asset context', 'P0 ≥ 7.0 starts the CERT-In six-hour clock automatically', 'Cross-tool corroboration recorded for auditors', 'AI advisory signals never alter the deterministic score']),
 ('Regulatory mapping', ['RBI CSF Annex-I clause cited on each finding', 'CERT-In incident JSON generated for every P0', 'CIS, ISO 27001, NIST 800-53 and OWASP via scanner packs', 'Tamper-evident PDF reports with SHA-256 footer']),
 'Missing CVSS falls back to severity; missing EPSS uses a configured floor so nothing is silently dropped.'),
('Software and supply-chain risk', 'APPLICATION SECURITY',
 ('Code and dependencies', ['Trivy, pip-audit and OSV-Scanner collectors', 'Semgrep and Bandit static analysis', 'Gitleaks and TruffleHog secret detection, values redacted', 'Checkov and Trivy infrastructure-as-code checks']),
 ('Build and artifact evidence', ['Syft software bill of materials', 'Cosign signature and SLSA attestation checks', 'VEX statements applied as documented downgrades', 'Air-gap verification with a pinned public key']),
 'Coverage depends on configured targets, installed tools and available advisory data.'),
('Infrastructure and API assessment', 'EXPOSURE MANAGEMENT',
 ('Infrastructure', ['Passive nmap service discovery, aggressive modes refused', 'testssl.sh TLS hygiene checks', 'Kubescape cluster posture and runtime image scans', 'Dockle container hardening checks']),
 ('Applications and APIs', ['Nuclei and OWASP ZAP assessment collectors', 'Dynamic testing off by default, three independent gates', 'External discovery with Subfinder and httpx', 'Enumerated hosts filtered to authorised domains']),
 'Assessment scans complement host monitoring and inline WAF enforcement.'),
('Cloud posture and discovery', 'AZURE + AWS + GCP',
 ('Posture and inventory', ['Prowler Azure, AWS and GCP configuration benchmarks', 'Azure Resource Graph, AWS and gcloud asset discovery', 'Kubernetes context enumeration and domain discovery', 'Nightly scheduled discovery per tenant']),
 ('Credential discipline', ['Each cloud account bound to one tenant by an admin', 'Bindings hold references only; secrets are rejected', 'Collectors run under the bound account, ambient keys stripped', 'Unbound accounts fail closed, never widen scope']),
 'Read-only cloud roles are expected; VulnSuite never requests write permissions in the target accounts.'),
('Scan authorisation and target safety', 'OWN-ASSETS ONLY',
 ('Who may scan what', ['Private address space scannable by definition', 'Public hosts need an admin-approved domain or network scope', 'Hostnames resolved before the check, no literal-only bypass', 'Rules enforced in the API and again in the worker']),
 ('Safe inputs', ['Every target field validated for format and shell safety', 'Repository paths confined to a workspace root', 'Scanner binaries receive targets after an explicit separator', 'Rejected requests recorded as denied in the audit trail']),
 'A bypassed API check is still caught at worker time; defence in depth is deliberate.'),
('Verified identity and tenant isolation', 'SSO TOKEN VERIFICATION + ROW-LEVEL SECURITY',
 ('Authentication and roles', ['Verify token signature, issuer, audience and expiry', 'Require signed tenant and explicit role claims', 'Admin, analyst, auditor and viewer rights', 'Sign-in and MFA follow identity-provider policy']),
 ('Database boundaries', ['Forced row-level security on all five tenant tables', 'Tenant bound to every transaction from the token', 'Schema owner separated from the runtime database role', 'Runtime role cannot alter policies or audit rows']),
 'JWT verification and RLS controls are implemented; live IdP integration and database-role enforcement need staging.'),
('Audit trail and analyst triage', 'ACCOUNTABILITY',
 ('Immutable API audit trail', ['Actor, tenant, action, outcome and client IP per call', 'Request IDs echoed back for log correlation', 'Handler detail: targets requested, triage changes made', 'Insert-only table guarded by a database trigger']),
 ('Triage workflow', ['Open, triaged, accepted and false-positive states', 'Justification required for acceptance and false positive', 'Acceptances expire within 365 days and reopen automatically', 'Re-scans never silently close analyst-owned findings']),
 'A finding is auto-closed only when the tool that reported it completed cleanly and no longer reports it.'),
('Unified operations console', 'ALERTS + FINDINGS + AGENTS',
 ('Shared investigation view', ['View intrusion alerts and vulnerability findings', 'Inspect agent health, sensor status and version drift', 'Create and assign incidents from selected alerts', 'Review response plans before approval']),
 ('Operational safeguards', ['Apply the same API role checks to console actions', 'Keep access tokens in browser-tab memory', 'Report unavailable upstream sources explicitly', 'Retrieve findings through a fixed HTTPS connector']),
 'The console shows bounded recent lists; it is not an exhaustive cross-platform evidence search.'),
('Windows and Linux monitoring', 'WINDOWS EVENTS + LINUX AUDIT',
 ('Windows monitoring', ['Security log authentication and network logons', 'RDP and SMB evidence where source events support it', 'Sysmon process-creation records', 'Selected fields without raw command-line capture']),
 ('Linux monitoring', ['Event-driven audit execution records', 'Linux /proc process polling', 'SSH access, API denials and file-integrity signals', 'Sensor health and missing-telemetry indicators']),
 'Windows and Linux support monitoring and approved containment. Native enforcement and recovery require staging validation.'),
('Process and malware detection', 'SELECTED HOST SIGNALS',
 ('Suspicious activity', ['Recognised web-server parent spawning a shell', 'Execution from writable temporary locations', 'Deleted executable signals on Linux', 'Event records for short-lived processes']),
 ('Malware evidence', ['Known-bad SHA256 matches on selected targets', 'Optional Linux selected-file ClamAV scans', 'Path, signature and hash retained for review', 'Unavailable scanners surface degraded coverage']),
 'Coverage excludes complete memory scanning and full-disk protection. File quarantine does not terminate a running process.'),
('Lateral-movement signals', 'CROSS-HOST CORRELATION',
 ('Correlated patterns', ['Password spraying across multiple hosts', 'Same-user successful-login fan-out', 'Suspected pivots from already flagged hosts', 'Remote-access evidence from supported event sources']),
 ('Investigation context', ['Administrator-defined host-to-IP ownership', 'Time-bounded correlation with retained evidence', 'Retry, out-of-order and restart handling', 'Expiring exceptions for reviewed false positives']),
 'NAT, shared accounts and legitimate automation need review; protocol labels require supporting source evidence.'),
('WAF integration', 'MODSECURITY + CLOUDFLARE',
 ('On-premises or proxy WAF', ['Nginx / ModSecurity and OWASP CRS templates', 'Sanitised serial-JSON rule-match collection', 'DetectionOnly starting configuration', 'No request-body or credential export']),
 ('Cloudflare response connector', ['Use a configured zone and custom-ruleset scope', 'Apply an approved source-IP block', 'Embed fixed expiry in the provider rule', 'Retry cleanup without extending the deadline']),
 'Rule ordering, provider permissions, propagation and real traffic enforcement remain staging checks.'),
('Reviewed local containment', 'APPROVAL + BOUNDED ENFORCEMENT',
 ('Quarantine and restoration', ['Use approved malware path and SHA256 evidence', 'Linux: private same-filesystem quarantine vault', 'Windows: file-handle checks and protected ACLs', 'Restore without overwriting existing files']),
 ('Isolation and release', ['Require separate approval and local policy', 'Linux: kernel-expiring nftables isolation', 'Windows: firewall rules with local recovery tasks', 'Keep configured management exceptions']),
 'Containment is disabled by default. Windows expiry uses local recovery tasks; Linux uses kernel timeouts.'),
('How the components fit', 'PLATFORM ARCHITECTURE',
 ('Assessment service', ['FastAPI service, Celery workers and nightly scheduler', 'PostgreSQL with tenant policies, Redis broker and cache', 'Canonical findings, dedup and deterministic risk scoring', 'Read-only findings feed into the operations console']),
 ('Protection service', ['Authenticated Linux and Windows agents', 'One organisation per SQLite operational store', 'Detection, incidents, policies and response history', 'Independent delivery and cloud-response worker']),
 'SQLite protection persistence is not a horizontally scalable or highly available PostgreSQL backend.'),
('Central agent lifecycle', 'ENROLLMENT + POLICY + HEALTH',
 ('Credential management', ['Issue expiring, one-time enrollment credentials', 'Store hashes of enrolled host credentials', 'Rotate keys and revoke agent access centrally', 'Cancel unexecuted responses after revocation']),
 ('Inventory and policy', ['Track platform, agent version and queue health', 'Record administrator policy-version history', 'Flag drift from the desired software version', 'Keep privileged response enablement local to hosts']),
 'Agent software installation and upgrades use an administrator-controlled rollout.'),
('Incident and notification workflows', 'OWNERSHIP + EVIDENCE + DELIVERY',
 ('Investigation workflow', ['Link alerts to owned incident cases', 'Track status, notes and evidence timelines', 'Protect concurrent edits with case versions', 'Review alerts and add scoped, expiring exceptions']),
 ('SIEM and ticketing bridges', ['Send signed JSON to fixed HTTPS endpoints', 'Persist delivery state, leases and retry attempts', 'Attach stable keys for receiver deduplication', 'Audit outcomes without storing upstream secrets']),
 'Webhooks support organisation-operated adapters; native Jira, ServiceNow or Splunk connectors are not implied.'),
('Reliable delivery and retention', 'RECOVERY + MAINTENANCE',
 ('Telemetry continuity', ['Keep events until exact acknowledgement', 'Replay retained events after service outages', 'Pause collection visibly when the queue is full', 'Archive older events without fresh containment']),
 ('Evidence maintenance', ['Create consistent SQLite backups and verify restore', 'Preview retention cleanup before applying it', 'Preserve incident and response-linked evidence', 'Create offline-agent and stale-sensor alerts']),
 'Schedule maintenance explicitly and measure capacity, recovery objectives and backup security in the target environment.'),
('Hardened deployment', 'IMAGE SUPPLY CHAIN + AIR-GAP',
 ('Build integrity', ['Every scanner download SHA-256 pinned and verified', 'No pipe-to-shell, no floating "latest" versions', 'Containers run as an unprivileged user', 'Hash-locked Python dependencies']),
 ('Runtime posture', ['Redis authenticated; browser origins explicit, never wildcard', 'No scanner telemetry egress', 'Full offline mode with local vulnerability databases', 'Secrets injected from a vault, never baked into images']),
 'Tests fail the build if any download lacks a pin or the runtime user is removed.'),
('Validation evidence', 'AUTOMATED CHECKS + NATIVE FILE CHECKS',
 (TESTS, ['Access, roles, tenant and database-role boundaries', 'Target safety, scopes, cloud bindings and audit trail', 'Triage, scan lifecycle and deployment pinning', 'Detection, enrollment, incident and response workflows']),
 ('7 native Windows file checks passed', ['Disposable file-operation contract fixtures', 'Pinned-handle relative rename behavior', 'File-sharing and junction-race checks', 'Full ACL and firewall workflows require staging']),
 'Automated tests and narrow native file checks do not establish live containment efficacy or production readiness.'),
('Required staging validation', 'DEPLOYMENT GATES',
 ('Identity and data', ['IdP issuance, token lifetime and revocation behavior', 'PostgreSQL policies with both deployed database roles', 'Container image build and scanner compatibility', 'Existing-database migration rehearsal']),
 ('Hosts and enforcement', ['Windows Security/Sysmon and Linux audit collection', 'Cloudflare permissions, expiry and rule ordering', 'Linux/Windows isolation, expiry and rollback', 'False positives, overhead, backlog and recovery']),
 'Validate native Windows ACLs, firewall enforcement, scheduled-task expiry and reboot recovery before enabling containment.'),
('Evaluating fit for your organisation', 'DEPLOYMENT PLANNING',
 ('Scope and ownership', ['Select applications, APIs, cloud accounts and servers', 'Identify incident owners and response approvers', 'Approve the domains and networks in scope', 'Agree retention and recovery requirements']),
 ('Acceptance criteria', ['Measure detection coverage and false positives', 'Verify roles and separate-actor approval', 'Exercise containment, expiry and restoration', 'Measure host overhead and service recovery']),
 'Production deployment requires environment-specific validation and an approved operating procedure.'),
]

DESCRIPTIONS = [
 'VulnSuite is an internal security platform that finds and prioritises vulnerabilities, monitors servers for intrusion and coordinates approved response. It connects assessment findings with operational evidence while keeping responsibility, review and deployment requirements visible.',
 'Security teams need a clear path from identifying exposure to deciding what action is justified. VulnSuite supports that process by linking findings, suspicious activity and investigation records, helping analysts prioritise work and document their decisions.',
 'Different assets expose different kinds of risk, from vulnerable libraries to unsafe cloud settings and suspicious host activity. VulnSuite brings assessment and monitoring into a common operational context, with coverage determined by configured tools and telemetry sources.',
 'A single risk engine scores every finding, whichever tool produced it, so one queue replaces twenty tool-specific reports. Regulatory context travels with the finding: the RBI clause it maps to, and for critical items the CERT-In incident record needed within six hours.',
 'Applications inherit risk from their own code, third-party dependencies and build artifacts. These checks help teams understand what software contains, identify known weaknesses and retain supporting evidence so remediation and software release decisions can be reviewed.',
 'Exposed services, weak configurations and application interfaces can create paths into an organisation. Assessment collectors identify these conditions across selected targets, giving teams evidence to prioritise fixes and confirm which systems need closer investigation.',
 'Cloud estates change daily. Discovery keeps the asset inventory current across Azure, AWS and GCP, and posture benchmarks run under credentials that an administrator has explicitly bound to the tenant, so a scan can never reach further than the account it was approved for.',
 'A scanning platform is itself a risk if it can be pointed at systems the organisation does not own. VulnSuite scans private networks freely but requires an administrator to attest ownership of public domains and ranges, and validates every target before it reaches a scanner.',
 'Security operations involve sensitive evidence and actions that can interrupt services. Verified identity and explicit permissions establish who may act, while PostgreSQL enforces tenant boundaries itself, so an application bug cannot expose another organisation’s data.',
 'Auditors and incident reviewers need to know who did what, when, and why a risk was accepted. Every authenticated API call is recorded in a table nobody can rewrite, and analyst decisions carry a justification, an owner and an expiry that the platform enforces.',
 'An analyst investigating an alert needs to understand the affected host, its known weaknesses and any response already underway. The console brings that context together, helping teams coordinate investigation while making unavailable information visible.',
 'Server monitoring depends on collecting useful activity from the operating system and making gaps visible. Windows event sources and Linux audit records provide investigation evidence, while sensor health indicators help teams distinguish quiet systems from missing telemetry.',
 'Selected process patterns and reviewed malware indicators provide clues that warrant investigation. A known-bad hash match supplies specific file evidence; analysts can review its context before approving action, while missing scanners or telemetry remain visible as coverage limitations.',
 'Activity that appears ordinary on one server can become suspicious when repeated across several hosts. Correlating authentication events helps analysts recognise possible account misuse or movement between systems, while retaining context needed to assess legitimate administrative activity.',
 'Web application firewalls provide an enforcement point for traffic reaching protected applications. Connecting their signals with investigations helps teams understand attempted abuse and review scoped blocking decisions, with tuning and deployment checks needed to avoid disrupting legitimate requests.',
 'Containment can interrupt business services, so response decisions need clear evidence and accountability. VulnSuite places supported file quarantine and host isolation behind separate approval and local policy checks, with recorded outcomes and reviewed recovery paths.',
 'The assessment service evaluates exposure; the protection service handles telemetry, investigations and response. Their separate responsibilities help teams plan access, storage, maintenance and integration around the requirements of each service.',
 'Host monitoring depends on knowing which agents are enrolled, authorised and reporting correctly. Central lifecycle controls help maintain that inventory, replace credentials, withdraw access and identify policy or version differences that require administrator attention.',
 'Investigations often involve several people and external operational systems. Incident records preserve ownership and decisions, while signed notifications carry relevant information to organisation-operated integrations, helping teams coordinate work and recover delivery after temporary service failures.',
 'Network interruptions and growing evidence volumes can affect security operations. Persistent queues and acknowledgement checks support recovery after outages, while backup and retention controls help teams manage stored evidence according to investigation needs and operational requirements.',
 'A security tool that downloads twenty scanners is a supply-chain target. Every binary in the image is pinned to a known checksum and verified at build time, the containers run unprivileged, and the whole stack can operate without internet access using locally mirrored vulnerability data.',
 'The validation results demonstrate exercised code paths and selected native file behaviours. They provide evidence for technical review, while full containment effectiveness, host compatibility and operational performance require testing in the intended environment.',
 'Deployment conditions determine whether security controls work as intended. Staging should verify identity, database roles, telemetry, permissions, enforcement and recovery together, including how containment behaves during service interruptions and host restarts.',
 'A suitable deployment starts with clear asset scope, accountable owners and measurable acceptance criteria. These decisions help teams assess coverage, operational impact, recovery expectations and the conditions under which approved response should be enabled.',
]

SUBJECT = 'Introducing VulnSuite — vulnerability assessment, server protection and security operations'
INTRO = ('I would like to introduce VulnSuite, an internal security platform I have developed that brings '
         'vulnerability assessment, server intrusion monitoring and approved security response into one suite, '
         'built from the start around the RBI Cyber Security Framework and CERT-In reporting obligations. '
         'The attached package contains the complete source, the automated test suite, the operating manuals, '
         'a how-to-use process document and an executive briefing deck, for your review and a decision on a pilot.')
DEVELOPMENT_NOTE = ('VulnSuite was developed with assistance from frontier AI models, including Anthropic’s Claude Fable 5.1 '
                    'and OpenAI’s GPT-6 Astra, supporting architecture, implementation, testing and documentation. Both are '
                    'positioned by their respective providers among their most capable models for demanding coding and problem-solving work.')
SECTIONS = [
('Why VulnSuite', [
 'Our vulnerability surface is spread across code repositories, cloud accounts, container images, Kubernetes clusters, internet-facing domains and servers, each reported by a different tool in a different format.',
 'VulnSuite unifies 22 industry-standard scanners across 12 modules behind one risk engine, so the output is a single prioritised P0–P4 queue instead of twenty reports, with the regulatory citation attached to every finding.',
 'The same platform monitors Linux and Windows servers for intrusion signals and lets the SOC investigate and, with separate approval, contain, from one console.',
]),
('Vulnerability assessment coverage', [
 'Application security: Trivy, pip-audit and OSV-Scanner for dependencies; Semgrep and Bandit for code; Gitleaks and TruffleHog for secrets with values redacted; Checkov and Trivy for infrastructure as code.',
 'Exposure: passive nmap and testssl.sh for services and TLS; Dockle for container hardening; Kubescape and runtime image scans for Kubernetes; Subfinder and httpx for the external attack surface; Nuclei and OWASP ZAP for APIs, gated and off by default.',
 'Cloud: Prowler benchmarks and asset discovery for Azure, AWS and GCP, with nightly scheduled discovery per tenant.',
 'Supply chain: Syft SBOMs, Cosign signature and SLSA attestation checks, and VEX statements applied as documented downgrades rather than forgotten tickets.',
]),
('Risk prioritisation and compliance', [
 'Every finding is scored CVSS × EPSS × asset criticality × exposure and bucketed P0–P4. P0 starts the CERT-In six-hour clock and a CERT-In incident record is generated automatically.',
 'Each finding cites its RBI CSF Annex-I clause (crypto, patching, hardening, certificates, cloud, SDLC, secrets, database). CIS, ISO 27001, NIST 800-53 and OWASP mappings come from the scanner packs.',
 'Findings corroborated by several tools are merged with the corroboration trail kept for auditors. Optional AI signals (false-positive likelihood, known-exploited status) are advisory and never change the score.',
 'PDF reports carry a SHA-256 content hash in the footer for tamper evidence.',
]),
('Security controls built into the platform', [
 'Identity: login and MFA stay with our identity provider; the API verifies signed tokens and enforces four least-privilege roles (admin, analyst, auditor, viewer). There are no local passwords.',
 'Tenant isolation: PostgreSQL row-level security on every table, bound to the tenant in the verified token, with a separate schema-owner role so the runtime role cannot alter policies.',
 'Audit trail: every authenticated API call is recorded (actor, tenant, action, outcome, client IP, request ID, detail) in an insert-only table guarded by a database trigger.',
 'Scan authorisation: private networks are scannable; public domains and ranges require an administrator-approved scope, and hostnames are resolved before the check. Cloud scans run only under accounts an administrator has bound to the tenant, holding credential references rather than secrets.',
 'Safe by construction: every scan target is validated for format and shell safety, repository paths are confined to a workspace, aggressive scan modes are refused in code, and dynamic API testing needs three independent opt-ins.',
 'Analyst triage: accepted risks and false positives require a written justification; acceptances expire within 365 days and reopen automatically; re-scans never silently close an analyst-owned finding.',
 'Supply chain of the platform itself: every scanner binary is SHA-256 pinned and verified at build, containers run unprivileged, Python dependencies are hash-locked, Redis is authenticated, browser origins are explicit, and the whole stack runs offline with local vulnerability databases.',
]),
('Server monitoring and approved protection', [
 'Windows and Linux monitoring: Windows Security/Sysmon and Linux audit adapters, with SSH/API abuse, file-integrity and selected process signals.',
 'Malware and lateral-movement signals: known-bad SHA256 matches, optional Linux selected-file ClamAV scanning and cross-host login/pivot correlation.',
 'Windows and Linux containment: approved file quarantine/restoration and temporary host isolation/release, subject to separate-actor approval and local host policy. Containment is disabled by default.',
 'WAF integration: ModSecurity/OWASP CRS templates and sanitised telemetry, plus approved source-IP blocks through a configured Cloudflare connector.',
]),
('Security operations', [
 'SOC console: intrusion alerts, vulnerability findings, agent health and response review in a shared investigation view, with the same role checks as the API.',
 'Incident workflow: owned cases, status and evidence timelines, concurrent-edit protection, scoped and expiring exceptions.',
 'Agent management: one-time enrollment, credential rotation and revocation, policy history and version tracking; software rollout is administrator controlled.',
 'Integrations: signed HTTPS JSON webhooks with durable retries and delivery IDs for SIEM and ticketing adapters operated by us; structured JSON logs for Splunk or Sentinel.',
]),
('Reliability', [
 'Telemetry continuity: persistent queues, exact acknowledgements, visible queue limits and replay after outages; historical evidence cannot initiate fresh containment.',
 'Evidence maintenance: consistent backups, restoration verification, previewable retention cleanup and preservation of incident- and response-linked evidence.',
 'Assessment resilience: a crashing or timed-out scanner never fails a run; its error is recorded and findings it previously reported are never auto-closed on that basis.',
]),
('Validation and deployment requirements', [
 f'Evidence: {TESTS} across access control, tenant and database-role boundaries, target safety, scopes, cloud bindings, audit trail, triage, deployment pinning, detection, enrollment, incident and response workflows, plus seven narrowly scoped native Windows file-operation checks. Mocked response tests do not establish live enforcement.',
 'Staging before production: identity-provider integration, PostgreSQL policies with both database roles, the container image build, telemetry collection, ClamAV signatures, WAF enforcement, and native Windows/Linux containment and recovery.',
 'Operating scope: the protection service runs one organisation per SQLite store. Full EDR, memory protection, high availability and production capacity are outside the validated scope; quarantine does not terminate an already-running process.',
]),
('What is attached', [
 'VulnSuite_v0.4_hardening_2026-10-19.zip with its SHA-256 file: complete source, automated tests, deployment files, manuals (README, FEATURES, engineering guide, identity and database guide, protection operations guides) and the executive deck.',
 'VulnSuite_How_To_Use_2026-10-19.docx: step-by-step process document covering installation, the access model, tenant setup, daily operations, triage rules, the test suite, a staging acceptance checklist, maintenance and known limitations.',
 'VulnSuite_Executive_Deck_FINAL.pptx and VulnSuite_Executive_Deck_Review.pdf: the briefing presentation and its review copy.',
]),
('Requested next steps', [
 'Architecture and security review of the package by your team, with particular attention to the tenant isolation model, the audit trail, the scan-authorisation controls and the DAST gating.',
 'Approval of a 30-day internal pilot on non-production scope: selected repositories and images, two non-production clusters, one Azure subscription and one AWS or GCP sandbox, and our public root domains in passive mode only.',
 'Nomination of a platform-engineering owner for staging deployment and a SOC owner for the protection pilot on a small set of Linux and Windows servers, monitoring only, with containment disabled.',
 'A 45-minute walkthrough at your convenience to cover the architecture, the security controls and the pilot plan.',
]),
]


def color(value):
    return RGBColor.from_string(value)


def box(slide, x, y, w, h, fill):
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    shape.fill.solid(); shape.fill.fore_color.rgb = color(fill)
    shape.line.fill.background()
    return shape


def text(slide, value, x, y, w, h, size=18, fill=INK, bold=False):
    shape = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = shape.text_frame; tf.clear(); tf.word_wrap = True
    tf.auto_size = MSO_AUTO_SIZE.NONE
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    p = tf.paragraphs[0]; p.text = value
    p.font.name = FONT; p.font.size = Pt(size); p.font.bold = bold; p.font.color.rgb = color(fill)
    p.space_after = Pt(0)
    return shape


def wrapped(value, size, width):
    font = ImageFont.truetype(FONT_FILE, int(size * 4))
    words = value.split(); lines = []; line = ''
    for word in words:
        candidate = (line + ' ' + word).strip()
        if line and font.getlength(candidate) / 4 > width * 72:
            lines.append(line); line = word
        else:
            line = candidate
    if line:
        lines.append(line)
    return lines


def bullets(slide, items, x, y, w, h, where):
    shape = text(slide, '', x, y, w, h)
    tf = shape.text_frame
    for i, item in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = item; p.level = 0
        p.font.name = FONT; p.font.size = Pt(17); p.font.color.rgb = color(INK)
        p.line_spacing = Pt(22); p.space_after = Pt(8)
        props = p._p.get_or_add_pPr(); props.set('marL', str(int(Inches(.20)))); props.set('indent', str(-int(Inches(.18))))
        bullet = OxmlElement('a:buChar'); bullet.set('char', '•')
        props.insert_element_before(bullet, 'a:tabLst', 'a:defRPr', 'a:extLst')
    needed = sum(len(wrapped(item, 17, w - .23)) * 22 + 8 for item in items) - 8
    if needed > h * 72:
        raise ValueError(f'Bullet overflow on {where}: {needed}pt > {h * 72}pt')


def generate():
    assert len(DESCRIPTIONS) == len(SLIDES), 'Each slide needs a feature explanation'
    prs = Presentation(); prs.slide_width = Inches(13.333); prs.slide_height = Inches(7.5)
    prs.core_properties.title = SUBJECT
    prs.core_properties.subject = 'Platform capabilities, security controls and deployment requirements'
    prs.core_properties.author = 'VulnSuite'
    pdfmetrics.registerFont(TTFont('VS', FONT_FILE)); pdfmetrics.registerFont(TTFont('VS-Bold', BOLD_FILE))
    pdf = canvas.Canvas(str(ROOT / 'VulnSuite_Executive_Deck_Review.pdf'), pagesize=(13.333 * 72, 7.5 * 72))
    pdf.setTitle(SUBJECT); pdf.setAuthor('VulnSuite')

    def pdftext(value, x, y, size=18, bold=False, fill=INK, width=None, leading=None):
        pdf.setFillColor('#' + fill); pdf.setFont('VS-Bold' if bold else 'VS', size)
        lines = wrapped(value, size, width) if width else [value]
        for j, line in enumerate(lines):
            pdf.drawString(x * 72, (7.5 - y) * 72 - size - j * (leading or size + 6), line)

    for n, (title, kicker, left, right, note) in enumerate(SLIDES, 1):
        s = prs.slides.add_slide(prs.slide_layouts[6])
        box(s, 0, 0, 13.333, .10, ORANGE)
        text(s, kicker, .55, .35, 12, .3, 11, ORANGE, True)
        text(s, title, .55, .87, 12.2, .65, 34, NAVY, True)
        description = DESCRIPTIONS[n - 1]
        if len(wrapped(description, 15.5, 12.2)) > 3:
            raise ValueError(f'Slide {n} description exceeds three lines')
        if len(wrapped(note, 11, 12.2)) > 2:
            raise ValueError(f'Slide {n} footnote exceeds two lines')
        explanation = text(s, description, .55, 1.55, 12.2, .84, 15.5, INK)
        explanation.text_frame.paragraphs[0].line_spacing = Pt(20)
        pdf.setFillColor('#' + ORANGE); pdf.rect(0, 7.4 * 72, 13.333 * 72, .1 * 72, fill=1, stroke=0)
        pdftext(kicker, .55, .35, 11, True, ORANGE); pdftext(title, .55, .87, 34, True, NAVY)
        pdftext(description, .55, 1.55, 15.5, width=12.2, leading=20)
        for x, (heading, items) in zip([.55, 6.87], [left, right]):
            if len(wrapped(heading, 20, 5.36)) > 1:
                raise ValueError(f'Slide {n} heading wraps: {heading}')
            box(s, x, 2.55, 5.91, 4.0, PANEL)
            box(s, x, 2.55, .05, 4.0, ORANGE)
            text(s, heading, x + .27, 2.78, 5.36, .65, 20, NAVY, True)
            bullets(s, items, x + .27, 3.54, 5.3, 2.86, f'slide {n} "{heading}"')
            pdf.setFillColor('#' + PANEL); pdf.rect(x * 72, (7.5 - 6.55) * 72, 5.91 * 72, 4.0 * 72, fill=1, stroke=0)
            pdf.setFillColor('#' + ORANGE); pdf.rect(x * 72, (7.5 - 6.55) * 72, .05 * 72, 4.0 * 72, fill=1, stroke=0)
            pdftext(heading, x + .27, 2.78, 20, True, NAVY, width=5.36)
            cursor = 3.54
            for item in items:
                pdftext('•', x + .27, cursor, 17, False, ORANGE)
                pdftext(item, x + .5, cursor, 17, width=5.07, leading=22)
                cursor += (len(wrapped(item, 17, 5.07)) * 22 + 8) / 72
        text(s, note, .55, 6.65, 12.2, .42, 11, MUTED)
        text(s, f'CONFIDENTIAL • INTERNAL REVIEW  |  {DATE}', .55, 7.13, 11, .2, 9, MUTED)
        text(s, f'{n:02d} / {len(SLIDES):02d}', 12.08, 7.13, .75, .2, 9, MUTED)
        pdftext(note, .55, 6.65, 11, fill=MUTED, width=12.2)
        pdftext(f'CONFIDENTIAL • INTERNAL REVIEW  |  {DATE}', .55, 7.13, 9, fill=MUTED)
        pdftext(f'{n:02d} / {len(SLIDES):02d}', 12.08, 7.13, 9, fill=MUTED)
        s.notes_slide.notes_text_frame.text = (description + '\nScope: ' + note +
            '\nHow to use: docs/HOW_TO_USE.md\nEngineering reference: vulnsuite/CLAUDE.md'
            '\nProtection operations: vulnsuite/protection/OPERATIONS.md and deploy/protection/OPERATIONS.md'
            '\nAutomated validation does not establish live enforcement or full EDR coverage.')
        pdf.showPage()
    pdf.save()
    prs.save(ROOT / 'VulnSuite_Executive_Deck_FINAL.pptx')

    lines = ['Subject: ' + SUBJECT, '', 'Classification: CONFIDENTIAL — INTERNAL USE ONLY', '', 'Dear [CISO Name],', '', INTRO, '', DEVELOPMENT_NOTE, '']
    for i, (heading, items) in enumerate(SECTIONS, 1):
        lines += [f'{i}. {heading.upper()}'] + ['   • ' + item for item in items] + ['']
    lines += ['Regards,', '[Your Name]', '[Your Role]', '[Phone] | [Email]', '', 'CONFIDENTIAL — INTERNAL USE ONLY',
              'Do not forward outside the organisation without CISO approval.']
    body = '\n'.join(lines) + '\n'
    (ROOT / 'VulnSuite_Intro_Email.txt').write_text(body, encoding='utf-8')
    (ROOT / 'vulnsuite').mkdir(exist_ok=True)
    (ROOT / 'vulnsuite' / 'ciso_email.txt').write_text(body, encoding='utf-8')
    sections = ''.join('<h2>' + str(i) + '. ' + escape(h) + '</h2><ul>' + ''.join('<li>' + escape(v) + '</li>' for v in items) + '</ul>'
                       for i, (h, items) in enumerate(SECTIONS, 1))
    page = ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>VulnSuite briefing</title><style>body{margin:0;background:#f3f6fa;color:#334155;font:16px/1.6 Arial,sans-serif}'
            'main{max-width:820px;margin:24px auto;background:white;padding:36px;border-top:6px solid #f38020}'
            'h1{color:#0a2540;font-size:26px;line-height:1.3}h2{color:#0a2540;font-size:19px;margin-top:28px}li{margin:9px 0}'
            'small{color:#64748b}ul{padding-left:25px}</style></head><body><main>')
    page += ('<small>CONFIDENTIAL — INTERNAL USE ONLY</small><h1>' + escape(SUBJECT) + '</h1><p>Dear [CISO Name],</p><p>' + escape(INTRO) +
             '</p><p>' + escape(DEVELOPMENT_NOTE) + '</p>' + sections + '<p>Regards,<br>[Your Name]<br>[Your Role]<br>[Phone] | [Email]</p></main></body></html>')
    (ROOT / 'VulnSuite_Intro_Email.html').write_text(page, encoding='utf-8')
    print(f'Generated {len(SLIDES)} slides, companion review PDF, and the introduction email (txt, html, vulnsuite/ciso_email.txt).')


if __name__ == '__main__':
    generate()
