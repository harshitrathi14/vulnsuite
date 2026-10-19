# VulnSuite server protection

A host monitoring and response module for internal servers and internet-facing
hosts, with Linux and Windows telemetry. It runs alongside VulnSuite's vulnerability scanning.
It is not a complete EDR, network IDS, WAF or guarantee against compromise.

## Operations and Windows containment release (0.4)

The [operations guide](OPERATIONS.md) documents the new verified identity/RBAC,
operations console, central agent enrollment, Windows/Linux audit telemetry,
incident workflows, durable delivery, SIEM/ticket bridges and reviewed containment.
Where older baseline behaviour below differs, the current operations guide applies.

**Platform coverage:** Windows and Linux have monitoring and approved
quarantine/restoration and host isolation/release implementations. Windows uses
native file handles/ACLs and Windows Firewall with local recovery tasks; Linux uses
its existing file-vault and nftables implementations. Native Windows validation is
still required before rollout; see the [Windows deployment guide](../../deploy/protection/windows/README.md).

## Implemented coverage

| Signal | Detection |
| --- | --- |
| OpenSSH log entries | Five failed authentications from one IP to one host within five minutes |
| OpenSSH log entries | A successful login following five failures from the same IP, even with out-of-order delivery |
| Structured API access log | Twenty HTTP 401/403 responses from one IP to one host within five minutes |
| Explicitly watched files | Content, owner, group or permission changes; creation and deletion |
| Linux processes | Web server spawning a shell, execution from /tmp, /var/tmp or /dev/shm, and deleted executables |
| Malware | Known-bad SHA256 matches in running executables and selected files; optional ClamAV signature scanning |
| Multiple hosts | Password spraying across three or more servers and same-user SSH login fan-out |
| Enrolled source host | Malware/process signal followed by an SSH login to another host from that source's configured IP |
| ModSecurity v3 | Sanitised WAF rule matches and reported intervention state |
| Agent communication | Last-seen/stale host status and per-sensor health |

Thresholds are fixed in `store.py` for this first version. Authentication rules
correlate by source IP, not proof of attacker identity. NAT, legitimate failed
logins and normal deployments can produce alerts. File changes are informational
security signals, not evidence that a compromise definitely occurred.

The service persists events, alerts, response requests, receipts and an audit trail.
The baseline response adds a source IP to one dedicated nftables set on the
reporting host for 60–3600 seconds. An IP is eligible only if it matches an explicit
permitted network and does not match a protected network, at both service and agent.
The current release also supports Cloudflare WAF blocking, Windows/Linux file quarantine and
temporary host isolation through separately approved response plans. These require
explicit configuration and independent local policy checks for host actions. See
the [operations guide](OPERATIONS.md) for approval, expiry and rollback behaviour.

## Source and integration boundary

The protection source is in `vulnsuite/protection`, with deployment examples in
`deploy/protection` and automated tests in `tests/protection` at the repository root.

This is a **separate single-organisation control service**: deploy separate
processes, databases, credentials and ingress per organisation. Its local SQLite
operational store is not the suite's multi-tenant findings database. It uses its own verified operator identity configuration; the assessment API also now verifies signed tokens. Existing
scan jobs, risk scoring, dashboard and scan reconciliation are unchanged; intrusion
alerts are read through this service's API/CLI and are not automatically closed
when a vulnerability scan completes. The operations console combines read-only vulnerability findings with intrusion records, and configured webhooks support SIEM/ticket bridges.

## Run locally

From the directory containing the `vulnsuite` package and `tests`:

```bash
python3 -m venv .venv
.venv/bin/pip install 'fastapi>=0.110' 'uvicorn>=0.29' 'httpx>=0.27' \
  'python-jose[cryptography]>=3.5' 'pydantic-settings>=2.2'
```

Copy `deploy/protection/server.example.json` and `agent.example.json` into a
private configuration directory. Generate distinct random tokens using
`python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`: one operator token
and one token per host. Replace every placeholder. The host token must match in
the service's host entry and that host's agent configuration. Keep files readable
only by their service account. Example tokens are rejected at service startup.

For local testing, set the service database and agent state paths to writable
private paths, and use `http://127.0.0.1:8010` as the agent server URL. Adjust log
paths for your distribution: Debian/Ubuntu commonly use `/var/log/auth.log`, while
RHEL-derived hosts may use `/var/log/secure`. Journald-only hosts need a persistent
sshd log export first. Only add explicit regular files to `watch_files`.

```bash
VULNSUITE_PROTECTION_CONFIG=/absolute/path/server.json \
  .venv/bin/uvicorn vulnsuite.protection.service:create_app --factory \
  --host 127.0.0.1 --port 8010 --workers 1

.venv/bin/python -m vulnsuite.protection.agent --config /absolute/path/agent.json
```

The first agent cycle starts logs at EOF and establishes the file baseline. Enroll
only after reviewing a known-good server state. Removing state resets this baseline.
File contents and raw log lines never leave the host; the monitored file's path,
change type and parsed authentication username/source address may be sent. Process
signals contain executable/parent paths, PID and process start ticks; they never
contain arguments or environment variables. Malware signals include file path,
SHA256 and signature name. WAF signals contain only rule IDs, source IP and action.

Save only the operator token into a private token file to inspect the service:

```bash
.venv/bin/python -m vulnsuite.protection.operator \
  --url http://127.0.0.1:8010 --token-file /absolute/path/operator-token alerts
```

Replace `alerts` with `hosts`, `responses`, `audit`, `overview`, `incidents`,
`playbooks` or `suppressions` to inspect those records.
A block request uses the same prefix followed by:

```text
block --alert-id 12 --duration 300 --reason "Investigated repeated unauthorised access"
```

A queued response is not proof of enforcement. Check `responses` for the agent's
`applied`/`failed` receipt. Timeouts expire in the kernel even if the agent stops.
An `applied` receipt reports successful rule insertion, not independently verified
packet blocking. To remove a block early, the host administrator can delete its
IP element from the dedicated set; deleting only the `inet vulnsuite` table removes
this module's enforcement without flushing other firewall rules.

## Deploy to servers

Templates live in `deploy/protection/`. Install the package and venv at
`/opt/vulnsuite`, create the separate `vulnsuite-protection` and `vulnsuite-agent`
service accounts as needed, put configuration under `/etc/vulnsuite-protection/`,
and install the relevant systemd unit on each machine. Units use `StateDirectory`
and private permissions. Set configuration ownership so only its service account
and the administrator can read its keys. Grant the agent read access only to the
configured logs/files; adjust `SupplementaryGroups=adm` for the distribution.

Keep the control service bound to loopback behind your HTTPS reverse proxy.
Only enrolled hosts and operators should reach it. Configure ingress request-rate
and connection limits; the application enforces a 256 KiB request limit and 200
events per batch. Agents verify HTTPS certificates, ignore environment proxy
settings, do not follow redirects and require HTTPS except on literal loopback.
Synchronise host clocks. Back up the database and config, monitor disk space, and
rotate/revoke host tokens through the audited agent-management API. The service
config seeds host credentials only on first enrollment; restarting does not
overwrite later credential or policy changes.

For API monitoring, add a log entry such as
`{"path":"/var/log/nginx/api-security.json","kind":"api"}`. Each line must be a
JSON object with numeric `status` and `remote_addr`. Configure the web server to
record a trustworthy client address; do not derive it from an untrusted forwarded
header. Behind a reverse proxy, host-level blocking may not reach the real client:
protect proxy addresses and use a WAF/proxy integration for client enforcement.

### Optional host enforcement

Both example configs disable response. Before enabling it, set accurate management,
monitoring, control-plane and proxy networks in `protected_networks` and restrict
`permitted_networks` to networks where source blocking is authorised. Empty
permitted networks deny all blocks. Special/non-unicast IPs are always rejected.

On a staging Linux host with nftables, review and load `vulnsuite.nft` using
`nft -f /path/to/vulnsuite.nft`. It adds a dedicated table and does not flush existing
rules. Its INPUT chain covers traffic delivered to the host, not forwarded traffic
to containers or Kubernetes workloads. The pre-created sets have bounded size and
kernel-managed element timeouts, following the
[nftables timeout contract](https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts).

Enable `allow_response` in both configs and install the example systemd response
drop-in, granting only the agent `CAP_NET_ADMIN`. Restart the services after config
changes. Test with an expendable source address outside protected networks and
confirm actual traffic drops and expires. The default monitoring unit has no
network-admin capability. These deployment actions are intentionally not run by
unit tests or source installation.

## Process, malware and lateral-movement setup

The example agent config now includes `process_monitor` and `malware` sections.
Existing configs continue to work; enable the new sensors explicitly.

Set `process_monitor.enabled=true` to poll Linux `/proc` on each agent cycle. Rules
flag deleted executables, executables under `/tmp`, `/var/tmp` and `/dev/shm`, and
known shell executables whose immediate parent is a recognised web server. Use
`allowed_executables` for exact local paths of reviewed legitimate exceptions;
these exceptions never suppress known-bad hash matches. Visibility is limited by
the service account, procfs `hidepid` and container/PID namespace. Do not grant
broad root access just to hide a partial sensor status. A regular deployment or
upgrade may legitimately run a deleted executable; review the evidence.

Optionally add `known_bad_sha256` to either section as a JSON map from lowercase
64-character SHA256 to a short signature label. Use only reviewed indicators;
there is no built-in malware feed or claim that an empty indicator list detects
unknown malware. Process hashing reads `/proc/<pid>/exe`, covers up to 64 distinct
executables per cycle, and rotates the starting process for coverage. The process
sensor examines up to 4096 visible PIDs and emits at most 500 signals per cycle;
exceeded budgets mark it partial. It tracks PID plus start ticks to handle PID reuse.
Hashing is bounded to 16 MiB per executable. Arguments and environment are never read.

For ClamAV, install `/usr/bin/clamscan` and its supported signature databases on
the monitored host; maintain the databases with your supported FreshClam service.
Set `malware.enabled=true`, `clamav=true` and populate `scan_files` with explicit,
absolute regular file paths readable by the agent. The sensor scans up to eight
files of up to 16 MiB per scheduled scan, with a minimum 60-second interval (default
300). Directories/symlinks are refused. Scanning uses a 60-second command deadline,
archive budgets and a maximum signature database age of seven days. Unsupported
options, absent scanner/databases, unreadable files, changed inputs and scan limits
produce degraded health instead of a clean result. Scan-limit alerts are not
labelled as malware. The scanner itself does not delete, quarantine or upload files;
quarantine requires a separate approved playbook. This is
scheduled selected-file scanning, not an on-access or full-disk antivirus service.

`operator hosts` shows `sensors` with `status`, `detail`, `last_seen` and `stale`.
Failures also produce `sensor_degraded` alerts. Independent log/file/sensor failures
do not stop heartbeat delivery or other sensors. An unconfigured malware engine
is not considered healthy. Malware health is refreshed between scheduled scans;
its status describes the latest attempt, not proof of an uninfected server.

For lateral-movement correlation, set each enrolled host's `addresses` to its
unique stable IPs through enrollment or the host-policy API. The service config
provides initial policies for existing configurations only. An agent cannot
assign its own host identity or IP ownership. Duplicate ownership is rejected.
The service correlates, over five minutes:

- At least ten SSH failures reaching three distinct reporting hosts from one IP:
  `cross_host_password_spray`.
- Successful SSH logins for one username reaching three hosts from one IP:
  `remote_login_fanout`.
- A process/malware signal on an enrolled source followed by a successful SSH login
  to another enrolled host from the source's configured address:
  `suspected_lateral_movement` (critical).

Both arrival orders are supported and history survives restarts. Different usernames,
source IPs and stale evidence do not combine into one pivot. Shared accounts, NAT,
bastions and legitimate orchestration may look similar; these are investigation
alerts, not proof. The Windows adapter adds RDP/network-logon, SMB-access and
Sysmon process evidence; Linux audit adds event-driven process execution. WinRM
process ancestry is a signal, not proof of a remote connection's source. See the
linked collector guides for source setup and protocol attribution limits.

## WAF setup

See [ModSecurity/OWASP CRS deployment](../../deploy/protection/waf/README.md).
The provided nginx/ModSecurity configuration integrates a real external WAF and
sanitised serial-JSON telemetry. It starts in DetectionOnly; enable enforcement
only after staging tests and application-specific CRS tuning. Neither a readable
log nor an HTTP 403 alone proves that WAF blocking is active.

## Reliability and limits

- The local outbox commits log offsets, file baselines and events together before
  transmission. Event IDs deduplicate retries across control-service restarts.
- The outbox defaults to 5,000 events and has configurable capacity. Collection
  pauses at capacity without advancing unread offsets and reports backlog health.
  The server accepts events within its archive retention window (30 seconds future skew).
  Historical events within the configured retention window are archived without running current detections. Unacknowledged events are retained by the agent.
- The agent detects inode changes and copy-truncation, and waits for complete log
  lines. Unread tails of rotated files can be lost; this is not a lossless log shipper.
  Lines above 64 KiB are skipped and mark that log sensor partial.
- File monitoring polls explicit files up to 16 MiB and refuses symlinks. It cannot
  detect a change that is reverted between polls, capture every process execution,
  or protect its state from a privileged attacker on the monitored host.
- Receipts are durable and retried. A crash between rule execution and recording
  its result leaves a conservative failure receipt; inspect the host ruleset. The
  agent does not repeat uncertain actions or extend their timeout on restart.
- Raw events use configurable retention; explicit maintenance protects incident-linked evidence. Alerts/audits/responses persist
  until operationally archived; plan storage/backup for their volume. Audit records
  are application records, not tamper-proof external evidence.
- No eBPF capture, memory scanning, exfiltration detection,
  complete authenticated patch/hardening audit or automated incident
  investigation is implemented. Process polling alone misses short-lived activity;
  correlation rules identify suspicious patterns and do not establish compromise.
  A privileged attacker can evade or tamper with a host sensor. ClamAV and the WAF
  require separate installation, updates and live validation.

## Verification

```bash
python3 -m pytest -q --confcutdir=tests/protection -o addopts='' tests/protection
python3 -m compileall -q vulnsuite/protection
```

The isolated test directory avoids unrelated suite fixtures and external scanner
requirements. Tests cover credential separation, cross-host command isolation,
strict telemetry validation, stale events, transactional rollback, deduplication,
out-of-order correlation, restart persistence, file changes/log rotation, network
outages, protected addresses, response receipts and an end-to-end simulated block.
Additional tests cover process heuristics, PID reuse, hash matches, ClamAV limits
and failures, WAF redaction/intervention state, sensor degradation, password spraying,
login fan-out and pivot detection in both arrival orders. The tests mock external
ClamAV/firewall execution; no live server, WAF or firewall has been modified.
