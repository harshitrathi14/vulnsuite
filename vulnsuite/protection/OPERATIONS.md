# VulnSuite operations enhancement release

This release adds verified access-token authentication, an operations console,
incident handling, central enrollment, broader endpoint telemetry, longer outage
retention and reviewed containment integrations. This is implemented source with
automated validation; external identity, Windows/auditd, PostgreSQL, Cloudflare,
ClamAV and live firewall behaviour still need deployment-specific staging tests.

**Platform coverage (0.4):** Windows and Linux have monitoring and approved
quarantine/restoration and host isolation/release implementations. Windows native
file handles/ACLs and firewall recovery tasks have automated adapter/workflow tests;
live Windows execution, permissions and recovery still need staging validation.

## Verified identity and roles

The main assessment API no longer accepts arbitrary bearer tokens. Configure
`VULNSUITE_AUTH_*` for the issuer, audience and pinned JWKS URL/file described in
[auth configuration](../../deploy/protection/auth.example.md). JWT verification
checks signature, allowed algorithm, issuer, audience, expiry, signed tenant and
explicit role claims. The `X-Tenant-Id` header must equal the signed tenant claim.
The PostgreSQL session binding now applies on every transaction, with forced RLS
and a runtime role that cannot bypass tenant policies. Database policy migrations
need execution privileges; use your reviewed deployment/migration process. Existing
assessment deployments must configure verified identity and migrate the old
superuser application role before upgrading; follow the
[Compose identity and database guide](../deploy/AUTH_DEPLOYMENT.md).

For the protection service, use `deploy/protection/operations.example.json` as the
starting point. `operator_auth` configures the same verifier, and
`organisation_id` binds all operator access to one signed tenant. In this mode,
shared bootstrap operator keys are disabled. Interactive sign-in and MFA are
provided by the external identity provider; this release verifies its access tokens.

Roles:

| Role | Rights |
| --- | --- |
| viewer / auditor | Read overview, evidence, investigations, policies and audit history |
| analyst | Read, review alerts, own/update investigations and request response plans |
| admin | Analyst rights plus enrollment, revocation, policy changes, exception creation and approval |

For isolated pilot testing only, named local `operators` may be configured as
`{"reviewer":{"token":"<random token>","roles":["admin"]}}`. Tokens must be
unique and at least 32 characters. Different names with the same token are rejected.
The legacy `operator_token` remains a local bootstrap admin credential when SSO is
not configured. A single bootstrap identity cannot self-approve two-person response
plans. Configure actual separate identities, not aliases of one shared token.

## Unified operations console

Open `/console` on the protection service through the deployment's HTTPS proxy.
The console provides:

- Intrusion alerts and their evidence, alongside vulnerability findings.
- Agent connectivity, platform/version metadata, sensor status and version drift.
- Investigation creation from selected alerts, ownership, notes and status updates.
- Review of response plans and approval by a different administrator.
- Central agent enrollment with a one-time credential.

Tokens remain only in the browser tab's memory; sign-out clears them. Data is
rendered as text, and the console uses a same-origin content security policy.
The console is a client of the same role-checked API; hiding a button is not an
authorization control.

To show vulnerability findings, configure the fixed HTTPS `assessment_api`
connection with a read-only service token supplied through `token_env`. Its
`tenant_id` must match `organisation_id`. The aggregator makes only fixed read
requests and reports unavailable/expired credentials as an unavailable source,
not an empty/clean vulnerability inventory. The console shows bounded recent lists
(200 findings/alerts/incidents), not an exhaustive cross-platform evidence search.

## Central agent enrollment and policy

1. An administrator requests `POST /v1/enrollment-tokens` with a unique host name,
   typed host policy and optional TTL (60–3600 seconds; default ten minutes).
2. On the intended host, redeem the one-use token at `POST /v1/enroll` and save the
   returned host token into its private local configuration.
3. Run the configured Linux or Windows agent. Heartbeats report platform, agent
   version, queue capacity/depth and paused collection.
4. Administrators rotate or revoke credentials using
   `POST /v1/agents/{host}/rotate` or `/revoke`. Rotation invalidates the old token
   immediately. Revocation prevents further API access and cancels unexecuted
   containment commands. Previously attempted cloud actions still get cleanup.

The enrollment database persists token hashes, never raw host tokens. Tokens are
returned once to the requesting administrator/host. `/v1/agents/{host}/policy`
accepts administrator policy updates and records a policy version history. Current
policy is available to the credential-bound host at `/v1/agent/policy`.

Set `addresses` for stable host ownership and `desired_version` for version drift
reporting. Duplicate active address ownership is rejected. Local response policy
is an independent gate and must be deployed on the host; server policy changes
cannot silently enable privileged host actions. Software upgrades remain an
administrator-controlled rollout; enrollment does not provide arbitrary remote
software execution. The config file seeds existing hosts only on first import;
subsequent policy/credential changes use the audited API/database.

## Endpoint telemetry

- [Windows collector](../../deploy/protection/windows/README.md): Security log
  authentication events, RDP/network logon evidence, SMB access events and Sysmon
  process creation. The adapter forwards only selected fields, not command lines.
- [Linux audit collector](../../deploy/protection/audit/README.md): event-driven
  execution records complement `/proc` polling and can catch short-lived activity.
- Process-start records feed suspicious executable-path and web-server-to-shell
  rules. Windows network logon is not automatically labelled SMB or WinRM: source
  telemetry must establish the protocol.
- Windows quarantine evidence can come from exact Sysmon SHA256 matches against
  the locally configured reviewed indicator list. Unknown/missing hashes remain
  process telemetry. The native executor rechecks the file's identity and hash.
- The Windows runner also executes approved Windows-native playbooks when explicitly
  configured; it rejects the legacy nftables IP-block command. Host audit
  configuration, log-read access and Sysmon installation are deployment
  prerequisites. These are not changed automatically by the agent.

Use approved staging scenarios to verify event IDs and actual field availability
on the OS versions you operate. Event-driven records improve coverage but do not
constitute a complete EDR, network IDS or memory scanner.

## Reliable delivery and retention

The service accepts historical events within `retention_days` (default seven,
range 1–365) but evaluates current detections and host health only from events in
the latest five minutes. Older records are stored for investigation; they cannot
initiate a fresh block or make an offline host look healthy. Replay IDs continue
to deduplicate across restarts and schema upgrades.

The agent keeps events until the server acknowledges the exact batch count.
Transport errors, malformed acknowledgements and HTTP 422 preserve pending data.
Queues are bounded and configurable; reaching capacity pauses collection without
advancing unread log offsets, while a separately persisted health message reports
the backlog. A record outside the configured archive acceptance window requires
operator investigation or a retention-window adjustment; it is not silently erased.

Use the explicit `maintenance` CLI for consistent backup, verified restore and
retention cleanup. Schedule cleanup deliberately: ingests no longer delete evidence
behind active investigations. See `python -m vulnsuite.protection.maintenance --help`
and the [maintenance and staging runbook](../../deploy/protection/OPERATIONS.md).
It covers backups, recovery, retention, missing-telemetry alerts, synthetic detection
evaluation and staged agent upgrades. This service still uses a per-organisation
SQLite operational database; it is not a horizontally scalable PostgreSQL backend.

## Investigations, exceptions and notifications

- `POST /v1/incidents` creates an owned case linked to actual alert IDs.
- `PATCH /v1/incidents/{id}` requires the current version to prevent overwriting
  concurrent analyst edits. Status/owner changes append a note and audit entry.
- `GET /v1/incidents/{id}/timeline` returns notes and linked alert evidence.
- `POST /v1/alerts/{id}/review` records triage, resolution or false-positive review.
- `POST /v1/suppressions` creates a narrowly scoped rule/host/source exception with
  a reason and a maximum seven-day expiry. Matching alerts remain stored and visible
  as suppressed; notifications are muted. Exceptions can be revoked immediately.
- Metrics distinguish reviewed false positives from overall detections and include
  time to first review. They are operational measurements, not detection accuracy
  guarantees.

Configured SIEM/ticket bridges receive signed JSON webhooks through a durable
outbox. The worker uses fixed HTTPS destinations, environment-provided secrets,
idempotency keys, leased claims and retry/backoff. Receiving systems must verify
signatures and deduplicate delivery IDs. Adapters for a vendor-specific incident
schema belong at the bridge; generic webhooks do not imply a native Jira/Sentinel
or Splunk integration. No message is sent merely by importing/configuring code.
Run the worker explicitly after reviewing the configured destinations.

## Reviewed response plans

`POST /v1/playbooks` constructs an immutable, auditable proposal from an alert.
`POST /v1/playbooks/{id}/approve` requires an administrator whose signed/operator
subject differs from the requester. Expired or already approved requests cannot
be approved again. The UI exposes the plan before approval.

Supported playbooks:

- `quarantine_file`: only malware-alert path/hash evidence; the host verifies an
  exact path allowlist and hash, moves the file to a private quarantine directory,
  and records a durable manifest. Files are not deleted.
- `restore_file`: targets a previous applied or failed quarantine attempt and refuses to overwrite
  an existing destination. Rollback remains possible for older incident alerts.
- `isolate_host`: requires explicit host enablement, platform, permitted actions,
  management exceptions and immutable expiry. Linux's nftables gate times out in
  the kernel. Windows uses job-owned firewall rules and a pre-armed SYSTEM recovery
  task/watchdog, with agent cleanup before network operations. Windows requires
  pinned management host IPs and a trusted local helper hash; its expiry depends
  on Windows service availability and must be tested on the deployed host policy.
- `release_host`: removes the specific previous isolation attempt's owned rules.
  This is also available after a failed/uncertain attempt, with separate approval.
- `cloud_waf_block`: uses a configured Cloudflare zone/ruleset. The rule includes a
  provider-evaluated fixed expiry, so failed cleanup cannot turn the temporary block
  into permanent enforcement. The durable worker reconciles and removes expired
  managed rules; retries do not extend the approved expiry.
- `terminate_process`: only alerts that evidence a PID (`web_server_shell`,
  `writable_directory_execution`, `deleted_executable`, or a `malware_detected`
  hit from the running-process scan). The plan pins PID, executable and, where the
  agent observed it, the procfs start ticks; otherwise the alert time bounds the
  identity. On Linux the agent opens a pidfd, re-reads the identity behind that PID
  and signals through the pidfd (SIGTERM, then SIGKILL after `grace_seconds`,
  default 2), so a recycled PID is reported `process_absent` rather than killed.
  Windows opens one handle for the image, creation-time, terminate and exit-wait
  calls. init/systemd/sshd and core Windows system processes are never targets;
  `response_policy.termination.protected_executables` extends that list locally,
  and root-owned Linux processes need `allow_privileged: true`. Termination is not
  reversible and has no rollback playbook; it does not remove the file (use
  `quarantine_file`) or stop a respawning parent (use `isolate_host`).

Local responses are delivered only to the matching active host credential and
independently checked against `response_policy` on that host. Result receipts must
match the approved action; failed or uncertain execution is not reported as success.
Existing operator-requested temporary IP blocks remain available under their
narrower host IP policy. See the [response/integration examples](../../deploy/protection/integrations/README.md)
for exact configuration.

Windows configuration and its precise management-port exceptions are documented in
the [Windows deployment guide](../../deploy/protection/windows/README.md). Quarantine
does not terminate processes; request `terminate_process` separately when the file
is still running. Before native execution the agent saves an uncertain
receipt; a crash therefore reports failure instead of replaying a privileged action.
Review local evidence and use a separately approved rollback for uncertain outcomes.

## Release verification and deployment gate

Automated tests exercise signed-token rejection, RBAC, tenant isolation statements,
enrollment/revocation, case concurrency, archived telemetry, Windows/audit parsers,
notification retries, response approval, local playbook policies and rollback.
A browser smoke check covers sign-in, alert selection, incident creation, agent
view and sign-out without persistent browser token storage.

Required live staging checks remain: external IdP issuance/revocation, PostgreSQL
RLS under the chosen service role, host OS event collection, ClamAV signatures,
WAF enforcement, real packet isolation/rollback and provider API permissions. Run
approved detection simulations and normal business workloads; measure false
positives, collection gaps, CPU/storage use and recovery before production rollout.
