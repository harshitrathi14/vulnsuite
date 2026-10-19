# Protection operations and staging validation

The operational backend is SQLite with transactional ingestion, online backup and
explicit maintenance. Run one control-service writer deployment per organisation.
These tools do not establish production capacity, high availability, live firewall
correctness or a complete EDR capability. Benchmark your expected event volume and
recovery backlog before choosing a deployment size. No PostgreSQL migration or
cluster failover implementation is included.

## Backup and recovery

- Keep the database, server configuration and host credentials in private directories. Store backups on protected storage with appropriate encryption and retention; backup encryption and off-host replication belong to your storage/backup system.
- Use the SQLite backup API command below, which includes committed WAL data and checks the completed snapshot. Copying only a live `.db` file can omit committed WAL transactions.
- Record the JSON result's SHA256 independently with the backup inventory. Check restored data in a separate service deployment before switching any production configuration.
- Restore requires the expected digest and a new target path. It never replaces a running database. The restored database contains an audit record; its resulting digest therefore differs from the source backup digest.
- Test recovery against the organisation's recovery time and recovery point objectives. This repository does not assert measured RTO/RPO.

```bash
python3 -m vulnsuite.protection.maintenance --actor backup-operator backup \
  --database /var/lib/vulnsuite-protection/events.db \
  --target /private/backups/protection-2026-10-19.db

python3 -m vulnsuite.protection.maintenance --actor restore-operator restore \
  --backup /private/backups/protection-2026-10-19.db \
  --sha256 EXPECTED_64_CHARACTER_SHA256 \
  --target /private/recovery/events.db
```

Snapshots use exclusive publication and retain audit history. Failed backup attempts
are recorded in the source audit log; successful restores are recorded in the new
database. Preserve the original backup during investigations.

## Retention and loss of visibility

- `prune` previews counts by default. `--apply` explicitly commits eligible deletion and its audit record in one transaction. There is no background cleanup started by this module.
- Event retention defaults to 7 days by receipt time; unreferenced alert retention defaults to 90 days; delivered notification retention defaults to 30 days. Review these periods against organisational policy and the server's accepted telemetry archive window.
- Cleanup keeps incident-linked alerts, every response-history reference, pending notification alert references, active loss-of-visibility alerts, and supporting evidence around retained alerts. It keeps each alert's triggering event plus the correlation window from five minutes before to thirty seconds after an alert across hosts. This can retain events beyond `event-days`.
- Audit records, incidents, host policies, response histories and unfinished deliveries are preserved. They still consume storage; monitor disk capacity and separately archive these records under the organisation's policy.
- The health command creates deduplicated `agent_offline` and `sensor_stale` alerts. New enrollments receive a grace period. Fresh telemetry resolves the visibility alert's review state; an investigator's incident status remains unchanged. No log receipt proves tampering; an outage can have several causes.
- Configure your own service supervisor/scheduler to run health checks every minute and retention on the reviewed schedule. `--config` on health queues notifications for configured integrations; the independent notification worker sends them. Without it, alerts remain visible in the SOC console/API.

```bash
python3 -m vulnsuite.protection.maintenance prune \
  --database /var/lib/vulnsuite-protection/events.db \
  --event-days 7 --alert-days 90 --delivery-days 30

# After reviewing the preview, explicitly apply the selected retention policy.
python3 -m vulnsuite.protection.maintenance --actor retention-operator prune \
  --database /var/lib/vulnsuite-protection/events.db \
  --event-days 7 --alert-days 90 --delivery-days 30 --apply

python3 -m vulnsuite.protection.maintenance --actor health-monitor health \
  --database /var/lib/vulnsuite-protection/events.db \
  --stale-seconds 120 --grace-seconds 300 \
  --config /etc/vulnsuite-protection/server.json
```

Only sensors that have previously reported can become `sensor_stale`. Review
expected sensor configuration at enrollment; a never-enabled sensor has no evidence
stream for this watchdog to evaluate. Revoked hosts do not produce new missing-agent
alerts, and revocation alone does not mark an existing outage as recovered.

## Synthetic and live staging gates

- Run the protection tests: `python3 -m pytest tests/protection -q`.
- Run `python3 -m vulnsuite.protection.evaluation --output /private/reports/synthetic-new.json`. It creates isolated temporary databases, checks expected detector rules and emits a case-level confusion matrix. It never connects to hosts, sends notifications, scans malware or modifies a firewall.
- The fixture set deliberately includes a benign repeated-password failure that triggers a brute-force alert. Its synthetic false-positive rate describes these eight hand-written scenarios only. It is not an estimate of production detection accuracy.
- On representative staging hosts, verify Security/Sysmon or auditd evidence, timestamps, redaction, native source retention and sensor health. Exercise source rotation and service restart, then an outage long enough to fill the configured queue. Confirm committed evidence replays once, archived evidence does not produce live containment, and backpressure remains visible.
- Label a representative sample of normal organisation traffic and authorised test incidents; record per-rule precision/recall, false positives, ingestion delay, CPU/memory, disk growth and event loss. Review narrow host/rule/IP suppressions with expiry. Synthetic fixtures do not replace this evaluation.
- Test reverse-proxy SSO with valid, expired and wrong-audience tokens, role separation, host revocation, incident workflow and notification retries against staging integrations.
- Validate real nftables, Windows Event Log permissions and cloud-WAF behavior on disposable infrastructure. Verify exact allowed management access, expiry, receipt, provider status and rollback before enabling a production response policy. Mocked subprocess/provider tests establish request construction and policy checks only.

## Staged agent upgrades

1. Produce a versioned package and record its exact SHA256 in the approved release inventory. Verify the digest on each staging host before installing; obtain the expected digest through the trusted release process.
2. Back up private agent state/configuration and the service database. Retain the previous package for rollback. Do not clear the outbox or file baseline as an upgrade shortcut.
3. Stop one staging agent, verify the package with `sha256sum --check release.sha256` on Linux or `Get-FileHash -Algorithm SHA256` on Windows, install that specific local artifact, then restart the agent under its supervisor.
4. Set the host policy's desired agent version in the console/API. Confirm the next heartbeat's `agent_version`, queue depth, sensor health and version drift status. Registration policy does not execute an upgrade or arbitrary remote code.
5. Repeat with a small representative host group, observe the agreed staging window and test rollback. Expand in reviewed batches only after observed health and telemetry meet the recorded criteria.

No host upgrade, scheduled maintenance, identity-provider change, WAF deployment or
live containment was executed by these examples.
