# Linux execution audit input

- Review `vulnsuite-exec.rules` with the existing audit policy and host architecture. Load it through the distribution's auditd policy deployment on a staging server, then check event volume, kernel audit backlog/lost counters and log retention before production.
- Grant the agent read access to the audit log through the approved local group/ACL. Add `{"kind":"linux_audit","path":"/var/log/audit/audit.log"}` to the agent's `logs` array.
- Successful execve/execveat SYSCALL records tagged `vulnsuite_exec` become `process_start` events with original time, stable audit record identity, executable path and PID/PPID. This captures short-lived processes that /proc polling can miss. Keep the existing process monitor for deleted executable checks, parent resolution and on-host hash matching.
- The adapter ignores EXECVE and PROCTITLE records; command arguments never enter its outbox. Native audit logs may contain arguments locally, so their access and retention still require normal administration.
- Configure `queue_capacity` (100–1000000 events, default 5000) and audit rotation retention together. Full queues pause log reads at committed offsets and report backpressure. Server rejection retains the batch, including events outside the server archive window, for operator recovery. Stop the agent and archive its private state before approved repair; do not delete the state merely to clear the queue.
- Reading auditd logs supplies event-driven execution evidence through a polling transport. It does not hook or block execution, inspect memory, or provide kernel tamper resistance. Only the executable path is available from the SYSCALL record; parent-image rules need the existing /proc sensor or richer source telemetry.

## Log tamper watch rules

- `vulnsuite-logs.rules` tags successful writes and attribute changes under `/var/log`, to audit and syslog configuration and to the audit control binaries with `vulnsuite_log_tamper`, excluding the legitimate writers (`rsyslogd`, `systemd-journald`, `logrotate`, `auditd`). Adjust the writer paths to your distribution and add `-F exe!=` entries for approved log shippers before loading.
- The agent joins the tagged SYSCALL record with its PATH record into one `log_tamper` event (executable, PID, audit uid, path, `deleted`/`replaced`/`written`). An event split across a read boundary is still reported, without the path. Per source, `"tamper_ignore_executables": ["/usr/bin/backup-agent"]` drops a known writer on the host.
- Expect noise during package upgrades and log maintenance; review the first week on staging and extend the exclusions rather than removing the rule.

References: [Linux audit rules](https://man7.org/linux/man-pages/man7/audit.rules.7.html), [ausearch event record semantics](https://man7.org/linux/man-pages/man8/ausearch.8.html).
