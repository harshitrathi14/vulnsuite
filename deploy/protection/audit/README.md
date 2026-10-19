# Linux execution audit input

- Review `vulnsuite-exec.rules` with the existing audit policy and host architecture. Load it through the distribution's auditd policy deployment on a staging server, then check event volume, kernel audit backlog/lost counters and log retention before production.
- Grant the agent read access to the audit log through the approved local group/ACL. Add `{"kind":"linux_audit","path":"/var/log/audit/audit.log"}` to the agent's `logs` array.
- Successful execve/execveat SYSCALL records tagged `vulnsuite_exec` become `process_start` events with original time, stable audit record identity, executable path and PID/PPID. This captures short-lived processes that /proc polling can miss. Keep the existing process monitor for deleted executable checks, parent resolution and on-host hash matching.
- The adapter ignores EXECVE and PROCTITLE records; command arguments never enter its outbox. Native audit logs may contain arguments locally, so their access and retention still require normal administration.
- Configure `queue_capacity` (100–1000000 events, default 5000) and audit rotation retention together. Full queues pause log reads at committed offsets and report backpressure. Server rejection retains the batch, including events outside the server archive window, for operator recovery. Stop the agent and archive its private state before approved repair; do not delete the state merely to clear the queue.
- Reading auditd logs supplies event-driven execution evidence through a polling transport. It does not hook or block execution, inspect memory, or provide kernel tamper resistance. Only the executable path is available from the SYSCALL record; parent-image rules need the existing /proc sensor or richer source telemetry.

References: [Linux audit rules](https://man7.org/linux/man-pages/man7/audit.rules.7.html), [ausearch event record semantics](https://man7.org/linux/man-pages/man8/ausearch.8.html).
