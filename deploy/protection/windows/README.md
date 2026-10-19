# Windows monitoring and approved containment

Windows now has implementations for monitoring, file quarantine/restoration and
temporary host isolation/release. Native file and firewall execution still require
staging validation on the Windows versions and policies used by your organisation.
Response is disabled in the example until both local and control-service policies
are configured and an administrator separately approves each action.

- Install the same Python package/dependencies as the protection agent; use a dedicated service identity with permission to read `Security` and `Microsoft-Windows-Sysmon/Operational`.
- Enable successful/failed Logon and File Share auditing through your approved Windows audit policy. Install/configure Sysmon process-create events with SHA256 if process evidence is required.
- Copy `Export-VulnSuiteEvents.ps1` and `agent.example.json` to `C:\ProgramData\VulnSuite`, replace the token/URL, and restrict the directory ACL to Administrators, SYSTEM and the dedicated service identity. The JSON state contains account names and host telemetry; Windows directory ACLs provide protection because POSIX modes do not.
- Run `python -m vulnsuite.protection.windows_agent --config C:\ProgramData\VulnSuite\agent.json` under your service supervisor or a startup Scheduled Task with restart-on-failure. Event collection is read-only and invokes PowerShell without profile or interactive input; approved response uses separate native executors. Apply your normal code signing policy. The agent holds a Windows file lock to prevent concurrent state writers.
- First enrollment records the newest channel positions; subsequent cycles read records in order. Cursors and normalized event outbox commit together before delivery, so server outages do not discard acknowledged cursor evidence. Configure sufficient Windows channel retention and queue capacity for the expected outage.
- Channel read errors, malformed evidence, backlog and detected log clearing produce sensor health. Channel rollover can still remove uncollected evidence; monitor Windows Event Log retention and agent backlog externally. A compromised local administrator can suppress logs or tamper with the agent; this is not tamper-proof EDR.

## Evidence and limits

- Security 4624/4625 with logon type 10 supplies RDP authentication events; type 3 remains generic network authentication. The source IP must be present and non-loopback.
- Security 1102 (audit log cleared), 1100 (event-log service stopped) and 4719 (audit policy changed) are exported as `log_tamper` evidence with the acting account where the event carries one. Clearing the Security log is itself logged as the first entry of the new log, so the signal survives the clear.
- Security 5140 supplies SMB share-access outcomes using the audit success/failure keyword. This is observed share access and may be normal; it is not proof of credential theft.
- Sysmon 1 supplies process image, parent, PID, username, optional SHA256 and original event time. A `System32\wsmprovhost.exe` parent marks WinRM-associated execution; it does not infer a remote source IP or establish maliciousness. General type-3 logons are never relabeled WinRM.
- Raw XML/messages, command lines, parent arguments, file contents and environment variables are excluded twice: by the PowerShell export allowlist and Python normalization.
- Configure `windows_eventlog.known_bad_sha256` as a map of reviewed lowercase SHA256 values to short indicator labels. Enable SHA256 in Sysmon's hash configuration. Only exact matches generate malware path/hash evidence eligible for quarantine; missing, unknown or ambiguous hashes do not establish malware. A match records the observed process image; the executor rechecks the file before any move.
- Linux `/proc`, Linux file polling and the legacy nftables IP-block endpoint remain disabled on Windows. Windows uses the platform-bound playbook workflow described below.

## Containment deployment

1. Install the Python agent source and its minimal runtime dependencies (`httpx`,
   `pydantic`) in an administrator-protected location. Windows quarantine also needs
   `pywin32`; the package declares the `windows` optional dependency. The assessment
   suite's Linux scanner image is not the Windows agent installation method.
2. Follow [quarantine setup](QUARANTINE.md) and [isolation setup](ISOLATION.md) for
   native privileges, private NTFS directories, ACLs, trusted helper installation
   and local recovery tasks. Set the installed helper's reviewed SHA256 in local
   policy. Keep all state, configuration, Python modules and helper files protected
   against modification by ordinary users.
3. Merge `control-plane-response.example.json` into the protection service's
   private configuration, replacing `windows-server-a` with the enrolled host ID.
   Both policies must explicitly specify `platform: windows`. Keep quarantine's
   exact file allowlist on the host and preserve independent local enforcement.
4. Review the isolation management exceptions: Windows accepts pinned `/32` or
   `/128` management hosts. TCP exceptions allow a configured port at either endpoint
   to preserve reply traffic. Use only trusted management hosts; this is not a
   stricter directional service-port policy. DNS/UDP is blocked. Provide a reviewed
   local hostname mapping or an IP-based TLS endpoint with a valid certificate so
   agent recovery does not depend on cached DNS.
5. Validate on disposable Windows hosts before setting `enabled: true`: exact hash
   match and changed-file rejection; reparse points, hardlinks and alternate streams;
   private vault permissions; no-overwrite restore; firewall policy conflicts;
   IPv4/IPv6 management reachability; expiry, service restart, reboot and manual
   release. Keep an independent administrator recovery path during the test.
6. Request a playbook against an alert, inspect its platform/evidence/expiry, and
   have a different administrator approve it. Check the execution receipt. A crash
   during execution reports an uncertain failure rather than repeating containment;
   a separately approved restore/release can recover from the local journal.

Quarantine preserves the file and does not terminate an already-running process.
Locked/busy files can be refused. Windows isolation expiry depends on Task Scheduler
and the local recovery helper; it is not a kernel TTL. No native Windows firewall
or production files were modified during the Linux-based automated tests.

References: [Microsoft logon event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [share-access event 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140), [Sysmon event documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
