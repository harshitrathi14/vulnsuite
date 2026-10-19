# Reviewed Windows host isolation and release

Windows containment uses a fixed installed PowerShell helper and Windows Defender
Firewall. An analyst requests an isolation plan and a different administrator
approves it. The matching enrolled Windows agent independently verifies its local
policy before executing the plan. A separately approved release targets the original
job. No PowerShell commands, executable paths or firewall scripts come from alerts
or server plans.

## Local configuration

Merge the following into the Windows agent configuration, keeping disabled until
the staging checks below pass. Configure the control plane's host isolation policy
with the same platform, management hosts and ports. Native execution settings and
helper integrity are local controls.

```json
{
  "response_policy": {
    "enabled": false,
    "platform": "windows",
    "allowed_actions": ["isolate_host", "release_host"],
    "isolation": {
      "management_networks": ["10.10.0.5/32", "fd00::5/128"],
      "management_ports": [443, 3389],
      "state_dir": "C:\\ProgramData\\VulnSuite\\Isolation",
      "helper_sha256": "REPLACE_WITH_LOWERCASE_SHA256_OF_APPROVED_INSTALLED_HELPER"
    }
  }
}
```

- Management addresses must be pinned unicast IPv4 `/32` or IPv6 `/128` hosts.
  Broad subnets, loopback, link-local addresses and multicast are rejected.
- Install the agent package and its `windows_isolation_helper.ps1` under a trusted,
  administrator-managed directory. The helper path is fixed relative to the Python
  module. The configured digest must match that installed helper exactly. Do not
  install it in a user-writable checkout or temporary directory.
- Pre-create the state directory on NTFS. Its owner and writable access must be
  restricted to SYSTEM and Administrators; installer-owned protected ancestors are
  supported. The helper checks owners, write rights and reparse points throughout
  the path, including the installed helper. It refuses UNC, device, alternate-data
  stream and ambiguous path forms. State records and scheduled tasks are operational
  recovery material; keep them through agent upgrades.
- The service needs an elevated Windows administrator context. Windows PowerShell,
  the NetSecurity and ScheduledTasks modules, Defender Firewall, Base Filtering
  Engine and Task Scheduler must be available. The implementation does not change
  service startup settings, disable Group Policy or bypass PowerShell execution
  policy. If organisational policy requires signed scripts, sign the reviewed helper
  and record the digest of the signed installed file.
- Compute the pin during the trusted release process:

```powershell
(Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\Program Files\VulnSuite\vulnsuite\protection\windows_isolation_helper.ps1').Hash.ToLowerInvariant()
```

Updating the helper requires updating the approved local pin. Keep the state path
and installed helper available until outstanding isolation jobs are released.

## Effective firewall policy

Windows explicit block rules override conflicting allow rules. The helper therefore
does **not** install a block-all rule and expect management allows to override it.

- TCP connections to addresses outside the pinned management hosts are blocked in
  both directions, including IPv4 and IPv6. Complement ranges exclude loopback.
- For pinned management hosts, TCP is excepted when **either the local or remote
  endpoint port** is in `management_ports`. A block matches only when both ports are
  outside that set. This deliberately preserves management replies without assuming
  undocumented flow-reclassification behavior. It is not a stricter directional
  destination-port restriction: a process binding local port 443 can reach other
  TCP ports on a pinned management host. Restrict the list to dedicated trusted
  management hosts and enforce authentication/access controls on those hosts.
- Other IP protocol numbers, including UDP, are blocked to non-loopback peers.
  The protocol rules are explicit, avoiding a broad block that could swallow a
  management or IPv6 discovery exception.
- IPv4 destination-unreachable messages and IPv6 packet-too-big messages remain
  available for connectivity error handling and path MTU. IPv6 router/neighbor
  discovery types 133–136 are permitted only for link-local, link-local multicast,
  unspecified DAD or pinned IPv6 management addresses. Echo traffic and other ICMP
  types are blocked. These limited control-message exceptions are intentional.
- DNS, DHCP, NTP and other UDP services are not exceptioned. Use a reviewed static
  hostname mapping or an IP-address control-plane URL whose TLS certificate matches
  that IP. Validate a fresh connection without relying on a DNS cache, and use a
  network configuration that does not need lease/address refresh during isolation.
- All Windows Firewall profiles and interfaces must participate. The helper refuses
  disabled/excluded firewall interfaces, disabled rule merging, shields-up policy,
  existing enabled explicit block rules and authenticated-bypass policies. Existing
  block rules are conservatively treated as unsupported instead of being removed or
  overwritten. A managed endpoint whose Group Policy does not permit local rules
  needs an organisation-specific enforcement integration.
- The current implementation creates 526 individually owned local rules because
  the native protocol field accepts discrete protocol numbers. Rule-creation cost
  must be measured in staging. This is host firewall containment; Hyper-V guests,
  separate network compartments, third-party WFP providers, bridges or offloaded
  traffic need explicit deployment evaluation.

The helper checks the ActiveStore enforcement status, rule count, names, protocol,
action, direction, address/port/ICMP filters, profiles and interface scope before
reporting success. Unsupported or unverifiable policy produces a failed receipt.
It never claims a successful local rule write alone proves packet isolation.

## Independent deadline, recovery and limits

- Plans have an immutable 60–3,600 second lifetime. Approval and setup consume that
  time. A new installation is rejected if less than 30 seconds remain before native
  preparation; every rule addition checks the original deadline.
- Before the first firewall rule is written, the helper persists a private recovery
  manifest and registers a SYSTEM task with the original expiry and a startup
  trigger. It starts an independent watchdog and waits for its fresh heartbeat.
  Task identity, action, triggers and settings must verify before enforcement starts.
- The watchdog runs independently of the agent and network connection. The task
  starts missed work when available, retries failures, and supports startup recovery.
  An administrator/SYSTEM-only mutex prevents concurrent apply/release operations;
  the apply loop checks expiry so a release cannot be followed by late rule writes.
- An applied-job retry verifies existing rules and the original task; it does not
  register a new deadline or extend the isolation. An interrupted partial application
  is released and fails visibly rather than continuing silently.
- Any setup or verification failure attempts removal of that job's rules. Failed
  rollback remains a failure and retains recovery state/task for retry. Release
  verifies both the local policy collection and the effective ActiveStore before
  reporting `isolation_released`; it does not delete unrelated firewall rules.
- The agent also calls local expiry cleanup before networking, including when new
  response actions have been disabled. Preserve the local state directory and helper
  configuration so cleanup remains possible.

**Windows expiry is a scheduled-task/watchdog mechanism, not a kernel rule TTL.**
If Task Scheduler, the watchdog, the firewall provider or the operating system is
unavailable or disabled, removal can be late. Reboot startup recovery can also be
delayed. An administrator or attacker with sufficient privileges can stop or alter
these services. The implementation cannot guarantee a hard deadline during those
failures; deploy only after validating recovery and an out-of-band administrative
path. Do not describe this mechanism as equivalent to Linux nftables timeout sets.

## Required Windows staging checks

- Use a disposable Windows VM with out-of-band console access and representative
  Defender Firewall/GPO settings. Verify service state, local policy merge, helper
  signature/pin, ACLs, task principal and effective filters. Confirm unsupported
  preflight conditions leave no isolation rules behind.
- Verify pinned management traffic and blocked traffic independently for both
  IPv4 and IPv6, inbound and outbound, new and existing flows. Include RDP or WinRM
  as configured, non-management hosts, remote ports outside policy, UDP, loopback,
  IPv6 discovery and MTU behavior. Test a new agent connection without cached DNS.
- Stop the polling agent after isolation. Confirm the independent watchdog releases
  at the original deadline, then test service interruption, task restart, clock
  changes and reboot recovery. Record actual release latency and remaining rules.
- Interrupt rule installation midway, lose the control-plane connection, retry an
  identical job, alter a managed rule, disable local rule merging, and exercise a
  separately approved release. Confirm partial failures are cleaned and never
  reported as successful enforcement.
- Recheck third-party endpoint/firewall providers, existing IPsec policies and
  virtual networking. Measure setup time and CPU impact of the rule set before
  choosing a duration. Maintain an approved local recovery runbook.

Automated tests check complement mathematics, block/allow non-overlap, management
scope, helper invocation/pinning, immutable expiry, and PowerShell orchestration
using an in-memory firewall fixture. Parser checks do not execute the production
entry point. These tests do not establish live Windows packet filtering or reliable
deadline execution on a deployed host. No live Windows firewall was modified during
repository implementation.

Microsoft references:

- [Windows Firewall rule precedence and local policy merge](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules).
- [Rule address, protocol, port and ICMP filters](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule).
- [Local policy modification states](https://learn.microsoft.com/en-us/windows/win32/api/icftypes/ne-icftypes-net_fw_modify_state).
- [Effective firewall rule enforcement status](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallrule).
- [Scheduled task triggers](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger).
- [Scheduled task registration](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask).
