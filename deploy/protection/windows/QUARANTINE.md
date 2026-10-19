# Windows file quarantine and restoration

Windows quarantine is an opt-in local containment action with a separately
approved restoration action. The agent moves one approved file into a protected
vault and records evidence and its original owner/group/DACL. The source file is
not deleted. This does not stop an already running process, inspect memory, or
isolate a Windows host from the network.

## Requirements and policy

- Install the versioned VulnSuite Windows extra, including the reviewed `pywin32` dependency. All Windows imports are lazy; Linux tests do not execute Win32 operations.
- Use a local NTFS volume. The original file and vault must be on the same drive and volume. Set up a separate vault on each approved volume as a separate policy/deployment; moving evidence across volumes is refused.
- Run under the dedicated service identity with access to read approved files and change their DACL/owner. `SeRestorePrivilege` is required to restore a recorded original owner. LocalSystem is one possible deployment identity; provision privileges through the organisation's service-account policy.
- Pre-create the vault with a protected DACL granting access only to the service SID, SYSTEM and Administrators, with a trusted owner. For a LocalSystem deployment, an administrator can use the example below on a new empty vault. Do not use a folder containing other data.
- Configure exact absolute `allowed_paths`, not directory globs. Add your agent installation/configuration and other organisation-specific critical files/directories to `protected_paths`. Windows, Program Files, boot/recovery/system-volume directories, Microsoft ProgramData, drive-root files and the vault itself are denied automatically.
- Both service-side approval and the agent's local `response_policy` must allow the action. The accepted malware evidence must identify the file and its exact SHA256. A generic process alert alone is insufficient evidence for a file move.

```powershell
# Example only: create a NEW local vault for a LocalSystem service.
$vault = 'C:\SecurityVault'
if (Test-Path -LiteralPath $vault) { throw 'Choose a new empty vault path' }
New-Item -ItemType Directory -Path $vault | Out-Null
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm('O:SYG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
Set-Acl -LiteralPath $vault -AclObject $acl
```

Agent policy example, merged into the existing private agent configuration:

```json
{
  "response_policy": {
    "enabled": false,
    "platform": "windows",
    "allowed_actions": ["quarantine_file", "restore_file"],
    "quarantine": {
      "quarantine_dir": "C:\\SecurityVault",
      "allowed_paths": ["C:\\Workloads\\uploads\\reviewed-suspect.bin"],
      "protected_paths": ["C:\\VulnSuite", "C:\\ProgramData\\VulnSuite"],
      "max_file_bytes": 104857600
    }
  }
}
```

Keep `enabled` false until the staging checks below pass for the intended service
identity and host configuration, then explicitly enable the reviewed local policy.

## Native behavior and recovery

- Local drive paths are validated before access. UNC paths, devices, mapped shares, alternate data streams, short-path aliases, ambiguous components, reparse points/junctions and hardlinked files are refused. All named streams are enumerated; files with streams beyond the default data stream are refused.
- Native handles pin directory ancestry against rename/deletion. Directory handles allow read/write sharing because Windows needs write access internally during a relative rename; source file handles allow reads and deny writes/deletes. Held child handles keep ancestors nonempty, and the destination handle is checked again for a reparse point immediately before the native relative rename. A post-open destination junction causes the tested relative operation to fail without redirecting the payload. Busy files or ancestors that cannot be opened safely fail closed. File identity, link count, size and SHA256 are checked against approved evidence.
- The file moves through `NtSetInformationFile` with `FileRenameInformation` using a pinned destination directory, with replacement disabled. There is no path-based rename fallback. Native completion status is checked; an unexpected pending result is awaited before its buffers are released. A protected manifest is flushed before mutation, and each subsequent immutable state record is flushed before atomic publication. An exclusive record lock prevents concurrent operations on one request.
- The quarantined file is owned by the service identity, has a private protected DACL, and has file execution explicitly denied. This does not revoke an existing process's memory mappings or terminate it. Administrators and SYSTEM remain trusted and can modify the host or vault.
- Restore verifies the original identity/hash and performs an atomic move with the restrictive quarantine ACL still in place, refusing an existing destination. It then restores the recorded owner/group/DACL under the original parent so inherited ACLs are evaluated in the correct directory. A failed rename leaves the private payload in the vault; failed ACL restoration keeps the verified file private at the original path with a durable restoring state for approved recovery. Existing destination data is never replaced.
- If a crash leaves a verified payload with only the `prepared` manifest, a separately approved restore can recover it. If a `prepared` record has no payload because the agent stopped after changing the original ACL but before the move, approved rollback pins the original path and verifies its exact file identity, single link and SHA256 before recording a durable restoring state and restoring the recorded owner/group/DACL in place. Missing, replaced or changed source files are refused without mutation. If a crash occurs after restoring the file but before the final manifest, retry verifies the original file and re-establishes its recorded security before acknowledging restoration.
- If evidence changes or cannot be verified, preserve the vault for administrator investigation. Do not delete manifests or rename payloads to bypass failed checks. Uncommitted private `.manifest-*.tmp` files may remain after a crash and do not count as committed state.

## Staging validation

The repository tests exercise orchestration with a mock native adapter, including
hash/identity refusal, overwrite prevention, ACL restoration, request replay and
crash recovery. They do not establish that a Windows host's native policy works.
A disposable Windows TEMP fixture exercised the relative native rename, required
directory sharing, and a post-open junction substitution attempt; the redirected
destination received no payload. That narrow primitive check does not validate
the complete privileged pywin32 ACL workflow or production deployment.

An optional [native contract diagnostic](../../../tests/protection/windows_quarantine_native_contract.ps1)
reproduces those narrow checks using only a new disposable directory under Windows
TEMP. From the repository root in Windows PowerShell, explicitly opt in with:

```powershell
.\tests\protection\windows_quarantine_native_contract.ps1 -RunDisposableProbe
```

The diagnostic creates test files and a temporary junction, checks native rename
and sharing behavior, and removes its own temporary objects. It changes no ACLs,
firewall rules or service policy. It does not exercise the complete quarantine
workflow or replace the staging checklist.

On disposable Windows NTFS infrastructure, validate all of the following before
enabling response on an organisation server:

- Valid approved quarantine and separately approved restore; byte-for-byte file hash, original owner/group/DACL, private vault ACL and no-overwrite behavior.
- Wrong hash, changed file, busy/writable file handles, hardlinks, file/ancestor junctions and symbolic links, alternate streams, untrusted vault ACL, cross-volume paths and critical-system path refusal.
- Agent termination immediately before/after each rename and manifest publication; verify recovery and durable receipts without repeated actions.
- Missing privilege/dependency failures and sharing violations. Confirm they return failed receipts and leave original/preserved evidence available for review.

Native contracts: [CreateFile sharing and reparse flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), [native handle-based rename](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile), [relative target sharing contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information), [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo), [security descriptor operations](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-operations).
