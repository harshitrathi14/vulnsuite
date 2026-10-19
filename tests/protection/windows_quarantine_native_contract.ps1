# Manual native contract probe. Never loaded by the ordinary Python test suite.
# Creates only a new GUID-named directory in Windows TEMP, changes no ACLs or
# firewall/task policy, and deletes only the objects created under that directory.
[CmdletBinding()]
param([switch]$RunDisposableProbe)

if (-not $RunDisposableProbe) { throw 'Pass -RunDisposableProbe to run the isolated TEMP-only fixture.' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class VulnSuiteNativeContractResult {
    public string Case;
    public uint DirectoryShare;
    public bool DeleteOpenDenied;
    public bool AttributeWriteOpenAllowed;
    public bool JunctionEstablished;
    public bool RenameSucceeded;
    public string NtStatus;
    public int Win32Error;
    public bool PayloadAtExpectedLocation;
    public bool PayloadRedirected;
    public bool SourcePreserved;
    public bool FixtureCleaned;
}

public static class VulnSuiteNativeContractProbe {
    const uint DirectoryAccess = 0x00020081; // LIST_DIRECTORY | READ_ATTRIBUTES | READ_CONTROL
    const uint SourceAccess = 0x800f0000; // GENERIC_READ | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER
    const uint OpenFlags = 0x02200000; // OPEN_REPARSE_POINT | BACKUP_SEMANTICS
    const string Content = "VulnSuite disposable native contract fixture";

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle file, int kind, IntPtr data, uint size);
    [DllImport("ntdll.dll")]
    static extern uint NtSetInformationFile(SafeFileHandle file, IntPtr io, IntPtr data, uint size, int kind);
    [DllImport("ntdll.dll")]
    static extern uint RtlNtStatusToDosError(uint status);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(SafeFileHandle file, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DeviceIoControl(SafeFileHandle file, uint code, byte[] input, uint inputSize,
        IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);

    static SafeFileHandle Open(string path, uint access, uint share) {
        SafeFileHandle handle = CreateFile(path, access, share, IntPtr.Zero, 3, OpenFlags, IntPtr.Zero);
        if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new IOException("Fixture open failed: " + error); }
        return handle;
    }

    static void Rename(SafeFileHandle source, SafeFileHandle directory, string target,
                       bool native, bool absolute, VulnSuiteNativeContractResult result) {
        byte[] name = System.Text.Encoding.Unicode.GetBytes(target);
        int rootOffset = IntPtr.Size == 8 ? 8 : 4;
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + 4;
        // Match WindowsNative.rename's aligned variable ctypes structure plus 8
        // bytes of fixed-header padding, and its two-pointer-sized IO_STATUS_BLOCK.
        int size = ((nameOffset + name.Length + 2 + IntPtr.Size - 1) / IntPtr.Size) * IntPtr.Size + 8;
        IntPtr data = Marshal.AllocHGlobal(size), io = Marshal.AllocHGlobal(IntPtr.Size * 2);
        try {
            Marshal.Copy(new byte[size], 0, data, size); // ReplaceIfExists = false
            Marshal.Copy(new byte[IntPtr.Size * 2], 0, io, IntPtr.Size * 2);
            Marshal.WriteIntPtr(data, rootOffset, absolute ? IntPtr.Zero : directory.DangerousGetHandle());
            Marshal.WriteInt32(data, lengthOffset, name.Length);
            Marshal.Copy(name, 0, IntPtr.Add(data, nameOffset), name.Length);
            if (native) {
                uint status = NtSetInformationFile(source, io, data, (uint)size, 10);
                if (status == 0x103) {
                    if (WaitForSingleObject(source, 0xffffffff) != 0)
                        throw new IOException("Synchronous fixture rename completion could not be established");
                    status = unchecked((uint)Marshal.ReadInt32(io));
                } else if (status == 0) { status = unchecked((uint)Marshal.ReadInt32(io)); }
                result.NtStatus = "0x" + status.ToString("x8");
                result.RenameSucceeded = status == 0;
                result.Win32Error = status == 0 ? 0 : (int)RtlNtStatusToDosError(status);
            } else {
                result.RenameSucceeded = SetFileInformationByHandle(source, 3, data, (uint)size);
                result.Win32Error = result.RenameSucceeded ? 0 : Marshal.GetLastWin32Error();
            }
        } finally { Marshal.FreeHGlobal(data); Marshal.FreeHGlobal(io); }
    }

    static void U16(byte[] buffer, int offset, int value) {
        Array.Copy(BitConverter.GetBytes((ushort)value), 0, buffer, offset, 2);
    }

    static void SetJunction(SafeFileHandle directory, string target) {
        byte[] substitute = System.Text.Encoding.Unicode.GetBytes(@"\??\" + target);
        byte[] print = System.Text.Encoding.Unicode.GetBytes(target);
        byte[] data = new byte[16 + substitute.Length + 2 + print.Length + 2];
        Array.Copy(BitConverter.GetBytes((uint)0xa0000003), 0, data, 0, 4);
        U16(data, 4, data.Length - 8); U16(data, 8, 0); U16(data, 10, substitute.Length);
        U16(data, 12, substitute.Length + 2); U16(data, 14, print.Length);
        Array.Copy(substitute, 0, data, 16, substitute.Length);
        Array.Copy(print, 0, data, 16 + substitute.Length + 2, print.Length);
        uint returned;
        if (!DeviceIoControl(directory, 0x900a4, data, (uint)data.Length, IntPtr.Zero, 0, out returned, IntPtr.Zero))
            throw new IOException("Fixture junction creation failed: " + Marshal.GetLastWin32Error());
    }

    static void DeleteJunction(SafeFileHandle directory) {
        byte[] data = new byte[8]; uint returned;
        Array.Copy(BitConverter.GetBytes((uint)0xa0000003), 0, data, 0, 4);
        if (!DeviceIoControl(directory, 0x900ac, data, 8, IntPtr.Zero, 0, out returned, IntPtr.Zero))
            throw new IOException("Fixture junction cleanup failed: " + Marshal.GetLastWin32Error());
    }

    public static VulnSuiteNativeContractResult[] Run() {
        string root = Path.Combine(Path.GetTempPath(), "vulnsuite-native-contract-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var results = new List<VulnSuiteNativeContractResult>();
        try {
            foreach (uint share in new uint[] { 1, 3 }) {
                foreach (string mode in new string[] { "win32-relative", "win32-absolute", "nt-relative" }) {
                    string directory = Path.Combine(root, "case-" + share + "-" + mode);
                    string destination = Path.Combine(directory, "destination"), source = Path.Combine(directory, "source.bin");
                    Directory.CreateDirectory(destination); File.WriteAllText(source, Content);
                    var result = new VulnSuiteNativeContractResult { Case = mode, DirectoryShare = share };
                    using (SafeFileHandle target = Open(destination, DirectoryAccess, share)) {
                        using (SafeFileHandle probe = CreateFile(destination, 0x10000, 7, IntPtr.Zero, 3, OpenFlags, IntPtr.Zero))
                            result.DeleteOpenDenied = probe.IsInvalid && Marshal.GetLastWin32Error() == 32;
                        using (SafeFileHandle probe = CreateFile(destination, 0x100, 7, IntPtr.Zero, 3, OpenFlags, IntPtr.Zero))
                            result.AttributeWriteOpenAllowed = !probe.IsInvalid;
                        using (SafeFileHandle file = Open(source, SourceAccess, 1))
                            Rename(file, target, mode == "win32-absolute" ? Path.Combine(destination, "payload") : "payload",
                                   mode == "nt-relative", mode == "win32-absolute", result);
                        result.PayloadAtExpectedLocation = File.Exists(Path.Combine(destination, "payload"));
                        result.SourcePreserved = File.Exists(source) && File.ReadAllText(source) == Content;
                    }
                    results.Add(result);
                }
            }

            string junctionDirectory = Path.Combine(root, "junction-case");
            string pinned = Path.Combine(junctionDirectory, "pinned"), redirected = Path.Combine(junctionDirectory, "redirected");
            string original = Path.Combine(junctionDirectory, "source.bin");
            Directory.CreateDirectory(pinned); Directory.CreateDirectory(redirected); File.WriteAllText(original, Content);
            var junctionResult = new VulnSuiteNativeContractResult { Case = "nt-relative-after-junction", DirectoryShare = 3 };
            using (SafeFileHandle target = Open(pinned, DirectoryAccess, 3))
            using (SafeFileHandle changer = Open(pinned, 0x40000000, 3)) {
                bool junction = false;
                try {
                    SetJunction(changer, redirected); junction = true; junctionResult.JunctionEstablished = true;
                    using (SafeFileHandle file = Open(original, SourceAccess, 1))
                        Rename(file, target, "payload", true, false, junctionResult);
                    junctionResult.PayloadRedirected = File.Exists(Path.Combine(redirected, "payload"));
                    junctionResult.SourcePreserved = File.Exists(original) && File.ReadAllText(original) == Content;
                } finally { if (junction) DeleteJunction(changer); }
            }
            results.Add(junctionResult);
        } finally { Directory.Delete(root, true); }
        foreach (var result in results) result.FixtureCleaned = true;
        return results.ToArray();
    }
}
'@

$results = @([VulnSuiteNativeContractProbe]::Run())
$version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$failures = @($results | Where-Object {
    ($_.Case -eq 'nt-relative' -and $_.DirectoryShare -eq 3 -and -not $_.RenameSucceeded) -or
    ($_.Case -eq 'nt-relative' -and $_.DirectoryShare -eq 1 -and $_.RenameSucceeded) -or
    ($_.Case -ne 'nt-relative-after-junction' -and -not $_.DeleteOpenDenied) -or
    ($_.Case -eq 'nt-relative-after-junction' -and ($_.RenameSucceeded -or $_.PayloadRedirected -or -not $_.SourcePreserved)) -or
    -not $_.FixtureCleaned
})
[ordered]@{
    checked_at_utc = [DateTime]::UtcNow.ToString('o')
    scope = 'Disposable Windows TEMP handles, relative rename and junction-race contract only; no ACL, quarantine deployment, firewall or task changes.'
    powershell_version = $PSVersionTable.PSVersion.ToString()
    os_version = [Environment]::OSVersion.Version.ToString()
    windows_build = [string]$version.CurrentBuildNumber + '.' + [string]$version.UBR
    display_version = [string]$version.DisplayVersion
    process_bits = [IntPtr]::Size * 8
    directory_access = '0x00020081: FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL'
    source_access = '0x800f0000: GENERIC_READ | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER; FILE_SHARE_READ'
    rename_buffer = 'Aligned BOOLEAN, HANDLE, DWORD byte length, UTF-16 filename including spare NUL, plus 8 padding bytes; pointer-sized IO_STATUS_BLOCK union and Information'
    native_call = 'NtSetInformationFile(FileRenameInformation=10, RootDirectory=pinned directory, ReplaceIfExists=false)'
    passed = $failures.Count -eq 0
    results = $results
} | ConvertTo-Json -Depth 6
if ($failures.Count -ne 0) { exit 1 }
