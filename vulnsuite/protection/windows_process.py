"""Approved termination of one evidenced process (Windows).

Windows telemetry carries no start ticks, so identity is the image path plus a
creation time no later than the alert that evidenced it: a PID recycled after
the alert is refused. The process handle is opened once and used for the image
query, the creation-time query, the termination and the exit wait, so the same
object is inspected and signalled. No Windows API is called on import.
"""
from __future__ import annotations

import os
import time
from uuid import UUID

from .windows_quarantine import local_path

ALWAYS_PROTECTED = frozenset(p.lower() for p in (
    r"C:\Windows\System32\wininit.exe", r"C:\Windows\System32\csrss.exe",
    r"C:\Windows\System32\smss.exe", r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\lsass.exe", r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\TermService.exe"))
MAX_GRACE = 10
SKEW = 30
_PROCESS_TERMINATE = 0x0001
_SYNCHRONIZE = 0x00100000
_QUERY_LIMITED = 0x1000
_WAIT_OBJECT_0 = 0
_ERROR_INVALID_PARAMETER = 87
_ERROR_ACCESS_DENIED = 5
_FILETIME_EPOCH = 116444736000000000


class WindowsProcessError(OSError):
    """Sanitised native failure safe for audit storage."""


def protected_executables(config: dict) -> frozenset[str]:
    extra = config.get("protected_executables", [])
    if not isinstance(extra, list) or len(extra) > 256:
        raise ValueError("protected_executables must be a list")
    return ALWAYS_PROTECTED | {local_path(p).lower() for p in extra}


def prepare_windows_termination(config: dict, evidence: dict, request_id: str, now=None) -> dict:
    pid = evidence.get("pid")
    if type(pid) is not int or not 5 <= pid <= 2147483647:
        raise ValueError("process evidence requires a PID")
    executable = local_path(evidence.get("executable") or evidence.get("path"))
    if executable.lower() in protected_executables(config):
        raise ValueError("executable is protected by local policy")
    observed_at = evidence.get("observed_at")
    if type(observed_at) is not int or observed_at <= 0:
        raise ValueError("observation time required")
    grace = config.get("grace_seconds", 2)
    if type(grace) is not int or not 0 <= grace <= MAX_GRACE:
        raise ValueError("grace_seconds must be 0..10")
    created = int(time.time() if now is None else now)
    return {"platform": "windows", "request_id": str(UUID(request_id)), "pid": pid,
            "executable": executable, "observed_at": observed_at, "grace_seconds": grace,
            "created_at": created}


def _validate(config: dict, plan: dict, now=None) -> dict:
    if not isinstance(plan, dict) or type(plan.get("created_at")) is not int:
        raise ValueError("invalid termination plan")
    expected = prepare_windows_termination(config, plan, plan["request_id"], plan["created_at"])
    if expected != {k: v for k, v in plan.items() if k not in ("reason", "expires_at")}:
        raise ValueError("termination plan differs from local policy")
    instant = time.time() if now is None else now
    if plan["created_at"] > instant + SKEW:
        raise ValueError("termination plan is in the future")
    return expected


class WindowsProcessNative:
    """kernel32 adapter; constructed only on a Windows host, replaced by a fake in tests."""

    def __init__(self):
        if os.name != "nt":
            raise ValueError("Windows process response requires a Windows host")
        import ctypes
        from ctypes import wintypes
        self.ctypes, self.wintypes = ctypes, wintypes
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def open(self, pid: int):
        handle = self.kernel32.OpenProcess(_PROCESS_TERMINATE | _SYNCHRONIZE | _QUERY_LIMITED, False, pid)
        if not handle:
            code = self.ctypes.get_last_error()
            if code == _ERROR_INVALID_PARAMETER:
                raise ProcessLookupError(pid)
            raise WindowsProcessError("access_denied" if code == _ERROR_ACCESS_DENIED else "execution_failed")
        return handle

    def identity(self, handle) -> dict:
        ctypes, wintypes = self.ctypes, self.wintypes
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not self.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise WindowsProcessError("execution_failed")
        times = [wintypes.FILETIME() for _ in range(4)]
        if not self.kernel32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
            raise WindowsProcessError("execution_failed")
        creation = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        started_at = (creation - _FILETIME_EPOCH) / 10_000_000
        return {"executable": buffer.value[:size.value], "started_at": started_at}

    def terminate(self, handle) -> None:
        if not self.kernel32.TerminateProcess(handle, 1):
            code = self.ctypes.get_last_error()
            if code == _ERROR_ACCESS_DENIED:
                raise WindowsProcessError("access_denied")
            raise WindowsProcessError("execution_failed")

    def wait(self, handle, timeout: float) -> bool:
        return self.kernel32.WaitForSingleObject(handle, int(max(0.0, timeout) * 1000)) == _WAIT_OBJECT_0

    def close(self, handle) -> None:
        self.kernel32.CloseHandle(handle)


def _absent(plan: dict) -> dict:
    return {"status": "failed", "detail": "process_absent", "platform": "windows",
            "request_id": plan["request_id"], "pid": plan["pid"], "executable": plan["executable"]}


def terminate_windows_process(config: dict, plan: dict, *, native=None, now=None) -> dict:
    canonical = _validate(config, plan, now)
    pid = canonical["pid"]
    if pid == os.getpid():
        raise ValueError("protected process")
    native = native or WindowsProcessNative()
    try:
        handle = native.open(pid)
    except ProcessLookupError:
        return _absent(canonical)
    try:
        identity = native.identity(handle)
        # A process created after the alert cannot be the one the alert evidenced.
        if identity["started_at"] > canonical["observed_at"] + SKEW:
            return _absent(canonical)
        if identity["executable"].lower() != canonical["executable"].lower():
            raise ValueError("running image differs from the approved evidence")
        if identity["executable"].lower() in protected_executables(config):
            raise ValueError("executable is protected by local policy")
        if native.wait(handle, 0):
            return _absent(canonical)
        native.terminate(handle)
        if not native.wait(handle, canonical["grace_seconds"] + 2):
            raise WindowsProcessError("process did not exit")
    finally:
        native.close(handle)
    return {"status": "applied", "detail": "process_terminated", "platform": "windows",
            "request_id": canonical["request_id"], "pid": pid,
            "executable": canonical["executable"], "signal": "TerminateProcess"}
