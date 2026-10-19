"""Approved termination of one evidenced process (Linux).

The plan names the process by PID plus the identity the alert observed (procfs
start ticks when the agent saw it, otherwise the alert time). On the host the
agent opens a pidfd first, re-reads the identity through that PID, and signals
through the pidfd, so a PID recycled by an unrelated process is never killed.
Importing this module performs no process inspection or signalling.
"""
from __future__ import annotations

import os
import select
import signal
import time
from uuid import UUID

# Alert rules whose evidence carries a PID the analyst can act on.
TERMINATION_RULES = ("web_server_shell", "writable_directory_execution",
                     "deleted_executable", "malware_detected")
# Never terminated regardless of policy: init, the service manager and remote access.
ALWAYS_PROTECTED = frozenset({"/sbin/init", "/usr/sbin/init", "/lib/systemd/systemd",
                              "/usr/lib/systemd/systemd", "/usr/sbin/sshd", "/usr/bin/sshd",
                              "/usr/sbin/sshd-session", "/usr/lib/openssh/sshd-session"})
MAX_GRACE = 10
SKEW = 30


def _executable(value) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value or len(value) > 1024:
        raise ValueError("absolute executable path required")
    if any(part in (".", "..", "") for part in value.split("/")[1:]):
        raise ValueError("executable path must be normalized")
    return value


def protected_executables(config: dict) -> frozenset[str]:
    extra = config.get("protected_executables", [])
    if not isinstance(extra, list) or len(extra) > 256:
        raise ValueError("protected_executables must be a list")
    return ALWAYS_PROTECTED | {_executable(p) for p in extra}


def prepare_termination(config: dict, evidence: dict, request_id: str, now=None) -> dict:
    """Build the immutable plan from alert evidence; raises ValueError when policy forbids it."""
    pid = evidence.get("pid")
    if type(pid) is not int or not 2 <= pid <= 2147483647:
        raise ValueError("process evidence requires a PID")
    executable = _executable(evidence.get("executable") or evidence.get("path"))
    if executable in protected_executables(config):
        raise ValueError("executable is protected by local policy")
    start_ticks = evidence.get("start_ticks")
    if start_ticks is not None and (type(start_ticks) is not int or start_ticks < 0):
        raise ValueError("invalid process start ticks")
    observed_at = evidence.get("observed_at")
    if type(observed_at) is not int or observed_at <= 0:
        raise ValueError("observation time required")
    grace = config.get("grace_seconds", 2)
    if type(grace) is not int or not 0 <= grace <= MAX_GRACE:
        raise ValueError("grace_seconds must be 0..10")
    created = int(time.time() if now is None else now)
    return {"platform": "linux", "request_id": str(UUID(request_id)), "pid": pid,
            "executable": executable, "start_ticks": start_ticks, "observed_at": observed_at,
            "grace_seconds": grace, "created_at": created}


def _validate(config: dict, plan: dict, now=None) -> dict:
    if not isinstance(plan, dict) or type(plan.get("created_at")) is not int:
        raise ValueError("invalid termination plan")
    expected = prepare_termination(config, plan, plan["request_id"], plan["created_at"])
    if expected != {k: v for k, v in plan.items() if k not in ("reason", "expires_at")}:
        raise ValueError("termination plan differs from local policy")
    instant = time.time() if now is None else now
    if plan["created_at"] > instant + SKEW:
        raise ValueError("termination plan is in the future")
    return expected


class LinuxProcessNative:
    """Thin procfs/pidfd adapter; replaced by a fake in tests."""

    def __init__(self, proc_root: str = "/proc"):
        self.proc_root = proc_root
        self.clock_ticks = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

    def open(self, pid: int) -> int:
        if not hasattr(os, "pidfd_open"):
            raise OSError("pidfd_open unavailable")
        return os.pidfd_open(pid)  # ProcessLookupError when absent

    def identity(self, pid: int) -> dict:
        base = os.path.join(self.proc_root, str(pid))
        with open(os.path.join(base, "stat"), encoding="utf-8", errors="replace") as stream:
            fields = stream.read().rsplit(")", 1)[1].split()
        start_ticks = int(fields[19])
        executable = os.readlink(os.path.join(base, "exe"))
        deleted = executable.endswith(" (deleted)")
        executable = executable.removesuffix(" (deleted)")
        uid = None
        with open(os.path.join(base, "status"), encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if line.startswith("Uid:"):
                    uid = int(line.split()[2])  # effective uid
                    break
        boot = None
        with open(os.path.join(self.proc_root, "stat"), encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if line.startswith("btime "):
                    boot = int(line.split()[1])
                    break
        if uid is None or boot is None:
            raise OSError("incomplete process identity")
        return {"start_ticks": start_ticks, "executable": executable, "deleted": deleted,
                "uid": uid, "started_at": boot + start_ticks / self.clock_ticks}

    def send(self, fd: int, sig: int) -> None:
        signal.pidfd_send_signal(fd, sig)

    def wait(self, fd: int, timeout: float) -> bool:
        """True once the process has exited (a pidfd becomes readable on exit)."""
        readable, _, _ = select.select([fd], [], [], max(0.0, timeout))
        return bool(readable)

    def close(self, fd: int) -> None:
        os.close(fd)


def _absent(plan: dict) -> dict:
    return {"status": "failed", "detail": "process_absent", "platform": "linux",
            "request_id": plan["request_id"], "pid": plan["pid"], "executable": plan["executable"]}


def terminate_process(config: dict, plan: dict, *, native=None, now=None) -> dict:
    canonical = _validate(config, plan, now)
    pid = canonical["pid"]
    if pid in (1, os.getpid(), os.getppid()):
        raise ValueError("protected process")
    native = native or LinuxProcessNative()
    try:
        fd = native.open(pid)
    except ProcessLookupError:
        return _absent(canonical)
    try:
        try:
            identity = native.identity(pid)
        except (FileNotFoundError, ProcessLookupError):
            return _absent(canonical)
        # The pidfd pins the original process, so a different identity behind this
        # PID means the evidenced process already exited and the PID was recycled.
        if canonical["start_ticks"] is not None:
            if identity["start_ticks"] != canonical["start_ticks"]:
                return _absent(canonical)
        elif identity["started_at"] > canonical["observed_at"] + SKEW:
            return _absent(canonical)
        if identity["executable"] != canonical["executable"]:
            raise ValueError("running executable differs from the approved evidence")
        if identity["executable"] in protected_executables(config):
            raise ValueError("executable is protected by local policy")
        if identity["uid"] == 0 and config.get("allow_privileged") is not True:
            raise ValueError("terminating a privileged process requires allow_privileged")
        used = "SIGTERM"
        try:
            native.send(fd, signal.SIGTERM)
        except ProcessLookupError:
            return _absent(canonical)
        exited = native.wait(fd, canonical["grace_seconds"])
        if not exited:
            used = "SIGKILL"
            try:
                native.send(fd, signal.SIGKILL)
            except ProcessLookupError:
                exited = True
            else:
                exited = native.wait(fd, 2)
        if not exited:
            raise OSError("process did not exit after SIGKILL")
    finally:
        native.close(fd)
    return {"status": "applied", "detail": "process_terminated", "platform": "linux",
            "request_id": canonical["request_id"], "pid": pid,
            "executable": canonical["executable"], "start_ticks": identity["start_ticks"],
            "signal": used, "uid": identity["uid"]}
