"""Opt-in local containment: hash-checked file moves and expiring nft isolation.

These functions must run on the enrolled host after an approved command is fetched.
They never accept shell commands or firewall scripts from the control plane.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import PurePosixPath
import re
import stat
import subprocess
import time
from uuid import UUID, uuid4


def _path(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise ValueError("absolute local path required")
    if any(part in (".", "..", "") for part in value.split("/")[1:]):
        raise ValueError("path must be normalized")
    return value


def _open_dir(value: str) -> int:
    """Pin every path component; never resolve symlinks."""
    _path(value)
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in PurePosixPath(value).parts[1:]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=current)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def _parent(value: str):
    parsed = PurePosixPath(_path(value))
    # A file directly under / is never an eligible quarantine target.
    if str(parsed.parent) == "/":
        raise ValueError("root directory targets are prohibited")
    return _open_dir(str(parsed.parent)), parsed.name


def _rename_noreplace(srcfd, src, dstfd, dst):
    # Atomic no-clobber rename, same-filesystem only. Never copy-and-delete on EXDEV.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise OSError(errno.ENOSYS, "renameat2 required")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                       ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(srcfd, os.fsencode(src), dstfd, os.fsencode(dst), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _hash(fd: int, max_bytes: int) -> str:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > max_bytes:
        raise ValueError("regular file with one link and permitted size required")
    os.lseek(fd, 0, os.SEEK_SET)
    digest, size = hashlib.sha256(), 0
    while chunk := os.read(fd, 1024 * 1024):
        size += len(chunk)
        if size > max_bytes:
            raise ValueError("file size limit exceeded")
        digest.update(chunk)
    after = os.fstat(fd)
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("file changed during verification")
    return digest.hexdigest()


def _write_manifest(fd: int, data: dict):
    name = ".manifest-" + uuid4().hex
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                  dir_fd=fd)
    try:
        with os.fdopen(out, "w") as stream:
            json.dump(data, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, "manifest.json", src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass


class Quarantine:
    """Move an explicitly allowlisted file into a private same-filesystem vault.

    Config: quarantine_dir (existing, owner-only directory), allowed_paths (exact
    paths), max_file_bytes (default 100 MiB). Payload contents are never deleted.
    """

    def __init__(self, config: dict):
        self.directory = _path(config["quarantine_dir"])
        self.allowed = {_path(p) for p in config.get("allowed_paths", [])}
        if not self.allowed:
            raise ValueError("explicit allowed_paths required")
        self.max_bytes = int(config.get("max_file_bytes", 100 * 1024 * 1024))
        if not 1 <= self.max_bytes <= 1024 * 1024 * 1024:
            raise ValueError("invalid maximum file size")
        if any(p == self.directory or p.startswith(self.directory + "/") for p in self.allowed):
            raise ValueError("quarantine vault cannot be a target")

    def _record(self, identifier: str, create=False):
        identifier = str(UUID(identifier))
        root = _open_dir(self.directory)
        try:
            info = os.fstat(root)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("quarantine directory must be owned by executor with mode 0700")
            if create:
                try:
                    os.mkdir(identifier, 0o700, dir_fd=root)
                    os.fsync(root)
                except FileExistsError:
                    pass
            folder = os.open(identifier, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=root)
            info = os.fstat(folder)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                os.close(folder)
                raise ValueError("unsafe quarantine record")
            return folder
        finally:
            os.close(root)

    @staticmethod
    def _read(fd):
        try:
            source = os.open("manifest.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=fd)
        except FileNotFoundError:
            return None
        with os.fdopen(source) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 16384 or info.st_nlink != 1:
                raise ValueError("invalid quarantine manifest")
            return json.loads(stream.read(16384))

    def quarantine(self, path: str, sha256: str, request_id: str) -> dict:
        path, request_id = _path(path), str(UUID(request_id))
        if path not in self.allowed or not re.fullmatch(r"[a-f0-9]{64}", sha256):
            raise ValueError("target or hash outside policy")
        folder = self._record(request_id, create=True)
        parent = None
        try:
            manifest = self._read(folder)
            if manifest and (manifest.get("path") != path or manifest.get("sha256") != sha256):
                raise ValueError("request identifier reused with different evidence")
            if manifest and manifest.get("state") == "restored":
                raise ValueError("quarantine already restored")
            # Recover a completed move after a worker/process crash.
            try:
                payload = os.open("payload", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                  dir_fd=folder)
            except FileNotFoundError:
                payload = None
            if payload is not None:
                try:
                    if not manifest or _hash(payload, self.max_bytes) != sha256:
                        raise ValueError("quarantined evidence mismatch")
                    os.fchmod(payload, 0o400)
                finally:
                    os.close(payload)
                manifest["state"] = "quarantined"
                _write_manifest(folder, manifest)
                return self._receipt(manifest)
            parent, name = _parent(path)
            source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                original = os.fstat(source)
                if _hash(source, self.max_bytes) != sha256:
                    raise ValueError("source hash differs from approved evidence")
                manifest = {"request_id": request_id, "path": path, "sha256": sha256,
                            "mode": stat.S_IMODE(original.st_mode) & 0o777,
                            "device": original.st_dev, "inode": original.st_ino,
                            "state": "prepared", "created_at": int(time.time())}
                _write_manifest(folder, manifest)
                _rename_noreplace(parent, name, folder, "payload")
                moved = os.stat("payload", dir_fd=folder, follow_symlinks=False)
                if (original.st_dev, original.st_ino) != (moved.st_dev, moved.st_ino):
                    # Preserve the substituted object and try to put it back without
                    # overwriting any path. The original descriptor is never modified.
                    try:
                        _rename_noreplace(folder, "payload", parent, name)
                    finally:
                        raise ValueError("source replaced during quarantine")
                os.fchmod(source, 0o400)
                os.fsync(source)
                os.fsync(parent)
                os.fsync(folder)
                if _hash(source, self.max_bytes) != sha256:
                    manifest["state"] = "evidence_changed"
                    _write_manifest(folder, manifest)
                    raise ValueError("evidence changed; preserved in vault for manual review")
            finally:
                os.close(source)
            manifest["state"] = "quarantined"
            _write_manifest(folder, manifest)
            return self._receipt(manifest)
        finally:
            if parent is not None:
                os.close(parent)
            os.close(folder)

    def restore(self, request_id: str) -> dict:
        folder, parent = self._record(request_id), None
        try:
            manifest = self._read(folder)
            if not manifest or manifest.get("path") not in self.allowed:
                raise ValueError("restore target outside current policy")
            parent, name = _parent(manifest["path"])
            if manifest.get("state") == "restored":
                return self._receipt(manifest)
            if manifest.get("state") not in ("prepared", "quarantined"):
                raise ValueError("record requires manual review")
            # Payloads are readable only by the executor, inside the owner-only vault.
            # Never follow symlinks while verifying retained evidence.
            try:
                payload = os.open("payload", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                  dir_fd=folder)
            except FileNotFoundError:
                # A crash after rename but before manifest persistence must not
                # repeat a move or overwrite the restored file.
                restored = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                   dir_fd=parent)
                try:
                    info = os.fstat(restored)
                    if ((info.st_dev, info.st_ino) != (manifest["device"], manifest["inode"])
                            or _hash(restored, self.max_bytes) != manifest["sha256"]):
                        raise ValueError("missing quarantine payload")
                finally:
                    os.close(restored)
                manifest["state"], manifest["restored_at"] = "restored", int(time.time())
                _write_manifest(folder, manifest)
                return self._receipt(manifest)
            try:
                if _hash(payload, self.max_bytes) != manifest["sha256"]:
                    raise ValueError("quarantine hash mismatch")
                os.fchmod(payload, manifest["mode"])
                try:
                    _rename_noreplace(folder, "payload", parent, name)
                except BaseException:
                    os.fchmod(payload, 0o400)
                    raise
                os.fsync(parent)
                os.fsync(folder)
            finally:
                os.close(payload)
            manifest["state"], manifest["restored_at"] = "restored", int(time.time())
            _write_manifest(folder, manifest)
            return self._receipt(manifest)
        finally:
            if parent is not None:
                os.close(parent)
            os.close(folder)

    @staticmethod
    def _receipt(manifest):
        return {"status": "rolled_back" if manifest["state"] == "restored" else "applied",
                "detail": manifest["state"], "request_id": manifest["request_id"],
                "path": manifest["path"], "sha256": manifest["sha256"]}


def prepare_isolation(config: dict, duration: int, request_id: str, now=None) -> dict:
    if type(duration) is not int or not 60 <= duration <= 3600:
        raise ValueError("duration must be 60..3600 seconds")
    management = [str(ipaddress.ip_network(n, strict=True))
                  for n in config.get("management_networks", [])]
    # Mandatory explicit control-plane/SSH reachability; /0 defeats isolation.
    if not management or any(ipaddress.ip_network(n).prefixlen == 0 for n in management):
        raise ValueError("explicit management networks required")
    ports = config.get("management_ports", [22, 443])
    if not ports or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError("invalid management ports")
    created = int(time.time() if now is None else now)
    return {"request_id": str(UUID(request_id)), "created_at": created,
            "expires_at": created + duration, "management_networks": sorted(management),
            "management_ports": sorted(set(ports))}


def isolation_script(config: dict, plan: dict, now=None) -> str:
    """Render fixed nft syntax; a kernel timeout removes the drop predicate."""
    expected = prepare_isolation(config, plan["expires_at"] - plan["created_at"],
                                 plan["request_id"], plan["created_at"])
    if plan.get('platform','linux')!='linux' or expected != {k: v for k, v in plan.items() if k not in ("reason", "platform", "automatic")}:
        raise ValueError("isolation plan differs from local policy")
    instant = time.time() if now is None else now
    seconds = int(plan["expires_at"] - instant)
    if not 1 <= seconds <= 3600 or plan["created_at"] > instant + 30:
        raise ValueError("isolation plan expired or invalid")
    table = "vsi_" + UUID(plan["request_id"]).hex
    ports = ", ".join(str(p) for p in plan["management_ports"])
    lines = [f"table inet {table} {{",
             "set gate4 { type ipv4_addr; flags interval,timeout; "
             f"elements = {{ 0.0.0.0/0 timeout {seconds}s }}; }}",
             "set gate6 { type ipv6_addr; flags interval,timeout; "
             f"elements = {{ ::/0 timeout {seconds}s }}; }}"]
    for direction in ("input", "output", "forward"):
        lines.append(f"chain {direction} {{ type filter hook {direction} priority -10; policy accept;")
        if direction != "forward":
            lines.append(f'{"iifname" if direction == "input" else "oifname"} "lo" accept')
        for network in plan["management_networks"]:
            version = "ip" if ipaddress.ip_network(network).version == 4 else "ip6"
            address = "saddr" if direction == "input" else "daddr"
            lines.append(f"{version} {address} {network} tcp dport {{ {ports} }} accept")
            lines.append(f"{version} {address} {network} tcp sport {{ {ports} }} ct state established accept")
        # IPv6 NDP is required for management connectivity; only link-local/control
        # packet types, never an unrestricted ICMPv6 accept.
        lines.append("icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept")
        lines.append("ip saddr @gate4 drop")
        lines.append("ip6 saddr @gate6 drop")
        lines.append("}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _isolation_exists(identifier: str) -> bool:
    table = "vsi_" + UUID(identifier).hex
    result = subprocess.run(["/usr/sbin/nft", "--json", "list", "tables"], check=True,
                            capture_output=True, text=True, timeout=10)
    data = json.loads(result.stdout)
    return any(item.get("table", {}).get("family") == "inet"
               and item.get("table", {}).get("name") == table
               for item in data["nftables"])


def apply_isolation(config: dict, plan: dict) -> dict:
    script = isolation_script(config, plan)
    # A retry after a crash never refreshes an existing kernel timeout. Job UUIDs
    # own a single table, created atomically. No system rules are flushed.
    if not _isolation_exists(plan["request_id"]):
        script = "create " + script
        subprocess.run(["/usr/sbin/nft", "--check", "-f", "-"], input=script, text=True,
                       check=True, capture_output=True, timeout=10)
        subprocess.run(["/usr/sbin/nft", "-f", "-"], input=script, text=True,
                       check=True, capture_output=True, timeout=10)
    return {"status": "applied", "detail": "isolated", "request_id": plan["request_id"],
            "expires_at": plan["expires_at"]}


def release_isolation(request_id: str) -> dict:
    table = "vsi_" + UUID(request_id).hex
    if _isolation_exists(request_id):
        subprocess.run(["/usr/sbin/nft", "delete", "table", "inet", table], check=True,
                       capture_output=True, timeout=10)
    return {"status": "rolled_back", "detail": "isolation_released", "request_id": str(UUID(request_id))}
