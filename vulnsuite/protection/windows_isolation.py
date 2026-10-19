"""Reviewed Windows Defender Firewall containment with an independent expiry task.

Windows has no nftables-style rule TTL. A SYSTEM scheduled watchdog is established
and confirmed before adding rules; task/service availability is a deployment gate.
No Windows API or helper is invoked when this module is imported or a plan is made.
"""
from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import time
from uuid import UUID

from .windows_quarantine import local_path


HELPER = Path(__file__).with_name("windows_isolation_helper.ps1")
_POLICY_ERRORS = {"policy_denied", "unsupported_policy", "unsafe_installation", "invalid_plan",
                  "plan_expired", "helper_not_ready", "job_conflict", "job_already_released"}
_EXECUTION_ERRORS = {"execution_failed", "rollback_failed", "watchdog_unavailable",
                     "effective_rules_unconfirmed", "interrupted_application"}


class WindowsIsolationError(OSError):
    """A sanitized native-execution error, safe to record in response audit."""


def _windows():
    return os.name == "nt"


def prepare_windows_isolation(config: dict, duration: int, request_id: str, now=None) -> dict:
    if type(duration) is not int or not 60 <= duration <= 3600:
        raise ValueError("duration must be 60..3600 seconds")
    networks = config.get("management_networks", [])
    ports = config.get("management_ports", [])
    if not isinstance(networks, list) or not 1 <= len(networks) <= 32:
        raise ValueError("one to 32 pinned management hosts required")
    parsed = [ipaddress.ip_network(value, strict=True) for value in networks]
    for network in parsed:
        address = network.network_address
        if network.prefixlen != address.max_prefixlen or address.is_loopback or address.is_multicast \
                or address.is_unspecified or address.is_link_local \
                or getattr(address, "ipv4_mapped", None) is not None:
            raise ValueError("Windows management endpoints must be unicast /32 or /128 hosts")
    if not isinstance(ports, list) or not 1 <= len(ports) <= 32 or any(
            type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("one to 32 explicit management TCP ports required")
    created = int(time.time() if now is None else now)
    return {"platform": "windows", "request_id": str(UUID(request_id)),
            "created_at": created, "expires_at": created + duration,
            "management_networks": sorted({str(network) for network in parsed}),
            "management_ports": sorted(set(ports))}


def _validate(config, plan, *, live=True):
    if type(plan.get("created_at")) is not int or type(plan.get("expires_at")) is not int:
        raise ValueError("invalid plan timestamps")
    expected = prepare_windows_isolation(config, plan["expires_at"] - plan["created_at"],
                                         plan["request_id"], plan["created_at"])
    if expected != {key: value for key, value in plan.items() if key != "reason"}:
        raise ValueError("Windows isolation differs from local policy")
    instant = time.time()
    if live and (plan["expires_at"] <= instant or plan["created_at"] > instant + 30):
        raise ValueError("isolation plan expired or in the future")
    return expected


def complement_ranges(networks: list[str], version: int) -> list[str]:
    """Return inclusive address ranges outside the supplied CIDRs, without overlap."""
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    intervals = sorted((int(net.network_address), int(net.broadcast_address)) for value in networks
                       if (net := ipaddress.ip_network(value)).version == version)
    cursor, result, maximum = 0, [], (1 << (32 if version == 4 else 128)) - 1
    for start, end in intervals:
        if start > cursor:
            result.append(str(cls(cursor)) if cursor == start - 1
                          else f"{cls(cursor)}-{cls(start - 1)}")
        cursor = max(cursor, end + 1)
    if cursor <= maximum:
        result.append(str(cls(cursor)) if cursor == maximum else f"{cls(cursor)}-{cls(maximum)}")
    return result


def complement_ports(ports: list[int]) -> list[str]:
    result, cursor = [], 0
    for port in sorted(set(ports)):
        if cursor < port:
            result.append(str(cursor) if cursor == port - 1 else f"{cursor}-{port - 1}")
        cursor = port + 1
    if cursor <= 65535:
        result.append(str(cursor) if cursor == 65535 else f"{cursor}-65535")
    return result


def firewall_rules(plan: dict) -> list[dict]:
    """Generate disjoint block/allow conditions; never block-all over an exception.

    TCP on a pinned management host is excepted when either endpoint port is in
    policy. This preserves replies conservatively; it is not a directional port
    restriction. TCP to other hosts is blocked. Essential ICMP control types are
    separate exceptions, with IPv6 discovery limited to neighbour/control scopes.
    """
    identifier = UUID(plan["request_id"]).hex
    management = [str(ipaddress.ip_network(n).network_address)
                  for n in plan["management_networks"]]
    outside = []
    non_loopback = []
    for version in (4, 6):
        loopbacks = ["127.0.0.0/8", "::1/128"]
        outside.extend(complement_ranges(plan["management_networks"] + loopbacks, version))
        non_loopback.extend(complement_ranges(loopbacks, version))
    bad_ports = complement_ports(plan["management_ports"])
    rules = []

    def add(direction, action, protocol, addresses, **filters):
        rules.append({"name": f"VulnSuite-Isolation-{identifier}-{len(rules):03d}",
                      "direction": direction, "action": action, "protocol": protocol,
                      "remote_addresses": addresses, **filters})

    for direction in (1, 2):  # INetFwRule: 1 inbound, 2 outbound; 0 block, 1 allow.
        add(direction, 0, 6, outside)
        add(direction, 0, 6, management, local_ports=bad_ports, remote_ports=bad_ports)
        add(direction, 1, 6, management, local_ports=[str(p) for p in plan["management_ports"]])
        add(direction, 1, 6, management, remote_ports=[str(p) for p in plan["management_ports"]])
        # IPsec authenticated-bypass policies are rejected by helper preflight.
        # Protocol numbers are discrete in INetFwRule; enumerate without broad
        # Any-protocol blocks that would swallow TCP or IPv6 discovery exceptions.
        for protocol in range(256):
            if protocol not in (1, 6, 58):
                add(direction, 0, protocol, non_loopback)
        for protocol, permitted in ((1, {3}), (58, {2, 133, 134, 135, 136})):
            add(direction, 0, protocol, non_loopback,
                icmp_types=[f"{kind}:*" for kind in range(256) if kind not in permitted])
            if protocol == 1:
                add(direction, 1, protocol, non_loopback, icmp_types=["3:*"])
            else:
                discovery = ["fe80::/10", "ff02::/16", "::/128"] + [
                    net for net in plan["management_networks"]
                    if ipaddress.ip_network(net).version == 6]
                nd_types = [f"{kind}:*" for kind in (133, 134, 135, 136)]
                add(direction, 0, 58, complement_ranges(discovery + ["::1/128"], 6),
                    icmp_types=nd_types)
                add(direction, 1, 58, discovery, icmp_types=nd_types)
                add(direction, 1, 58, non_loopback, icmp_types=["2:*"])
    return rules


def _state_directory(config):
    return local_path(config.get("state_dir", r"C:\ProgramData\VulnSuite\Isolation"))


def _powershell_path():
    buffer = ctypes.create_unicode_buffer(32768)
    count = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not count or count >= len(buffer):
        raise WindowsIsolationError("helper_not_ready")
    return str(PureWindowsPath(buffer.value) / "System32/WindowsPowerShell/v1.0/powershell.exe")


def _invoke(config: dict, mode: str, payload: dict | None = None, request_id=None):
    if not _windows():
        raise ValueError("Windows isolation requires a Windows host")
    expected_hash = config.get("helper_sha256", "")
    if not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or hashlib.sha256(HELPER.read_bytes()).hexdigest() != expected_hash:
        raise ValueError("installed helper hash does not match approved local configuration")
    command = [_powershell_path(), "-NoProfile", "-NonInteractive", "-File", str(HELPER),
               "-Mode", mode, "-StateDirectory", _state_directory(config)]
    if request_id is not None:
        command.extend(["-JobId", UUID(request_id).hex])
    try:
        result = subprocess.run(command, input=json.dumps(payload or {}, separators=(",", ":")),
                                text=True, capture_output=True, timeout=240, check=False)
    except subprocess.SubprocessError as exc:
        # The separately running task retains the original deadline after timeout.
        raise WindowsIsolationError("execution_failed") from exc
    try:
        if len(result.stdout) > 65536:
            raise ValueError("oversized helper response")
        receipt = json.loads(result.stdout.strip())
        if not isinstance(receipt, dict):
            raise ValueError("invalid helper receipt")
    except (ValueError, TypeError) as exc:
        raise WindowsIsolationError("execution_failed") from exc
    if result.returncode != 0 or receipt.get("status") == "failed":
        code = receipt.get("error", "execution_failed")
        if code in _POLICY_ERRORS:
            raise ValueError(code)
        raise WindowsIsolationError(code if code in _EXECUTION_ERRORS else "execution_failed")
    return receipt


def apply_windows_isolation(config: dict, plan: dict) -> dict:
    canonical = _validate(config, plan)
    receipt = _invoke(config, "Apply", {"plan": canonical, "rules": firewall_rules(canonical)})
    if (receipt.get("status"), receipt.get("detail"), receipt.get("request_id"), receipt.get("expires_at")) != (
            "applied", "isolated", canonical["request_id"], canonical["expires_at"]):
        raise WindowsIsolationError("effective_rules_unconfirmed")
    return {"status": "applied", "detail": "isolated", "platform": "windows",
            "request_id": canonical["request_id"], "expires_at": canonical["expires_at"],
            "expiry_mechanism": "scheduled_task_watchdog"}


def release_windows_isolation(config: dict, request_id: str) -> dict:
    identifier = str(UUID(request_id))
    receipt = _invoke(config, "Release", request_id=identifier)
    if (receipt.get("status"), receipt.get("detail"), receipt.get("request_id")) != (
            "rolled_back", "isolation_released", identifier):
        raise WindowsIsolationError("rollback_failed")
    return {"status": "rolled_back", "detail": "isolation_released", "platform": "windows",
            "request_id": identifier}


def cleanup_expired(config: dict) -> dict:
    """Local recovery, independent of control-plane reachability or enablement."""
    receipt = _invoke(config, "Cleanup")
    if receipt.get("status") != "cleaned" or type(receipt.get("released")) is not int:
        raise WindowsIsolationError("rollback_failed")
    return {"status": "cleaned", "released": receipt["released"]}
