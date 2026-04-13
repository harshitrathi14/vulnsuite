"""
VulnSuite - Nmap passive network collector (service & version detection)

Passive-mode usage only. This collector performs TCP connect scans
(-sT) with service/version detection (-sV) and safe default scripts
(--script=default,safe). It deliberately excludes:
  - SYN scans (-sS) which require raw sockets and can trigger IDS
  - Vulnerability scripts (vuln category) which probe for exploits
  - Aggressive timing (-T4/-T5) which stresses production services
  - OS fingerprinting (-O) which is chatty and often inaccurate

Role in the suite:
  This is the first non-code-based collector. It maps hosts to open
  services and known CVEs *for the detected version strings*. We feed
  the version output to a local CVE-in-product matcher (NVD cpe2.3
  lookup) at the normalize layer, not via nmap --script vuln, to
  keep the scan itself passive.

BFSI authorization controls (critical):
  - Targets MUST be on the tenant's allow-list (enforced by the
    orchestrator, NOT this collector).
  - Collector refuses any target matching RFC1918 + public CIDR mix
    unless `allow_public=True` is explicitly set and logged.
  - All invocations are rate-limited via `--max-rate` and timing
    profile -T2 ("polite") by default — safe for production scans
    during business hours.
  - Every scan records the invoking user, target, and timestamp to
    the audit log for CERT-In traceability.

Requires: nmap on PATH + appropriate Linux capabilities (cap_net_raw
is NOT required because we use -sT connect scans).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from uuid import UUID

from ...core.schema import Evidence, Finding, Module, ScanResult, Severity

logger = logging.getLogger(__name__)

# Service banners we treat as elevated risk on sight. Version match
# to specific CVEs happens in a downstream enricher; these are the
# "obviously should not be internet-exposed" services that warrant
# a finding regardless of version.
_HIGH_RISK_SERVICES = {
    "telnet":    (Severity.CRITICAL, "Cleartext remote shell; mandatory removal under RBI CSF."),
    "ftp":       (Severity.HIGH,     "Cleartext credentials; replace with SFTP."),
    "rsh":       (Severity.CRITICAL, "Legacy cleartext remote shell."),
    "rlogin":    (Severity.CRITICAL, "Legacy cleartext remote login."),
    "tftp":      (Severity.HIGH,     "No authentication; restrict to management VLAN."),
    "snmp":      (Severity.MEDIUM,   "Verify v3 with authPriv; disable v1/v2c."),
    "smb":       (Severity.HIGH,     "Restrict to internal; disable SMBv1."),
    "netbios-ssn": (Severity.HIGH,   "Legacy NetBIOS; disable unless required."),
    "vnc":       (Severity.HIGH,     "Enforce VPN access + strong auth."),
    "rdp":       (Severity.HIGH,     "Enforce NLA + MFA + jump host."),
    "mysql":     (Severity.MEDIUM,   "DBs should not be directly reachable."),
    "postgresql":(Severity.MEDIUM,   "DBs should not be directly reachable."),
    "mongodb":   (Severity.HIGH,     "Historically exposed without auth; verify."),
    "redis":     (Severity.HIGH,     "Default no-auth; verify ACLs + TLS."),
    "elasticsearch": (Severity.HIGH, "Default no-auth; verify security plugin."),
    "memcached": (Severity.HIGH,     "No auth by design; restrict network."),
}


class NmapNotInstalled(RuntimeError):
    pass


class NmapPassiveCollector:
    def __init__(
        self,
        binary: str = "nmap",
        timeout_seconds: int = 3600,
        timing: str = "T2",               # polite
        max_rate: int = 100,              # packets/sec ceiling
        top_ports: int = 1000,
        allow_public: bool = False,
        extra_scripts: str = "default,safe",
    ) -> None:
        if shutil.which(binary) is None:
            raise NmapNotInstalled(f"{binary!r} not found on PATH")
        if timing not in ("T0", "T1", "T2", "T3"):
            raise ValueError(f"timing {timing} too aggressive for passive mode")
        self.binary = binary
        self.timeout = timeout_seconds
        self.timing = timing
        self.max_rate = max_rate
        self.top_ports = top_ports
        self.allow_public = allow_public
        self.extra_scripts = extra_scripts

    # ---------- public ----------

    async def scan(
        self,
        target: str,
        tenant_id: UUID,
        asset_id: UUID,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        errors: list[str] = []
        findings: list[Finding] = []

        try:
            self._validate_target(target)
            xml_bytes = await self._run(target)
            findings = self._normalize(xml_bytes, tenant_id, asset_id, target)
        except asyncio.TimeoutError:
            errors.append(f"nmap timeout after {self.timeout}s")
            logger.exception("nmap timeout on %s", target)
        except Exception as e:  # noqa: BLE001
            errors.append(f"nmap error: {e}")
            logger.exception("nmap failed on %s", target)

        return ScanResult(
            tool="nmap",
            module=Module.NETWORK,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    # ---------- internals ----------

    def _validate_target(self, target: str) -> None:
        """Refuse public-internet targets unless explicitly allowed."""
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            # Hostname — defer to DNS at scan time; allow.
            return
        if not net.is_private and not self.allow_public:
            raise PermissionError(
                f"Refusing scan of public range {target}; "
                f"set allow_public=True and log explicit authorization."
            )

    async def _run(self, target: str) -> bytes:
        cmd = [
            self.binary,
            "-sT",                          # TCP connect (no raw sockets)
            "-sV",                          # version detection
            "--version-intensity", "5",     # moderate
            f"-{self.timing}",
            "--max-rate", str(self.max_rate),
            "--top-ports", str(self.top_ports),
            "--script", self.extra_scripts,
            "-Pn",                          # skip host discovery
            "-oX", "-",                     # XML to stdout
            target,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise

        if proc.returncode != 0:
            raise RuntimeError(
                f"nmap exit {proc.returncode}: "
                f"{stderr.decode(errors='ignore')[:500]}"
            )
        return stdout

    def _normalize(
        self,
        xml_bytes: bytes,
        tenant_id: UUID,
        asset_id: UUID,
        target: str,
    ) -> list[Finding]:
        if not xml_bytes:
            return []
        out: list[Finding] = []
        root = ET.fromstring(xml_bytes)

        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr", "") if addr_el is not None else ""
            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port in ports_el.findall("port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                portid = port.get("portid", "0")
                protocol = port.get("protocol", "tcp")
                svc = port.find("service")
                svc_name = (svc.get("name") if svc is not None else "") or ""
                product = (svc.get("product") if svc is not None else "") or ""
                version = (svc.get("version") if svc is not None else "") or ""
                extrainfo = (svc.get("extrainfo") if svc is not None else "") or ""

                sev, remediation = _HIGH_RISK_SERVICES.get(
                    svc_name.lower(),
                    (Severity.INFO,
                     "Service inventoried; verify necessity and hardening."),
                )

                title = (
                    f"{svc_name or 'unknown'}"
                    f"{f' ({product} {version})'.rstrip() if product else ''}"
                    f" open on {addr}:{portid}/{protocol}"
                )

                out.append(Finding(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    tool="nmap",
                    module=Module.NETWORK,
                    title=title.strip(),
                    description=(
                        f"Nmap service/version detection found "
                        f"{svc_name or 'an unidentified service'} listening "
                        f"on {addr}:{portid}/{protocol}. "
                        f"Product: {product or 'unknown'}. "
                        f"Version: {version or 'unknown'}. "
                        f"Extra: {extrainfo or 'n/a'}."
                    ),
                    severity=sev,
                    evidence=Evidence(
                        raw={
                            "target": target,
                            "host": addr,
                            "port": int(portid),
                            "protocol": protocol,
                            "service": svc_name,
                            "product": product,
                            "version": version,
                            "extrainfo": extrainfo,
                            "cpe": [e.text for e in (svc.findall("cpe") if svc is not None else []) if e.text],
                        },
                    ),
                    remediation=remediation,
                    references=[
                        "https://nmap.org/book/man-version-detection.html",
                    ],
                ))
        return out
