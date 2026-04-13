"""
VulnSuite - testssl.sh collector (TLS hygiene)

Wraps the `testssl.sh` CLI to assess TLS/SSL configuration of a
target endpoint. Passive from the endpoint's perspective: no
exploit attempts, only protocol negotiation and banner inspection.

RBI Cyber Security Framework mandates for BFSI:
  - TLS 1.2+ only (TLS 1.0, 1.1, SSLv2, SSLv3 forbidden)
  - Strong ciphers only (no RC4, 3DES, EXPORT, NULL, anonymous)
  - Valid, CA-signed certificates with >= 2048-bit RSA or ECC P-256
  - HSTS header on public banking endpoints
  - No known TLS vulnerabilities: Heartbleed, POODLE, BEAST, CRIME,
    LUCKY13, ROBOT, FREAK, LOGJAM, DROWN, Sweet32, Ticketbleed

This collector maps testssl.sh's findings directly onto those
mandates, so every finding carries a concrete regulatory citation
in its evidence block.

Requires: testssl.sh on PATH (https://testssl.sh).
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from ...core.schema import Evidence, Finding, Module, ScanResult, Severity

logger = logging.getLogger(__name__)

# testssl.sh severity -> our Severity. testssl uses:
# OK, INFO, LOW, MEDIUM, HIGH, CRITICAL, WARN, DEBUG, FATAL
_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "WARN":     Severity.LOW,
    "INFO":     Severity.INFO,
    "OK":       Severity.INFO,
}

# testssl.sh finding IDs that map directly to RBI CSF control items.
# The key is a substring match against testssl's `id` field.
_RBI_CONTROL_MAP: dict[str, str] = {
    "SSLv2":       "RBI-CSF Annex-I 6.2 — disable legacy SSL protocols",
    "SSLv3":       "RBI-CSF Annex-I 6.2 — disable legacy SSL protocols",
    "TLS1":        "RBI-CSF Annex-I 6.2 — TLS 1.2+ mandatory",
    "TLS1_1":      "RBI-CSF Annex-I 6.2 — TLS 1.2+ mandatory",
    "cipher_rc4":  "RBI-CSF Annex-I 6.2 — weak cipher prohibited",
    "3DES":        "RBI-CSF Annex-I 6.2 — weak cipher prohibited",
    "NULL":        "RBI-CSF Annex-I 6.2 — null cipher prohibited",
    "EXPORT":      "RBI-CSF Annex-I 6.2 — export cipher prohibited",
    "heartbleed":  "RBI-CSF Annex-I 6.3 — patch known TLS vulnerabilities",
    "ROBOT":       "RBI-CSF Annex-I 6.3 — patch known TLS vulnerabilities",
    "POODLE":      "RBI-CSF Annex-I 6.3 — patch known TLS vulnerabilities",
    "FREAK":       "RBI-CSF Annex-I 6.3 — patch known TLS vulnerabilities",
    "LOGJAM":      "RBI-CSF Annex-I 6.3 — patch known TLS vulnerabilities",
    "DROWN":       "RBI-CSF Annex-I 6.3 — patch known TLS vulnerabilities",
    "BEAST":       "RBI-CSF Annex-I 6.3 — patch known TLS vulnerabilities",
    "CRIME":       "RBI-CSF Annex-I 6.3 — patch known TLS vulnerabilities",
    "LUCKY13":     "RBI-CSF Annex-I 6.3 — patch known TLS vulnerabilities",
    "Sweet32":     "RBI-CSF Annex-I 6.3 — patch known TLS vulnerabilities",
    "ticketbleed": "RBI-CSF Annex-I 6.3 — patch known TLS vulnerabilities",
    "HSTS":        "RBI-CSF Annex-I 6.4 — HSTS required on public endpoints",
    "cert_chain":  "RBI-CSF Annex-I 6.5 — valid CA-signed certificate",
    "cert_expiration": "RBI-CSF Annex-I 6.5 — certificate renewal policy",
}


class TestSSLNotInstalled(RuntimeError):
    pass


class TestSSLCollector:
    def __init__(
        self,
        binary: str = "testssl.sh",
        timeout_seconds: int = 1200,
        severity_floor: str = "LOW",
        full_scan: bool = True,
    ) -> None:
        if shutil.which(binary) is None:
            raise TestSSLNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.severity_floor = severity_floor
        self.full_scan = full_scan

    # ---------- public ----------

    async def scan(
        self,
        target: str,                  # e.g. "bank.example.com:443"
        tenant_id: UUID,
        asset_id: UUID,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        errors: list[str] = []
        findings: list[Finding] = []

        try:
            raw = await self._run(target)
            findings = self._normalize(raw, tenant_id, asset_id, target)
        except asyncio.TimeoutError:
            errors.append(f"testssl timeout after {self.timeout}s")
            logger.exception("testssl timeout on %s", target)
        except Exception as e:  # noqa: BLE001
            errors.append(f"testssl error: {e}")
            logger.exception("testssl failed on %s", target)

        return ScanResult(
            tool="testssl.sh",
            module=Module.NETWORK,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    # ---------- internals ----------

    async def _run(self, target: str) -> list[dict]:
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w",
        ) as tmp:
            report_path = tmp.name

        cmd = [
            self.binary,
            "--quiet",
            "--color", "0",
            "--warnings", "off",
            "--severity", self.severity_floor,
            "--jsonfile-pretty", report_path,
        ]
        if self.full_scan:
            cmd += ["--full"]
        else:
            cmd += ["--fast"]
        cmd.append(target)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise

        # testssl.sh exits non-zero when findings exist; tolerate 0-2
        if proc.returncode not in (0, 1, 2):
            raise RuntimeError(
                f"testssl exit {proc.returncode}: "
                f"{stderr.decode(errors='ignore')[:500]}"
            )

        try:
            text = Path(report_path).read_text() or "[]"
            data = json.loads(text)
            # --jsonfile-pretty emits an object with "scanResult" list
            if isinstance(data, dict) and "scanResult" in data:
                findings: list[dict] = []
                for sr in data.get("scanResult", []) or []:
                    for section in (
                        "protocols", "ciphers", "serverPreferences",
                        "vulnerabilities", "serverDefaults",
                        "cipherTests", "browserSimulations", "headerResponse",
                    ):
                        findings.extend(sr.get(section, []) or [])
                return findings
            if isinstance(data, list):
                return data
            return []
        finally:
            Path(report_path).unlink(missing_ok=True)

    def _normalize(
        self,
        raw: list[dict],
        tenant_id: UUID,
        asset_id: UUID,
        target: str,
    ) -> list[Finding]:
        out: list[Finding] = []
        for item in raw or []:
            sev_str = (item.get("severity") or "INFO").upper()
            sev = _SEV_MAP.get(sev_str, Severity.INFO)
            if sev == Severity.INFO and sev_str == "OK":
                continue  # healthy checks are not findings

            finding_id = item.get("id", "unknown")
            finding_text = item.get("finding", "") or ""
            cve_list = self._extract_cves(item)
            rbi_citation = self._rbi_citation(finding_id)

            out.append(Finding(
                tenant_id=tenant_id,
                asset_id=asset_id,
                tool="testssl.sh",
                module=Module.NETWORK,
                title=f"{finding_id}: {finding_text[:120]}",
                description=finding_text[:2000],
                cve=cve_list,
                severity=sev,
                evidence=Evidence(
                    raw={
                        "target": target,
                        "id": finding_id,
                        "ip": item.get("ip"),
                        "port": item.get("port"),
                        "cve": item.get("cve"),
                        "cwe": item.get("cwe"),
                        "rbi_control": rbi_citation,
                    },
                ),
                remediation=self._remediation_hint(finding_id),
                references=[
                    "https://testssl.sh",
                    "https://www.rbi.org.in/Scripts/BS_CircularIndexDisplay.aspx?Id=10435",
                ],
            ))
        return out

    # ---------- helpers ----------

    @staticmethod
    def _extract_cves(item: dict) -> list[str]:
        raw = item.get("cve") or ""
        if not raw:
            return []
        # testssl emits space-separated CVE IDs in a single string
        return [c.strip().upper() for c in raw.split() if c.strip().upper().startswith("CVE-")]

    @staticmethod
    def _rbi_citation(finding_id: str) -> str | None:
        for token, citation in _RBI_CONTROL_MAP.items():
            if token.lower() in finding_id.lower():
                return citation
        return None

    @staticmethod
    def _remediation_hint(finding_id: str) -> str:
        fid = finding_id.lower()
        if "sslv2" in fid or "sslv3" in fid or "tls1" == fid or "tls1_1" in fid:
            return ("Disable legacy protocol on the TLS terminator "
                    "(nginx/HAProxy/Azure App Gateway). Leave only TLS 1.2 and 1.3.")
        if "rc4" in fid or "3des" in fid or "null" in fid or "export" in fid:
            return ("Remove weak ciphers from the server cipher suite. "
                    "Use the Mozilla 'intermediate' profile for TLS 1.2 and "
                    "default suites for TLS 1.3.")
        if "hsts" in fid:
            return ("Add `Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload` on all public HTTPS responses.")
        if "cert_expiration" in fid:
            return ("Renew the certificate and implement automated renewal "
                    "(ACME/Let's Encrypt or Azure Key Vault auto-renew).")
        if "cert_chain" in fid:
            return ("Fix certificate chain: serve the full intermediate chain, "
                    "verify CA trust, remove self-signed certs from production.")
        if any(v in fid for v in (
            "heartbleed", "robot", "poodle", "freak", "logjam",
            "drown", "beast", "crime", "lucky13", "sweet32", "ticketbleed",
        )):
            return ("Patch the TLS stack to a version that mitigates this "
                    "known vulnerability and re-test. Verify via SSL Labs "
                    "or testssl.sh after deployment.")
        return ("Review testssl.sh output and align the endpoint's TLS "
                "configuration with the RBI Cyber Security Framework Annex-I.")
