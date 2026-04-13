"""
VulnSuite - Trivy collector (SCA + container)

Wraps the `trivy` CLI. Supports filesystem (repo) and image scans.
Normalizes Trivy JSON output into the canonical Finding schema.

Requires: trivy binary on PATH (https://aquasec.com/trivy).
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from ...core.schema import (
    Evidence, Finding, Module, ScanResult, Severity,
)

logger = logging.getLogger(__name__)

TrivyTarget = Literal["fs", "image", "sbom"]

# Trivy severity -> our Severity
_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyNotInstalled(RuntimeError):
    pass


class TrivyCollector:
    """Async Trivy wrapper. One instance = one configured scanner."""

    def __init__(
        self,
        binary: str = "trivy",
        timeout_seconds: int = 900,
        offline: bool = False,
        severity_threshold: str = "LOW",
    ) -> None:
        if shutil.which(binary) is None:
            raise TrivyNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.offline = offline
        self.severity_threshold = severity_threshold

    # ---------- public ----------

    async def scan(
        self,
        target: str,
        kind: TrivyTarget,
        tenant_id: UUID,
        asset_id: UUID,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        errors: list[str] = []
        findings: list[Finding] = []

        try:
            raw = await self._run(target, kind)
            findings = self._normalize(raw, tenant_id, asset_id, kind)
        except asyncio.TimeoutError:
            errors.append(f"trivy timeout after {self.timeout}s")
            logger.exception("trivy timeout on %s", target)
        except Exception as e:  # noqa: BLE001
            errors.append(f"trivy error: {e}")
            logger.exception("trivy failed on %s", target)

        return ScanResult(
            tool="trivy",
            module=self._module_for_kind(kind),
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    # ---------- internals ----------

    async def _run(self, target: str, kind: TrivyTarget) -> dict:
        cmd = [
            self.binary, kind,
            "--format", "json",
            "--quiet",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--scanners", "vuln",
            "--exit-code", "0",
        ]
        if self.offline:
            cmd += ["--offline-scan", "--skip-db-update"]
        cmd.append(target)

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

        if proc.returncode not in (0, 1):  # 1 == vulns found, still OK
            raise RuntimeError(
                f"trivy exit {proc.returncode}: {stderr.decode(errors='ignore')[:500]}"
            )
        if not stdout:
            return {}
        return json.loads(stdout)

    def _normalize(
        self, raw: dict, tenant_id: UUID, asset_id: UUID, kind: TrivyTarget,
    ) -> list[Finding]:
        out: list[Finding] = []
        module = self._module_for_kind(kind)

        for result in raw.get("Results", []) or []:
            target_path = result.get("Target", "")
            pkg_type = result.get("Type", "")
            for v in result.get("Vulnerabilities", []) or []:
                cvss_base = self._extract_cvss(v)
                cve = v.get("VulnerabilityID", "")
                sev = _SEV_MAP.get((v.get("Severity") or "").upper(), Severity.INFO)

                out.append(Finding(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    tool="trivy",
                    module=module,
                    title=f"{cve} in {v.get('PkgName', '?')}",
                    description=(v.get("Description") or "")[:2000],
                    cve=[cve] if cve.startswith("CVE-") else [],
                    cwe=v.get("CweIDs", []) or [],
                    cvss_vector=self._extract_vector(v),
                    cvss_base=cvss_base,
                    severity=sev,
                    evidence=Evidence(
                        file=target_path,
                        raw={
                            "pkg_name": v.get("PkgName"),
                            "installed_version": v.get("InstalledVersion"),
                            "fixed_version": v.get("FixedVersion"),
                            "pkg_type": pkg_type,
                            "data_source": (v.get("DataSource") or {}).get("Name"),
                        },
                    ),
                    remediation=(
                        f"Upgrade {v.get('PkgName')} to {v['FixedVersion']}"
                        if v.get("FixedVersion") else "No fix available yet"
                    ),
                    references=v.get("References", []) or [],
                ))
        return out

    @staticmethod
    def _module_for_kind(kind: TrivyTarget) -> Module:
        if kind == "image":
            return Module.CONTAINER
        if kind == "sbom":
            return Module.SUPPLY_CHAIN
        return Module.SCA

    @staticmethod
    def _extract_cvss(v: dict) -> float:
        """Prefer NVD v3, fall back to any vendor v3, then v2, then 0."""
        cvss = v.get("CVSS") or {}
        for vendor in ("nvd", "redhat", "ghsa"):
            entry = cvss.get(vendor) or {}
            score = entry.get("V3Score") or entry.get("V2Score")
            if score:
                return float(score)
        return 0.0

    @staticmethod
    def _extract_vector(v: dict) -> str | None:
        cvss = v.get("CVSS") or {}
        for vendor in ("nvd", "redhat", "ghsa"):
            entry = cvss.get(vendor) or {}
            vec = entry.get("V3Vector")
            if vec:
                return vec
        return None
