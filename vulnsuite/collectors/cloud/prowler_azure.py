"""
VulnSuite - Prowler Azure cloud posture collector

Wraps `prowler azure` for CSPM against Azure subscriptions. Uses a
read-only service principal (Reader + Security Reader roles). Prowler
runs checks mapped to CIS Azure Benchmark, ISO 27001, NIST, and
PCI-DSS. Output is normalized into the canonical Finding schema and
tagged with CIS/compliance citations for BFSI audit defensibility.

Authorization model (critical for BFSI):
  Authentication is via environment variables set by the worker:
    AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID,
    AZURE_SUBSCRIPTION_ID. Secrets come from Azure Key Vault via
    the worker's managed identity; never hardcoded. The collector
    refuses to run if credentials are not present in env.

Requires: prowler on PATH (pip install prowler).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from ...core.schema import Evidence, Finding, Module, ScanResult, Severity

logger = logging.getLogger(__name__)

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}

_REQUIRED_ENV = (
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID",
)


class ProwlerNotInstalled(RuntimeError):
    pass


class ProwlerAzureCollector:
    def __init__(
        self,
        binary: str = "prowler",
        timeout_seconds: int = 3600,
        compliance_frameworks: tuple[str, ...] = (
            "cis_2.0_azure", "iso27001_2013", "nist_800_53_revision_5",
        ),
        services: tuple[str, ...] | None = None,   # None = all
        severity_floor: str = "low",
    ) -> None:
        if shutil.which(binary) is None:
            raise ProwlerNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.compliance = compliance_frameworks
        self.services = services
        self.severity_floor = severity_floor

    async def scan(
        self, tenant_id: UUID, asset_id: UUID,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        errors: list[str] = []
        findings: list[Finding] = []

        missing = [e for e in _REQUIRED_ENV if not os.getenv(e)]
        if missing:
            errors.append(f"missing Azure credentials: {missing}")
            return ScanResult(
                tool="prowler-azure", module=Module.CLOUD,
                asset_id=asset_id, started_at=started,
                finished_at=datetime.now(timezone.utc),
                findings=[], errors=errors,
            )

        try:
            raw = await self._run()
            findings = self._normalize(raw, tenant_id, asset_id)
        except asyncio.TimeoutError:
            errors.append(f"prowler timeout after {self.timeout}s")
            logger.exception("prowler timeout")
        except Exception as e:  # noqa: BLE001
            errors.append(f"prowler error: {e}")
            logger.exception("prowler failed")

        return ScanResult(
            tool="prowler-azure", module=Module.CLOUD,
            asset_id=asset_id, started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings, errors=errors,
        )

    async def _run(self) -> list[dict]:
        outdir = tempfile.mkdtemp(prefix="prowler-")
        cmd = [
            self.binary, "azure",
            "--sp-env-auth",
            "--output-formats", "json-ocsf",
            "--output-directory", outdir,
            "--severity", self.severity_floor,
        ]
        if self.services:
            cmd += ["--services", *self.services]
        if self.compliance:
            cmd += ["--compliance", *self.compliance]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
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

        if proc.returncode not in (0, 3):   # 3 == findings present
            raise RuntimeError(
                f"prowler exit {proc.returncode}: "
                f"{stderr.decode(errors='ignore')[:500]}"
            )

        # Locate the OCSF JSON output file in outdir
        findings_raw: list[dict] = []
        for p in Path(outdir).glob("*.ocsf.json"):
            try:
                data = json.loads(p.read_text())
                if isinstance(data, list):
                    findings_raw.extend(data)
            except Exception:  # noqa: BLE001
                logger.exception("failed to parse %s", p)
        return findings_raw

    def _normalize(
        self, raw: list[dict], tenant_id: UUID, asset_id: UUID,
    ) -> list[Finding]:
        out: list[Finding] = []
        for item in raw or []:
            # OCSF shape: flatten the parts we need
            finding_info = item.get("finding_info", {}) or {}
            status = (item.get("status_code") or "").lower()
            if status != "fail":
                continue   # only report failing checks

            sev_raw = (item.get("severity") or "informational").lower()
            sev = _SEV_MAP.get(sev_raw, Severity.INFO)

            check_id = finding_info.get("uid") or "prowler.unknown"
            title = finding_info.get("title") or check_id
            desc = finding_info.get("desc") or ""

            resources = item.get("resources", []) or []
            resource_name = resources[0].get("name", "") if resources else ""
            resource_type = resources[0].get("type", "") if resources else ""

            unmapped = item.get("unmapped", {}) or {}
            remediation = (
                (item.get("remediation") or {}).get("desc")
                or unmapped.get("remediation", "")
                or "Review Azure configuration per CIS Azure Benchmark."
            )

            out.append(Finding(
                tenant_id=tenant_id,
                asset_id=asset_id,
                tool="prowler-azure",
                module=Module.CLOUD,
                title=f"{check_id}: {title}",
                description=desc[:2000],
                severity=sev,
                evidence=Evidence(
                    raw={
                        "check_id": check_id,
                        "service": unmapped.get("service_name"),
                        "region": unmapped.get("region"),
                        "resource_name": resource_name,
                        "resource_type": resource_type,
                        "subscription": unmapped.get("account_uid"),
                        "compliance": unmapped.get("compliance", {}),
                        "cis_benchmark": "CIS Azure 2.0",
                    },
                ),
                remediation=remediation[:1000],
                references=[
                    "https://docs.prowler.com",
                    "https://www.cisecurity.org/benchmark/azure",
                ],
            ))
        return out
