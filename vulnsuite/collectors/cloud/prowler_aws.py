"""VulnSuite - Prowler AWS collector."""
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

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}


class ProwlerAWSNotInstalled(RuntimeError):
    pass


class ProwlerAWSCollector:
    def __init__(
        self,
        binary: str = "prowler",
        timeout_seconds: int = 3600,
        compliance_frameworks: tuple[str, ...] = ("cis_aws_1.5", "nist_800_53_revision_5"),
    ) -> None:
        if shutil.which(binary) is None:
            raise ProwlerAWSNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.compliance = compliance_frameworks

    async def scan(
        self,
        tenant_id: UUID,
        asset_id: UUID,
        account_ids: list[str] | None = None,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors: list[str] = []
        try:
            raw = await self._run(account_ids or [])
            findings = self._normalize(raw, tenant_id, asset_id)
        except asyncio.TimeoutError:
            errors.append(f"prowler aws timeout after {self.timeout}s")
        except Exception as exc:  # noqa: BLE001
            logger.exception("prowler aws failed")
            errors.append(f"prowler aws error: {exc}")
        return ScanResult(
            tool="prowler-aws",
            module=Module.CLOUD,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    async def _run(self, account_ids: list[str]) -> list[dict]:
        outdir = tempfile.mkdtemp(prefix="prowler-aws-")
        cmd = [
            self.binary,
            "aws",
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            outdir,
        ]
        if self.compliance:
            cmd += ["--compliance", *self.compliance]
        if account_ids:
            # Without this flag the current credential's whole organization is scanned.
            cmd += ["--aws-account-id", *account_ids]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise
        if proc.returncode not in (0, 3):
            raise RuntimeError(
                f"prowler aws exit {proc.returncode}: {stderr.decode(errors='ignore')[:500]}"
            )
        findings_raw: list[dict] = []
        for path in Path(outdir).glob("*.ocsf.json"):
            data = json.loads(path.read_text() or "[]")
            if isinstance(data, list):
                findings_raw.extend(data)
        return findings_raw

    def _normalize(self, raw: list[dict], tenant_id: UUID, asset_id: UUID) -> list[Finding]:
        out: list[Finding] = []
        for item in raw:
            if str(item.get("status_code") or "").lower() != "fail":
                continue
            finding_info = item.get("finding_info", {}) or {}
            sev = _SEV_MAP.get(str(item.get("severity") or "informational").lower(), Severity.INFO)
            unmapped = item.get("unmapped", {}) or {}
            resources = item.get("resources", []) or []
            resource = resources[0] if resources else {}
            check_id = str(finding_info.get("uid") or "prowler.aws")
            out.append(
                Finding(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    tool="prowler-aws",
                    module=Module.CLOUD,
                    title=f"{check_id}: {finding_info.get('title') or check_id}",
                    description=str(finding_info.get("desc") or "")[:2000],
                    severity=sev,
                    evidence=Evidence(
                        raw={
                            "check_id": check_id,
                            "resource_name": resource.get("name"),
                            "resource_type": resource.get("type"),
                            "account": unmapped.get("account_uid"),
                            "region": unmapped.get("region"),
                            "compliance": unmapped.get("compliance", {}),
                        }
                    ),
                    remediation=str(((item.get("remediation") or {}).get("desc")) or "Review the AWS configuration against the cited control.")[:1000],
                    references=["https://docs.prowler.com/introduction"],
                )
            )
        return out
