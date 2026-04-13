"""VulnSuite - Trivy config collector for corroborating IaC misconfigurations."""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from ...core.schema import Evidence, Finding, Module, ScanResult, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyConfigNotInstalled(RuntimeError):
    pass


class TrivyConfigCollector:
    def __init__(
        self,
        binary: str = "trivy",
        timeout_seconds: int = 1200,
        offline: bool = False,
    ) -> None:
        if shutil.which(binary) is None:
            raise TrivyConfigNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.offline = offline

    async def scan(
        self,
        paths: list[str],
        tenant_id: UUID,
        asset_id: UUID,
        module: Module = Module.IAC,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors: list[str] = []
        for path in paths:
            try:
                raw = await self._run(path)
                findings.extend(self._normalize(raw, tenant_id, asset_id, module))
            except asyncio.TimeoutError:
                errors.append(f"trivy config timeout after {self.timeout}s on {path}")
            except Exception as exc:  # noqa: BLE001
                logger.exception("trivy config failed on %s", path)
                errors.append(f"trivy config error on {path}: {exc}")
        return ScanResult(
            tool="trivy-config",
            module=module,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    async def _run(self, path: str) -> dict:
        cmd = [
            self.binary,
            "config",
            "--format",
            "json",
            "--quiet",
            "--severity",
            "CRITICAL,HIGH,MEDIUM,LOW",
        ]
        if self.offline:
            cmd += ["--skip-db-update"]
        cmd.append(path)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise
        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"trivy config exit {proc.returncode}: {stderr.decode(errors='ignore')[:500]}"
            )
        return json.loads(stdout or "{}")

    def _normalize(
        self,
        raw: dict,
        tenant_id: UUID,
        asset_id: UUID,
        module: Module,
    ) -> list[Finding]:
        out: list[Finding] = []
        for result in raw.get("Results", []) or []:
            file_path = str(result.get("Target") or "")
            for misconfig in result.get("Misconfigurations", []) or []:
                identifier = str(misconfig.get("AVDID") or misconfig.get("ID") or "trivy-config")
                severity = _SEVERITY_MAP.get(str(misconfig.get("Severity") or "UNKNOWN").upper(), Severity.INFO)
                out.append(
                    Finding(
                        tenant_id=tenant_id,
                        asset_id=asset_id,
                        tool="trivy-config",
                        module=module,
                        title=f"{identifier}: {misconfig.get('Title') or 'Misconfiguration'}",
                        description=str(misconfig.get("Description") or "")[:2000],
                        severity=severity,
                        evidence=Evidence(
                            file=file_path or None,
                            raw={
                                "check_id": identifier,
                                "resource": (misconfig.get("CauseMetadata") or {}).get("Resource"),
                                "namespace": misconfig.get("Namespace"),
                                "type": result.get("Type"),
                                "message": misconfig.get("Message"),
                            },
                        ),
                        remediation=str(misconfig.get("Resolution") or "Review the Trivy remediation guidance.")[:1000],
                        references=[str(misconfig.get("PrimaryURL"))] if misconfig.get("PrimaryURL") else [],
                    )
                )
        return out
