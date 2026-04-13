"""VulnSuite - Checkov collector for IaC and OpenAPI scanning."""
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
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class CheckovNotInstalled(RuntimeError):
    pass


class CheckovCollector:
    def __init__(
        self,
        binary: str = "checkov",
        timeout_seconds: int = 1800,
        download_external_modules: bool = False,
    ) -> None:
        if shutil.which(binary) is None:
            raise CheckovNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.download_external_modules = download_external_modules

    async def scan(
        self,
        paths: list[str],
        tenant_id: UUID,
        asset_id: UUID,
        frameworks: tuple[str, ...] | None = None,
        module: Module = Module.IAC,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors: list[str] = []

        for path in paths:
            try:
                raw = await self._run(path, frameworks)
                findings.extend(self._normalize(raw, tenant_id, asset_id, module))
            except asyncio.TimeoutError:
                errors.append(f"checkov timeout after {self.timeout}s on {path}")
            except Exception as exc:  # noqa: BLE001
                logger.exception("checkov failed on %s", path)
                errors.append(f"checkov error on {path}: {exc}")

        return ScanResult(
            tool="checkov",
            module=module,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    async def _run(self, path: str, frameworks: tuple[str, ...] | None) -> dict:
        cmd = [self.binary]
        target = Path(path)
        if target.is_dir():
            cmd += ["-d", path]
        else:
            cmd += ["-f", path]
        cmd += ["-o", "json", "--quiet"]
        if frameworks:
            cmd += ["--framework", ",".join(frameworks)]
        if self.download_external_modules:
            cmd += ["--download-external-modules", "true"]
        else:
            cmd += ["--download-external-modules", "false"]

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
                f"checkov exit {proc.returncode}: {stderr.decode(errors='ignore')[:500]}"
            )
        if not stdout:
            return {}
        return json.loads(stdout)

    def _normalize(
        self,
        raw: dict,
        tenant_id: UUID,
        asset_id: UUID,
        module: Module,
    ) -> list[Finding]:
        results = raw.get("results", {}) if isinstance(raw, dict) else {}
        failed_checks = results.get("failed_checks", []) or []
        out: list[Finding] = []
        for check in failed_checks:
            severity = _SEVERITY_MAP.get(
                str(check.get("severity") or check.get("bc_check_severity") or "info").lower(),
                Severity.INFO,
            )
            resource = str(check.get("resource") or check.get("resource_address") or "")
            guideline = str(check.get("guideline") or "")
            check_id = str(check.get("check_id") or check.get("bc_check_id") or "checkov.unknown")
            check_name = str(check.get("check_name") or "Checkov policy violation")
            file_path = str(
                check.get("repo_file_path")
                or check.get("file_path")
                or check.get("file_abs_path")
                or ""
            )

            out.append(
                Finding(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    tool="checkov",
                    module=module,
                    title=f"{check_id}: {check_name}",
                    description=str(check.get("details") or check.get("description") or "")[:2000],
                    severity=severity,
                    evidence=Evidence(
                        file=file_path or None,
                        raw={
                            "check_id": check_id,
                            "bc_check_id": check.get("bc_check_id"),
                            "resource": resource,
                            "framework": check.get("check_type"),
                            "file_path": file_path,
                            "guideline": guideline,
                            "check_class": check.get("check_class"),
                        },
                    ),
                    remediation=(guideline or "Review the Checkov policy guidance and remediate the misconfiguration.")[:1000],
                    references=[guideline] if guideline else [],
                )
            )
        return out
