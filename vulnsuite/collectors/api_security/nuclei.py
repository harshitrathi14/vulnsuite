"""VulnSuite - Nuclei wrapper for API and HTTP template scanning."""
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

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class NucleiNotInstalled(RuntimeError):
    pass


class NucleiCollector:
    def __init__(
        self,
        binary: str = "nuclei",
        timeout_seconds: int = 1200,
        severity_floor: str = "medium",
    ) -> None:
        if shutil.which(binary) is None:
            raise NucleiNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.severity_floor = severity_floor

    async def scan(self, targets: list[str], tenant_id: UUID, asset_id: UUID) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors: list[str] = []
        if not targets:
            return ScanResult(
                tool="nuclei",
                module=Module.API_SECURITY,
                asset_id=asset_id,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                findings=[],
                errors=[],
            )
        try:
            raw = await self._run(targets)
            findings = self._normalize(raw, tenant_id, asset_id)
        except asyncio.TimeoutError:
            errors.append(f"nuclei timeout after {self.timeout}s")
        except Exception as exc:  # noqa: BLE001
            logger.exception("nuclei failed")
            errors.append(f"nuclei error: {exc}")
        return ScanResult(
            tool="nuclei",
            module=Module.API_SECURITY,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    async def _run(self, targets: list[str]) -> list[dict]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(targets))
            input_path = tmp.name
        cmd = [
            self.binary,
            "-l",
            input_path,
            "-jsonl",
            "-severity",
            self.severity_floor + ",high,critical,low,info",
        ]
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
        finally:
            Path(input_path).unlink(missing_ok=True)
        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"nuclei exit {proc.returncode}: {stderr.decode(errors='ignore')[:500]}"
            )
        return [json.loads(line) for line in stdout.decode(errors="ignore").splitlines() if line.strip()]

    def _normalize(self, raw: list[dict], tenant_id: UUID, asset_id: UUID) -> list[Finding]:
        out: list[Finding] = []
        for item in raw:
            info = item.get("info", {}) or {}
            classification = info.get("classification", {}) or {}
            severity = _SEVERITY_MAP.get(str(info.get("severity") or "info").lower(), Severity.INFO)
            cves = classification.get("cve-id") or []
            if isinstance(cves, str):
                cves = [cves]
            cwes = classification.get("cwe-id") or []
            if isinstance(cwes, str):
                cwes = [cwes]
            out.append(
                Finding(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    tool="nuclei",
                    module=Module.API_SECURITY,
                    title=f"{item.get('template-id')}: {info.get('name') or 'Nuclei finding'}",
                    description=str(info.get("description") or "")[:2000],
                    cve=list(cves),
                    cwe=[c if str(c).startswith("CWE-") else f"CWE-{c}" for c in cwes],
                    severity=severity,
                    evidence=Evidence(
                        raw={
                            "rule_id": item.get("template-id"),
                            "path_or_url": item.get("matched-at"),
                            "method": item.get("type"),
                            "host": item.get("host"),
                            "curl_command": item.get("curl-command"),
                        }
                    ),
                    remediation="Review the matched API template and remove the exposed behavior or harden the affected endpoint.",
                    references=[str(ref) for ref in (info.get("reference") or [])],
                )
            )
        return out
