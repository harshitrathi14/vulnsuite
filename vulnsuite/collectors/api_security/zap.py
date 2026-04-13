"""VulnSuite - OWASP ZAP Automation Framework collector."""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import yaml

from ...core.schema import DASTMode, Evidence, Finding, Module, ScanResult, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


class ZAPNotInstalled(RuntimeError):
    pass


class ZAPAutomationCollector:
    def __init__(self, binary: str = "zap.sh", timeout_seconds: int = 1800) -> None:
        if shutil.which(binary) is None:
            raise ZAPNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds

    async def scan(
        self,
        tenant_id: UUID,
        asset_id: UUID,
        api_base_urls: list[str],
        api_specs: list[str],
        dast_mode: DASTMode,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors: list[str] = []
        if dast_mode == DASTMode.OFF:
            return ScanResult(
                tool="zap",
                module=Module.API_SECURITY,
                asset_id=asset_id,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                findings=[],
                errors=[],
            )
        try:
            report = await self._run(api_base_urls, api_specs, dast_mode)
            findings = self._normalize(report, tenant_id, asset_id)
        except asyncio.TimeoutError:
            errors.append(f"zap timeout after {self.timeout}s")
        except Exception as exc:  # noqa: BLE001
            logger.exception("zap failed")
            errors.append(f"zap error: {exc}")
        return ScanResult(
            tool="zap",
            module=Module.API_SECURITY,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    async def _run(self, api_base_urls: list[str], api_specs: list[str], dast_mode: DASTMode) -> dict:
        with tempfile.TemporaryDirectory(prefix="zap-af-") as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.yaml"
            report_path = Path(tmp_dir) / "report.json"
            plan = self._build_plan(api_base_urls, api_specs, dast_mode, report_path)
            plan_path.write_text(yaml.safe_dump(plan, sort_keys=False))

            proc = await asyncio.create_subprocess_exec(
                self.binary,
                "-cmd",
                "-autorun",
                str(plan_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise

            if proc.returncode not in (0, 1, 2):
                raise RuntimeError(
                    f"zap exit {proc.returncode}: {stderr.decode(errors='ignore')[:500]}"
                )
            if not report_path.exists():
                return {}
            return json.loads(report_path.read_text() or "{}")

    @staticmethod
    def _build_plan(
        api_base_urls: list[str],
        api_specs: list[str],
        dast_mode: DASTMode,
        report_path: Path,
    ) -> dict:
        jobs: list[dict] = []
        for spec in api_specs:
            jobs.append({"type": "openapi", "parameters": {"apiFile": spec}})
        if api_base_urls:
            jobs.append({"type": "spider", "parameters": {"url": api_base_urls[0], "maxDuration": 5}})
            jobs.append({"type": "passiveScan-wait", "parameters": {"maxDuration": 5}})
            if dast_mode == DASTMode.ACTIVE:
                jobs.append({"type": "activeScan", "parameters": {"policy": "Default Policy"}})
        jobs.append(
            {
                "type": "report",
                "parameters": {
                    "template": "traditional-json",
                    "reportFile": str(report_path),
                    "reportDir": str(report_path.parent),
                },
            }
        )
        return {
            "env": {
                "contexts": [{"name": "default", "urls": api_base_urls or ["http://localhost"]}],
                "parameters": {"failOnError": False},
            },
            "jobs": jobs,
        }

    def _normalize(self, report: dict, tenant_id: UUID, asset_id: UUID) -> list[Finding]:
        out: list[Finding] = []
        for site in report.get("site", []) or []:
            for alert in site.get("alerts", []) or []:
                severity = _SEVERITY_MAP.get(str(alert.get("riskdesc") or "info").split()[0].lower(), Severity.INFO)
                instances = alert.get("instances", []) or [{}]
                for instance in instances:
                    cwe = str(alert.get("cweid") or "").strip()
                    out.append(
                        Finding(
                            tenant_id=tenant_id,
                            asset_id=asset_id,
                            tool="zap",
                            module=Module.API_SECURITY,
                            title=f"{alert.get('pluginid')}: {alert.get('name')}",
                            description=str(alert.get("desc") or "")[:2000],
                            cwe=[f"CWE-{cwe}"] if cwe and cwe != "-1" else [],
                            severity=severity,
                            evidence=Evidence(
                                raw={
                                    "rule_id": alert.get("pluginid"),
                                    "path_or_url": instance.get("uri"),
                                    "method": instance.get("method"),
                                    "param": instance.get("param"),
                                    "attack": instance.get("attack"),
                                    "evidence": instance.get("evidence"),
                                    "solution": alert.get("solution"),
                                }
                            ),
                            remediation=str(alert.get("solution") or "Review the ZAP finding and harden the affected API endpoint.")[:1000],
                            references=[str(ref) for ref in (alert.get("reference") or "").splitlines() if ref],
                        )
                    )
        return out
