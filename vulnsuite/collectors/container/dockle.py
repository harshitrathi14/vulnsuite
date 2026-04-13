"""VulnSuite - Dockle container image hardening collector (CIS Docker Benchmark)."""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone
from uuid import UUID

from ...core.schema import Evidence, Finding, Module, ScanResult, Severity

logger = logging.getLogger(__name__)

_SEV_MAP = {
    "FATAL": Severity.CRITICAL,
    "WARN": Severity.HIGH,
    "INFO": Severity.MEDIUM,
    "SKIP": Severity.INFO,
    "PASS": Severity.INFO,
}


class DockleNotInstalled(RuntimeError):
    pass


class DockleCollector:
    def __init__(
        self,
        binary: str = "dockle",
        timeout_seconds: int = 600,
        exit_level: str = "info",
    ) -> None:
        if shutil.which(binary) is None:
            raise DockleNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.exit_level = exit_level

    async def scan(
        self, image: str, tenant_id: UUID, asset_id: UUID,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        errors: list[str] = []
        findings: list[Finding] = []

        try:
            raw = await self._run(image)
            findings = self._normalize(raw, tenant_id, asset_id, image)
        except asyncio.TimeoutError:
            errors.append(f"dockle timeout after {self.timeout}s")
        except Exception as e:  # noqa: BLE001
            errors.append(f"dockle error: {e}")
            logger.exception("dockle failed on %s", image)

        return ScanResult(
            tool="dockle", module=Module.CONTAINER, asset_id=asset_id,
            started_at=started, finished_at=datetime.now(timezone.utc),
            findings=findings, errors=errors,
        )

    async def _run(self, image: str) -> dict:
        cmd = [
            self.binary,
            "--format", "json",
            "--exit-code", "0",
            "--exit-level", self.exit_level,
            "--no-color",
            image,
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

        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"dockle exit {proc.returncode}: "
                f"{stderr.decode(errors='ignore')[:500]}"
            )
        if not stdout:
            return {}
        return json.loads(stdout)

    def _normalize(
        self, raw: dict, tenant_id: UUID, asset_id: UUID, image: str,
    ) -> list[Finding]:
        out: list[Finding] = []
        for item in raw.get("details", []) or []:
            level = (item.get("level") or "INFO").upper()
            if level in ("PASS", "SKIP"):
                continue
            sev = _SEV_MAP.get(level, Severity.INFO)
            code = item.get("code", "CIS-DI-0000")
            title = item.get("title", "")
            alerts = item.get("alerts", []) or []

            out.append(Finding(
                tenant_id=tenant_id,
                asset_id=asset_id,
                tool="dockle",
                module=Module.CONTAINER,
                title=f"{code}: {title}",
                description="; ".join(str(a) for a in alerts)[:2000],
                severity=sev,
                evidence=Evidence(
                    raw={
                        "image": image,
                        "code": code,
                        "level": level,
                        "alerts": alerts,
                        "cis_benchmark": "CIS Docker Benchmark",
                    },
                ),
                remediation=self._remediation_hint(code),
                references=[
                    "https://github.com/goodwithtech/dockle",
                    "https://www.cisecurity.org/benchmark/docker",
                ],
            ))
        return out

    @staticmethod
    def _remediation_hint(code: str) -> str:
        hints = {
            "CIS-DI-0001": "Create a non-root USER in the Dockerfile and run the container as that user.",
            "CIS-DI-0002": "Use a specific, pinned base image tag — never :latest.",
            "CIS-DI-0005": "Enable Content Trust (DOCKER_CONTENT_TRUST=1) and sign images.",
            "CIS-DI-0006": "Add a HEALTHCHECK instruction to the Dockerfile.",
            "CIS-DI-0008": "Remove setuid/setgid bits from files in the image.",
            "CIS-DI-0009": "Use COPY instead of ADD unless remote URLs are required.",
            "CIS-DI-0010": "Never store secrets in image layers; use Key Vault / Secrets Manager at runtime.",
            "DKL-DI-0006": "Avoid --privileged flag; drop all caps and add back only what is needed.",
            "DKL-LI-0001": "Do not install sudo inside containers.",
            "DKL-LI-0003": "Only expose ports the application actually needs.",
        }
        return hints.get(
            code,
            "Review Dockle documentation for this CIS Docker Benchmark rule.",
        )
