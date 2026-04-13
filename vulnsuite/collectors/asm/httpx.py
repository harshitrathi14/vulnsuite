"""VulnSuite - httpx wrapper for ASM HTTP/service enrichment."""
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


class HttpxNotInstalled(RuntimeError):
    pass


class HttpxCollector:
    def __init__(self, binary: str = "httpx", timeout_seconds: int = 900) -> None:
        if shutil.which(binary) is None:
            raise HttpxNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds

    async def scan(
        self,
        hosts: list[str],
        tenant_id: UUID,
        asset_id: UUID,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors: list[str] = []
        if not hosts:
            return ScanResult(
                tool="httpx",
                module=Module.ASM,
                asset_id=asset_id,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                findings=[],
                errors=[],
            )
        try:
            raw = await self._run(hosts)
            findings = self._normalize(raw, tenant_id, asset_id)
        except asyncio.TimeoutError:
            errors.append(f"httpx timeout after {self.timeout}s")
        except Exception as exc:  # noqa: BLE001
            logger.exception("httpx failed")
            errors.append(f"httpx error: {exc}")
        return ScanResult(
            tool="httpx",
            module=Module.ASM,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    async def _run(self, hosts: list[str]) -> list[dict]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(hosts))
            input_path = tmp.name

        cmd = [
            self.binary,
            "-silent",
            "-json",
            "-l",
            input_path,
            "-title",
            "-status-code",
            "-tech-detect",
            "-web-server",
            "-tls-probe",
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

        if proc.returncode != 0:
            raise RuntimeError(
                f"httpx exit {proc.returncode}: {stderr.decode(errors='ignore')[:500]}"
            )
        return [json.loads(line) for line in stdout.decode(errors="ignore").splitlines() if line.strip()]

    def _normalize(self, raw: list[dict], tenant_id: UUID, asset_id: UUID) -> list[Finding]:
        out: list[Finding] = []
        for item in raw:
            scheme = str(item.get("scheme") or "")
            port = int(item.get("port") or 0)
            severity = Severity.INFO
            if scheme == "http" and port in {80, 8080}:
                severity = Severity.MEDIUM
            elif scheme == "https":
                severity = Severity.LOW
            host = str(item.get("host") or item.get("input") or "")
            title = f"Exposed service discovered on {host}:{port}" if port else f"Exposed service discovered on {host}"
            out.append(
                Finding(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    tool="httpx",
                    module=Module.ASM,
                    title=title,
                    description=f"httpx detected a reachable service at {item.get('url') or host}.",
                    severity=severity,
                    evidence=Evidence(
                        raw={
                            "host": host,
                            "url": item.get("url"),
                            "port": port,
                            "scheme": scheme,
                            "status_code": item.get("status_code"),
                            "title": item.get("title"),
                            "tech": item.get("tech"),
                            "webserver": item.get("webserver"),
                            "tls": item.get("tls"),
                            "fingerprint": item.get("hash"),
                        }
                    ),
                    remediation="Review whether the endpoint should be internet-accessible and enforce HTTPS plus upstream access controls.",
                    references=["https://docs.projectdiscovery.io/opensource/httpx/overview"],
                )
            )
        return out
