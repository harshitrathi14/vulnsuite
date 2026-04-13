"""VulnSuite - Syft collector for SBOM generation and hygiene checks."""
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


class SyftNotInstalled(RuntimeError):
    pass


class SyftCollector:
    def __init__(self, binary: str = "syft", timeout_seconds: int = 900) -> None:
        if shutil.which(binary) is None:
            raise SyftNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds

    async def export_sbom(self, source: str) -> Path:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output = Path(tmp.name)
        cmd = [self.binary, source, "-o", "cyclonedx-json"]
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
        if proc.returncode != 0:
            output.unlink(missing_ok=True)
            raise RuntimeError(f"syft exit {proc.returncode}: {stderr.decode(errors='ignore')[:500]}")
        output.write_bytes(stdout)
        return output

    async def scan(
        self,
        sources: list[str],
        tenant_id: UUID,
        asset_id: UUID,
        input_is_sbom: bool = False,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors: list[str] = []
        temp_paths: list[Path] = []
        try:
            sbom_paths: list[Path] = []
            if input_is_sbom:
                sbom_paths = [Path(source) for source in sources]
            else:
                for source in sources:
                    path = await self.export_sbom(source)
                    temp_paths.append(path)
                    sbom_paths.append(path)

            for sbom_path in sbom_paths:
                findings.extend(self._normalize(json.loads(sbom_path.read_text() or "{}"), tenant_id, asset_id))
        except Exception as exc:  # noqa: BLE001
            logger.exception("syft failed")
            errors.append(f"syft error: {exc}")
        finally:
            for path in temp_paths:
                path.unlink(missing_ok=True)

        return ScanResult(
            tool="syft",
            module=Module.SUPPLY_CHAIN,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    def _normalize(self, sbom: dict, tenant_id: UUID, asset_id: UUID) -> list[Finding]:
        out: list[Finding] = []
        for component in sbom.get("components", []) or []:
            purl = str(component.get("purl") or "")
            version = str(component.get("version") or "")
            if purl and version:
                continue
            missing = "PURL" if not purl else "version"
            out.append(
                Finding(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    tool="syft",
                    module=Module.SUPPLY_CHAIN,
                    title=f"SBOM component missing {missing}: {component.get('name')}",
                    description="Syft generated or ingested an SBOM component with incomplete identity metadata.",
                    severity=Severity.LOW,
                    evidence=Evidence(
                        raw={
                            "component_name": component.get("name"),
                            "component_type": component.get("type"),
                            "purl": purl,
                            "version": version,
                            "bom_ref": component.get("bom-ref"),
                        }
                    ),
                    remediation="Regenerate the SBOM from a higher-fidelity source or enrich the package metadata so the component has a stable identity.",
                    references=["https://github.com/anchore/syft"],
                )
            )
        return out
