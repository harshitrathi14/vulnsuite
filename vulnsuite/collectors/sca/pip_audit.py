"""
VulnSuite - pip-audit collector (Python SCA, belt-and-braces for Trivy)

Wraps the `pip-audit` CLI to scan Python projects against the PyPA
Advisory Database and OSV. Complements Trivy: pip-audit consumes the
actual resolved environment (requirements.txt, pyproject.toml, or a
live venv) and catches advisories that Trivy's package-manifest
parser occasionally misses, especially for editable installs and
extras.

Deduplication of CVEs across Trivy and pip-audit happens later in
the orchestrator, keyed on (asset_id, cve, pkg_name, installed_version).

Requires: pip-audit on PATH (pip install pip-audit).
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import UUID

from ...core.schema import Evidence, Finding, Module, ScanResult, Severity

logger = logging.getLogger(__name__)

PipAuditSource = Literal["requirements", "project", "environment"]


class PipAuditNotInstalled(RuntimeError):
    pass


class PipAuditCollector:
    """Async pip-audit wrapper. Supports three input modes."""

    def __init__(
        self,
        binary: str = "pip-audit",
        timeout_seconds: int = 600,
        offline: bool = False,
        index_url: str | None = None,
    ) -> None:
        if shutil.which(binary) is None:
            raise PipAuditNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.offline = offline
        self.index_url = index_url

    # ---------- public ----------

    async def scan(
        self,
        target: str,
        source: PipAuditSource,
        tenant_id: UUID,
        asset_id: UUID,
    ) -> ScanResult:
        """
        target: path to requirements.txt, project dir, or "" for `source=environment`
        source: requirements | project | environment
        """
        started = datetime.now(timezone.utc)
        errors: list[str] = []
        findings: list[Finding] = []

        try:
            raw = await self._run(target, source)
            findings = self._normalize(raw, tenant_id, asset_id)
        except asyncio.TimeoutError:
            errors.append(f"pip-audit timeout after {self.timeout}s")
            logger.exception("pip-audit timeout on %s", target)
        except Exception as e:  # noqa: BLE001
            errors.append(f"pip-audit error: {e}")
            logger.exception("pip-audit failed on %s", target)

        return ScanResult(
            tool="pip-audit",
            module=Module.SCA,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    # ---------- internals ----------

    async def _run(self, target: str, source: PipAuditSource) -> dict:
        cmd = [self.binary, "--format", "json", "--progress-spinner", "off"]

        if source == "requirements":
            if not Path(target).is_file():
                raise FileNotFoundError(target)
            cmd += ["--requirement", target]
        elif source == "project":
            if not Path(target).is_dir():
                raise FileNotFoundError(target)
            cmd += ["--project-path", target]
        elif source == "environment":
            pass  # scans the active Python env
        else:
            raise ValueError(f"unknown source: {source}")

        if self.index_url:
            cmd += ["--index-url", self.index_url]
        if self.offline:
            # pip-audit has no true offline flag; cache-only behavior
            # is achieved via the PyPA DB cache in ~/.pip-audit
            cmd += ["--cache-dir", str(Path.home() / ".pip-audit")]

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

        # pip-audit: 0 = no vulns, 1 = vulns found, others = error
        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"pip-audit exit {proc.returncode}: "
                f"{stderr.decode(errors='ignore')[:500]}"
            )
        if not stdout:
            return {}
        return json.loads(stdout)

    def _normalize(
        self, raw: dict, tenant_id: UUID, asset_id: UUID,
    ) -> list[Finding]:
        """
        pip-audit JSON shape (v2.7+):
        {
          "dependencies": [
            {
              "name": "...",
              "version": "...",
              "vulns": [
                {"id": "GHSA-...", "fix_versions": [...],
                 "aliases": ["CVE-..."], "description": "..."}
              ]
            }
          ]
        }
        """
        out: list[Finding] = []
        for dep in raw.get("dependencies", []) or []:
            pkg = dep.get("name", "?")
            ver = dep.get("version", "?")
            for v in dep.get("vulns", []) or []:
                aliases = v.get("aliases", []) or []
                cves = [a for a in aliases if a.upper().startswith("CVE-")]
                advisory_id = v.get("id", "")
                fix_versions = v.get("fix_versions", []) or []

                # pip-audit doesn't ship CVSS directly; let the risk
                # engine's severity->CVSS fallback handle it. We mark
                # everything MEDIUM by default and upgrade when fix
                # version is absent (unpatched = worse).
                sev = Severity.MEDIUM if fix_versions else Severity.HIGH

                title = f"{cves[0] if cves else advisory_id} in {pkg} {ver}"
                out.append(Finding(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    tool="pip-audit",
                    module=Module.SCA,
                    title=title,
                    description=(v.get("description") or "")[:2000],
                    cve=cves,
                    severity=sev,
                    evidence=Evidence(
                        raw={
                            "pkg_name": pkg,
                            "installed_version": ver,
                            "fix_versions": fix_versions,
                            "advisory_id": advisory_id,
                            "aliases": aliases,
                            "data_source": "PyPA/OSV",
                        },
                    ),
                    remediation=(
                        f"Upgrade {pkg} to {fix_versions[0]}"
                        if fix_versions
                        else f"No fix released yet for {pkg} {ver}. "
                             f"Consider pinning an alternative or "
                             f"applying a virtual patch at the WAF/ingress."
                    ),
                    references=[
                        f"https://osv.dev/vulnerability/{advisory_id}"
                    ] if advisory_id else [],
                ))
        return out
