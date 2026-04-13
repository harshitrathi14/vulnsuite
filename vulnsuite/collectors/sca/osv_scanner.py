"""
VulnSuite - OSV-Scanner collector (multi-language SCA)

Wraps Google's `osv-scanner` CLI, which queries the OSV.dev database
covering Python (PyPI), JavaScript (npm), Go, Rust (crates.io), Java
(Maven), Ruby (RubyGems), Debian, Alpine, and more.

Role in the suite:
- Trivy: broad coverage, container-optimized, NVD-first CVSS
- pip-audit: Python deep-dive, PyPA advisory DB
- osv-scanner: multi-language deep-dive, OSV.dev (Google-curated,
  often fresher than NVD for ecosystem advisories)

Deduplication across the three SCA tools happens in core/orchestrator.py
on (asset_id, cve, pkg_name, installed_version). Running all three is
the BFSI belt-and-braces pattern: if one tool misses a CVE due to a
DB lag or parser bug, another catches it, and the auditor sees
cross-tool corroboration in the evidence block.

Requires: osv-scanner on PATH (https://github.com/google/osv-scanner).
"""
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

# OSV ecosystem severity is usually CVSS v3. When absent we derive from
# the advisory's database_specific.severity string (GHSA convention).
_DB_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class OSVScannerNotInstalled(RuntimeError):
    pass


class OSVScannerCollector:
    def __init__(
        self,
        binary: str = "osv-scanner",
        timeout_seconds: int = 900,
        offline_db_dir: str | None = None,
        skip_git: bool = False,
        recursive: bool = True,
    ) -> None:
        if shutil.which(binary) is None:
            raise OSVScannerNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.offline_db_dir = offline_db_dir
        self.skip_git = skip_git
        self.recursive = recursive

    # ---------- public ----------

    async def scan(
        self,
        target: str,
        tenant_id: UUID,
        asset_id: UUID,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        errors: list[str] = []
        findings: list[Finding] = []

        try:
            raw = await self._run(target)
            findings = self._normalize(raw, tenant_id, asset_id)
        except asyncio.TimeoutError:
            errors.append(f"osv-scanner timeout after {self.timeout}s")
            logger.exception("osv-scanner timeout on %s", target)
        except Exception as e:  # noqa: BLE001
            errors.append(f"osv-scanner error: {e}")
            logger.exception("osv-scanner failed on %s", target)

        return ScanResult(
            tool="osv-scanner",
            module=Module.SCA,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    # ---------- internals ----------

    async def _run(self, target: str) -> dict:
        if not Path(target).exists():
            raise FileNotFoundError(target)

        cmd = [self.binary, "scan", "source", "--format", "json"]
        if self.recursive:
            cmd.append("--recursive")
        if self.skip_git:
            cmd.append("--skip-git")
        if self.offline_db_dir:
            # Offline mode: pre-downloaded OSV DB on a jump host, essential
            # for air-gapped BFSI deployments.
            cmd += ["--offline-vulnerabilities",
                    "--local-db-path", self.offline_db_dir]
        cmd.append(target)

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

        # osv-scanner: 0 = clean, 1 = vulns found, 127+ = error
        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"osv-scanner exit {proc.returncode}: "
                f"{stderr.decode(errors='ignore')[:500]}"
            )
        if not stdout:
            return {}
        return json.loads(stdout)

    def _normalize(
        self, raw: dict, tenant_id: UUID, asset_id: UUID,
    ) -> list[Finding]:
        """
        osv-scanner JSON (v1.x):
        {
          "results": [
            {
              "source": {"path": "...", "type": "lockfile"},
              "packages": [
                {
                  "package": {"name": "...", "version": "...",
                              "ecosystem": "npm"},
                  "vulnerabilities": [
                    {
                      "id": "GHSA-...", "aliases": ["CVE-..."],
                      "summary": "...", "details": "...",
                      "severity": [{"type": "CVSS_V3",
                                    "score": "CVSS:3.1/..."}],
                      "affected": [...], "references": [...],
                      "database_specific": {"severity": "HIGH"}
                    }
                  ]
                }
              ]
            }
          ]
        }
        """
        out: list[Finding] = []
        for result in raw.get("results", []) or []:
            source_path = (result.get("source") or {}).get("path", "")
            for pkg in result.get("packages", []) or []:
                p = pkg.get("package", {}) or {}
                name = p.get("name", "?")
                version = p.get("version", "?")
                ecosystem = p.get("ecosystem", "?")

                for v in pkg.get("vulnerabilities", []) or []:
                    advisory_id = v.get("id", "")
                    aliases = v.get("aliases", []) or []
                    cves = [a for a in aliases
                            if a.upper().startswith("CVE-")]

                    cvss_base, cvss_vector = self._extract_cvss(v)
                    db_sev = ((v.get("database_specific") or {})
                              .get("severity") or "").upper()
                    sev = _DB_SEV_MAP.get(db_sev) or self._cvss_to_sev(cvss_base)

                    fix_versions = self._extract_fix_versions(v)

                    title = (f"{cves[0] if cves else advisory_id} in "
                             f"{name} {version} ({ecosystem})")
                    out.append(Finding(
                        tenant_id=tenant_id,
                        asset_id=asset_id,
                        tool="osv-scanner",
                        module=Module.SCA,
                        title=title,
                        description=(v.get("details")
                                     or v.get("summary") or "")[:2000],
                        cve=cves,
                        cvss_vector=cvss_vector,
                        cvss_base=cvss_base,
                        severity=sev,
                        evidence=Evidence(
                            file=source_path,
                            raw={
                                "pkg_name": name,
                                "installed_version": version,
                                "ecosystem": ecosystem,
                                "advisory_id": advisory_id,
                                "aliases": aliases,
                                "fix_versions": fix_versions,
                                "data_source": "OSV.dev",
                            },
                        ),
                        remediation=(
                            f"Upgrade {name} to {fix_versions[0]}"
                            if fix_versions
                            else f"No fix released yet for {name} {version}. "
                                 f"Pin alternative or apply virtual patch."
                        ),
                        references=[
                            r.get("url") for r in (v.get("references") or [])
                            if r.get("url")
                        ] or [f"https://osv.dev/vulnerability/{advisory_id}"],
                    ))
        return out

    # ---------- helpers ----------

    @staticmethod
    def _extract_cvss(v: dict) -> tuple[float, str | None]:
        """OSV `severity` is a list of {type, score}. Prefer CVSS_V3."""
        for entry in v.get("severity", []) or []:
            if (entry.get("type") or "").upper() in ("CVSS_V3", "CVSS_V4"):
                vector = entry.get("score")
                if vector and vector.startswith("CVSS:"):
                    # parse base score from vector tail if present
                    # osv stores vector-only; base score derived downstream
                    return (0.0, vector)
        return (0.0, None)

    @staticmethod
    def _cvss_to_sev(score: float) -> Severity:
        if score >= 9.0: return Severity.CRITICAL
        if score >= 7.0: return Severity.HIGH
        if score >= 4.0: return Severity.MEDIUM
        if score > 0.0: return Severity.LOW
        return Severity.MEDIUM  # unknown -> medium, never info

    @staticmethod
    def _extract_fix_versions(v: dict) -> list[str]:
        """Walk affected[].ranges[].events[] looking for 'fixed' events."""
        out: list[str] = []
        for aff in v.get("affected", []) or []:
            for rng in aff.get("ranges", []) or []:
                for ev in rng.get("events", []) or []:
                    if "fixed" in ev:
                        out.append(ev["fixed"])
        return out
