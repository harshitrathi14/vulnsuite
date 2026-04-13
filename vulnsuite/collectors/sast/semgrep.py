"""
VulnSuite - Semgrep collector (SAST)

Wraps the `semgrep` CLI to perform static analysis on source code.
Normalizes Semgrep JSON output into the canonical Finding schema.

Rule pack strategy:
- Default: `p/default` (Semgrep's curated baseline)
- Security-focused: `p/security-audit` + `p/owasp-top-ten`
- BFSI hardening: add `p/secrets` (complements gitleaks with code-context
  detection) and language-specific packs (`p/python`, `p/java`, `p/javascript`)

We run against the online registry by default, but support offline
rule directories for air-gapped deployments (banks commonly require this).

Requires: semgrep binary on PATH (pip install semgrep).
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

# Semgrep uses ERROR/WARNING/INFO — map to our 5-level scale.
# Semgrep doesn't emit CRITICAL natively, so we promote ERROR findings
# whose metadata.confidence == "HIGH" and metadata.impact == "HIGH".
_BASE_SEV_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

_DEFAULT_RULE_PACKS = (
    "p/default",
    "p/security-audit",
    "p/owasp-top-ten",
    "p/secrets",
)


class SemgrepNotInstalled(RuntimeError):
    pass


class SemgrepCollector:
    def __init__(
        self,
        binary: str = "semgrep",
        timeout_seconds: int = 1800,      # SAST is slow on big repos
        rule_packs: tuple[str, ...] = _DEFAULT_RULE_PACKS,
        offline_rules_dir: str | None = None,
        max_target_bytes: int = 1_000_000,   # skip generated/vendor files
        jobs: int = 0,                     # 0 = auto
    ) -> None:
        if shutil.which(binary) is None:
            raise SemgrepNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.rule_packs = rule_packs
        self.offline_rules_dir = offline_rules_dir
        self.max_target_bytes = max_target_bytes
        self.jobs = jobs

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
            errors.append(f"semgrep timeout after {self.timeout}s")
            logger.exception("semgrep timeout on %s", target)
        except Exception as e:  # noqa: BLE001
            errors.append(f"semgrep error: {e}")
            logger.exception("semgrep failed on %s", target)

        return ScanResult(
            tool="semgrep",
            module=Module.SAST,
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

        cmd = [
            self.binary, "scan",
            "--json",
            "--quiet",
            "--metrics", "off",           # never phone home (BFSI compliance)
            "--disable-version-check",
            "--max-target-bytes", str(self.max_target_bytes),
            "--timeout", str(self.timeout // 2),   # per-rule timeout
        ]
        if self.jobs:
            cmd += ["--jobs", str(self.jobs)]

        if self.offline_rules_dir:
            cmd += ["--config", self.offline_rules_dir]
        else:
            for pack in self.rule_packs:
                cmd += ["--config", pack]

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

        # semgrep: 0 = clean, 1 = findings, 2+ = error
        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"semgrep exit {proc.returncode}: "
                f"{stderr.decode(errors='ignore')[:500]}"
            )
        if not stdout:
            return {}
        return json.loads(stdout)

    def _normalize(
        self, raw: dict, tenant_id: UUID, asset_id: UUID,
    ) -> list[Finding]:
        out: list[Finding] = []
        for r in raw.get("results", []) or []:
            extra = r.get("extra", {}) or {}
            meta = extra.get("metadata", {}) or {}
            check_id = r.get("check_id", "semgrep.rule")
            file_path = r.get("path", "")
            start_line = (r.get("start") or {}).get("line", 0)
            lines = extra.get("lines", "") or ""

            sev = self._severity(extra.get("severity"), meta)

            cwe_list = self._as_list(meta.get("cwe"))
            owasp_list = self._as_list(meta.get("owasp"))
            references = self._as_list(meta.get("references"))

            out.append(Finding(
                tenant_id=tenant_id,
                asset_id=asset_id,
                tool="semgrep",
                module=Module.SAST,
                title=f"{check_id}",
                description=(extra.get("message") or "")[:2000],
                cwe=[self._extract_cwe_id(c) for c in cwe_list if c],
                severity=sev,
                evidence=Evidence(
                    file=file_path,
                    line=start_line,
                    snippet=lines[:300],
                    raw={
                        "check_id": check_id,
                        "end_line": (r.get("end") or {}).get("line"),
                        "confidence": meta.get("confidence"),
                        "impact": meta.get("impact"),
                        "likelihood": meta.get("likelihood"),
                        "owasp": owasp_list,
                        "category": meta.get("category"),
                        "technology": meta.get("technology"),
                    },
                ),
                remediation=(extra.get("fix") or meta.get("fix") or "")[:1000]
                            or "Review the flagged code and apply the "
                               "remediation guidance in the referenced rule.",
                references=references,
            ))
        return out

    # ---------- helpers ----------

    @staticmethod
    def _severity(sg_sev: str | None, meta: dict) -> Severity:
        base = _BASE_SEV_MAP.get((sg_sev or "").upper(), Severity.INFO)
        # Promote to CRITICAL when both impact and confidence are HIGH
        if (
            base == Severity.HIGH
            and (meta.get("impact") or "").upper() == "HIGH"
            and (meta.get("confidence") or "").upper() == "HIGH"
        ):
            return Severity.CRITICAL
        return base

    @staticmethod
    def _as_list(v) -> list[str]:
        if v is None:
            return []
        if isinstance(v, list):
            return [str(x) for x in v]
        return [str(v)]

    @staticmethod
    def _extract_cwe_id(raw: str) -> str:
        """Semgrep emits CWE as 'CWE-79: Cross-site Scripting'. Normalize to 'CWE-79'."""
        raw = raw.strip().upper()
        if raw.startswith("CWE-"):
            return raw.split(":", 1)[0].strip()
        return raw
