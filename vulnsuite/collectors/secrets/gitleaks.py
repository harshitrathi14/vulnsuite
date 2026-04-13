"""
VulnSuite - Gitleaks collector (secrets scanning)

Wraps the `gitleaks` CLI in `detect` mode for filesystem/repo scans.
Normalizes gitleaks JSON output into the canonical Finding schema.

Secrets findings have no CVE and no CVSS, so they rely on the risk
engine's severity->CVSS fallback + EPSS floor. A leaked production
secret on an internet-facing asset will still land in P0 thanks to
the exposure and criticality multipliers.

Requires: gitleaks binary on PATH (https://github.com/gitleaks/gitleaks).
"""
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


# Heuristic: rule IDs containing these tokens are treated as CRITICAL.
# Everything else in gitleaks is HIGH by default — a leaked secret is
# never "low" in our book, it's just a question of blast radius.
_CRITICAL_RULE_HINTS = (
    "aws", "gcp", "azure", "private-key", "private_key", "rsa",
    "stripe", "slack-bot", "github-pat", "jwt",
)


class GitleaksNotInstalled(RuntimeError):
    pass


class GitleaksCollector:
    def __init__(
        self,
        binary: str = "gitleaks",
        timeout_seconds: int = 600,
        config_path: str | None = None,
        redact: bool = True,
    ) -> None:
        if shutil.which(binary) is None:
            raise GitleaksNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.config_path = config_path
        self.redact = redact

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
            errors.append(f"gitleaks timeout after {self.timeout}s")
            logger.exception("gitleaks timeout on %s", target)
        except Exception as e:  # noqa: BLE001
            errors.append(f"gitleaks error: {e}")
            logger.exception("gitleaks failed on %s", target)

        return ScanResult(
            tool="gitleaks",
            module=Module.SECRETS,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    # ---------- internals ----------

    async def _run(self, target: str) -> list[dict]:
        if not Path(target).exists():
            raise FileNotFoundError(target)

        # gitleaks writes JSON to a report file, not stdout, so use a temp file.
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as tmp:
            report_path = tmp.name

        cmd = [
            self.binary, "detect",
            "--source", target,
            "--report-format", "json",
            "--report-path", report_path,
            "--no-banner",
            "--exit-code", "0",   # don't fail on findings
        ]
        if self.redact:
            cmd.append("--redact")
        if self.config_path:
            cmd += ["--config", self.config_path]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise

        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"gitleaks exit {proc.returncode}: "
                f"{stderr.decode(errors='ignore')[:500]}"
            )

        try:
            text = Path(report_path).read_text() or "[]"
            return json.loads(text)
        finally:
            Path(report_path).unlink(missing_ok=True)

    def _normalize(
        self, raw: list[dict], tenant_id: UUID, asset_id: UUID,
    ) -> list[Finding]:
        out: list[Finding] = []
        for item in raw or []:
            rule_id = (item.get("RuleID") or "unknown").lower()
            sev = (
                Severity.CRITICAL
                if any(h in rule_id for h in _CRITICAL_RULE_HINTS)
                else Severity.HIGH
            )
            file_path = item.get("File") or ""
            start_line = item.get("StartLine") or 0
            commit = item.get("Commit") or ""
            author = item.get("Author") or ""
            match = item.get("Match") or ""  # already redacted if --redact

            out.append(Finding(
                tenant_id=tenant_id,
                asset_id=asset_id,
                tool="gitleaks",
                module=Module.SECRETS,
                title=f"Secret leaked: {rule_id}",
                description=(item.get("Description") or "")[:1000],
                cwe=["CWE-798"],  # Use of Hard-coded Credentials
                severity=sev,
                evidence=Evidence(
                    file=file_path,
                    line=start_line,
                    snippet=match[:200],
                    raw={
                        "rule_id": rule_id,
                        "commit": commit,
                        "author": author,
                        "entropy": item.get("Entropy"),
                        "tags": item.get("Tags", []),
                    },
                ),
                remediation=(
                    "1) Revoke the credential at the provider immediately. "
                    "2) Rotate to a new secret stored in a vault "
                    "(HashiCorp Vault, AWS Secrets Manager, Azure Key Vault). "
                    "3) Rewrite git history to purge the leak "
                    "(git-filter-repo or BFG). "
                    "4) Audit access logs for the exposed credential."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/798.html",
                    "https://github.com/gitleaks/gitleaks",
                ],
            ))
        return out
