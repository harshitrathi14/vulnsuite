"""
VulnSuite - Bandit collector (Python-specific SAST)

Bandit is the de-facto Python security linter, maintained by PyCQA.
It walks the Python AST and flags insecure API usage patterns that
generic SAST tools (Semgrep) sometimes miss or under-weight:
pickle.loads, yaml.load (unsafe loader), eval/exec, subprocess with
shell=True, weak crypto (MD5/SHA1/DES), hardcoded temp paths,
assert-based security checks, XML parsers with entity expansion, and
insecure SSL context defaults.

Role in the suite:
- Semgrep: broad, multi-language, OWASP Top 10, pattern-driven
- Bandit: Python-only, AST-driven, CWE-mapped to B-codes
- Overlap is intentional. For Python-heavy BFSI stacks (Django, Flask,
  FastAPI microservices) Bandit catches idioms Semgrep's generic
  Python rules don't cover, particularly around crypto primitives and
  deserialization — both heavily audited under RBI and ISO 27001 A.14.

Why this matters specifically for Indian BFSI:
- RBI's Cyber Security Framework (2016, updated) explicitly flags
  weak cryptography and insecure deserialization as high-risk.
- Bandit's B-code taxonomy (B301 pickle, B303 MD5, B506 yaml.load,
  B602 subprocess shell=True, B608 hardcoded_sql) maps cleanly to
  these audit requirements, giving the CISO a direct control-to-
  finding trace for regulators.

Requires: bandit on PATH (pip install bandit).
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

# Bandit emits SEVERITY in {LOW, MEDIUM, HIGH} and CONFIDENCE in
# {LOW, MEDIUM, HIGH}. We combine them into our 5-level scale using
# a matrix that matches OWASP risk rating. Confidence=LOW findings are
# demoted because Bandit is famously noisy on them.
_RISK_MATRIX: dict[tuple[str, str], Severity] = {
    ("HIGH",   "HIGH"):   Severity.CRITICAL,
    ("HIGH",   "MEDIUM"): Severity.HIGH,
    ("HIGH",   "LOW"):    Severity.MEDIUM,
    ("MEDIUM", "HIGH"):   Severity.HIGH,
    ("MEDIUM", "MEDIUM"): Severity.MEDIUM,
    ("MEDIUM", "LOW"):    Severity.LOW,
    ("LOW",    "HIGH"):   Severity.MEDIUM,
    ("LOW",    "MEDIUM"): Severity.LOW,
    ("LOW",    "LOW"):    Severity.INFO,
}

# Default test profile: everything except noisy assert_used (B101),
# which is nearly always a false positive in test files.
_DEFAULT_SKIPS = ("B101",)


class BanditNotInstalled(RuntimeError):
    pass


class BanditCollector:
    def __init__(
        self,
        binary: str = "bandit",
        timeout_seconds: int = 900,
        confidence_floor: str = "LOW",      # report all, demote in matrix
        severity_floor: str = "LOW",
        skip_tests: tuple[str, ...] = _DEFAULT_SKIPS,
        exclude_paths: tuple[str, ...] = (
            "tests", "test", ".venv", "venv", "node_modules", ".git",
        ),
        config_file: str | None = None,
    ) -> None:
        if shutil.which(binary) is None:
            raise BanditNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.confidence_floor = confidence_floor
        self.severity_floor = severity_floor
        self.skip_tests = skip_tests
        self.exclude_paths = exclude_paths
        self.config_file = config_file

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
            errors.append(f"bandit timeout after {self.timeout}s")
            logger.exception("bandit timeout on %s", target)
        except Exception as e:  # noqa: BLE001
            errors.append(f"bandit error: {e}")
            logger.exception("bandit failed on %s", target)

        return ScanResult(
            tool="bandit",
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
            self.binary,
            "--recursive",
            "--format", "json",
            "--quiet",
            "--confidence-level", self.confidence_floor.lower(),
            "--severity-level", self.severity_floor.lower(),
        ]
        if self.skip_tests:
            cmd += ["--skip", ",".join(self.skip_tests)]
        if self.exclude_paths:
            cmd += ["--exclude", ",".join(self.exclude_paths)]
        if self.config_file:
            cmd += ["--configfile", self.config_file]
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

        # bandit exit codes: 0 = clean, 1 = findings, 2 = error
        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"bandit exit {proc.returncode}: "
                f"{stderr.decode(errors='ignore')[:500]}"
            )
        if not stdout:
            return {}
        return json.loads(stdout)

    def _normalize(
        self, raw: dict, tenant_id: UUID, asset_id: UUID,
    ) -> list[Finding]:
        """
        Bandit JSON shape:
        {
          "results": [
            {
              "test_id": "B303", "test_name": "blacklist",
              "issue_severity": "MEDIUM", "issue_confidence": "HIGH",
              "issue_cwe": {"id": 327, "link": "..."},
              "issue_text": "...", "filename": "...",
              "line_number": 42, "line_range": [42, 44],
              "code": "...", "more_info": "..."
            }
          ]
        }
        """
        out: list[Finding] = []
        for r in raw.get("results", []) or []:
            sev = (r.get("issue_severity") or "LOW").upper()
            conf = (r.get("issue_confidence") or "LOW").upper()
            mapped = _RISK_MATRIX.get((sev, conf), Severity.INFO)

            test_id = r.get("test_id", "B000")     # e.g. B303
            test_name = r.get("test_name", "")      # e.g. blacklist
            cwe_obj = r.get("issue_cwe") or {}
            cwe_id = cwe_obj.get("id")
            cwes = [f"CWE-{cwe_id}"] if cwe_id else []

            out.append(Finding(
                tenant_id=tenant_id,
                asset_id=asset_id,
                tool="bandit",
                module=Module.SAST,
                title=f"{test_id} {test_name}".strip(),
                description=(r.get("issue_text") or "")[:2000],
                cwe=cwes,
                severity=mapped,
                evidence=Evidence(
                    file=r.get("filename", ""),
                    line=r.get("line_number", 0),
                    snippet=(r.get("code") or "")[:400],
                    raw={
                        "test_id": test_id,
                        "test_name": test_name,
                        "bandit_severity": sev,
                        "bandit_confidence": conf,
                        "line_range": r.get("line_range"),
                        "more_info": r.get("more_info"),
                    },
                ),
                remediation=self._remediation_hint(test_id),
                references=[
                    cwe_obj.get("link"),
                    r.get("more_info"),
                ],
            ))
        return out

    # ---------- helpers ----------

    @staticmethod
    def _remediation_hint(test_id: str) -> str:
        """
        Curated remediation for the Bandit checks most likely to fire
        in BFSI codebases. Fallback points to the Bandit docs.
        """
        hints = {
            "B301": "pickle is unsafe for untrusted data. Use JSON or a "
                    "signed serialization library (itsdangerous).",
            "B303": "MD5/SHA1 are cryptographically broken. Use SHA-256 "
                    "or BLAKE2 via hashlib; for password hashing use "
                    "argon2-cffi or bcrypt.",
            "B304": "Insecure cipher (DES/RC4/Blowfish). Use AES-256-GCM "
                    "via the `cryptography` library.",
            "B305": "Insecure cipher mode (ECB). Use GCM or CBC with HMAC.",
            "B324": "hashlib with insecure algorithm. Use SHA-256+ or "
                    "password-hashing library.",
            "B501": "requests call with verify=False disables TLS "
                    "validation. Remove it or pin a CA bundle.",
            "B502": "Insecure SSL/TLS version. Enforce TLS 1.2+ "
                    "(RBI mandate).",
            "B506": "yaml.load without SafeLoader enables arbitrary "
                    "code execution. Use yaml.safe_load.",
            "B602": "subprocess with shell=True enables command "
                    "injection. Pass args as a list, shell=False.",
            "B608": "Possible SQL injection via string concatenation. "
                    "Use parameterized queries.",
        }
        return hints.get(
            test_id,
            f"Review Bandit {test_id} guidance: "
            f"https://bandit.readthedocs.io/en/latest/plugins/",
        )
