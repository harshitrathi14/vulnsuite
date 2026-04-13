"""
VulnSuite - TruffleHog collector (secrets, with live verification)

Second-opinion secrets scanner complementing gitleaks. TruffleHog's
distinctive capability is *live credential verification*: for supported
detectors (AWS, GCP, Azure, Slack, Stripe, GitHub, etc.) it attempts
a benign authenticated API call to determine whether the leaked
credential is currently valid.

Why this matters for BFSI:
- A *verified-live* leaked credential is a P0 incident and triggers
  CERT-In's 6-hour reporting clock. An unverified hit may be a
  long-revoked test key buried in git history.
- Analyst triage time drops dramatically when the scanner tells you
  "this key still works" vs "this matches a regex".

Compliance caveat (important):
- Verification makes outbound authenticated API calls from the scanner
  host. Some BFSI security policies prohibit this from the CI network
  (data egress, audit trail concerns). We expose `verify=False` as a
  first-class option and default to it OFF. The CISO must explicitly
  opt in per environment.

Requires: trufflehog on PATH (https://github.com/trufflesecurity/trufflehog).
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

TruffleSource = Literal["filesystem", "git"]

# Verified leaks are always CRITICAL. Unverified hits are HIGH by default;
# the risk engine's exposure + criticality multipliers will push
# prod-internet-facing unverified leaks into P0 anyway.
_VERIFIED_SEV = Severity.CRITICAL
_UNVERIFIED_SEV = Severity.HIGH


class TruffleHogNotInstalled(RuntimeError):
    pass


class TruffleHogCollector:
    def __init__(
        self,
        binary: str = "trufflehog",
        timeout_seconds: int = 900,
        verify: bool = False,           # OFF by default; see module docstring
        only_verified: bool = False,    # emit only verified hits (low-noise mode)
        include_detectors: str | None = None,   # comma-separated detector names
        exclude_detectors: str | None = None,
    ) -> None:
        if shutil.which(binary) is None:
            raise TruffleHogNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.verify = verify
        self.only_verified = only_verified
        self.include_detectors = include_detectors
        self.exclude_detectors = exclude_detectors

    # ---------- public ----------

    async def scan(
        self,
        target: str,
        source: TruffleSource,
        tenant_id: UUID,
        asset_id: UUID,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        errors: list[str] = []
        findings: list[Finding] = []

        try:
            raw_events = await self._run(target, source)
            findings = self._normalize(raw_events, tenant_id, asset_id)
        except asyncio.TimeoutError:
            errors.append(f"trufflehog timeout after {self.timeout}s")
            logger.exception("trufflehog timeout on %s", target)
        except Exception as e:  # noqa: BLE001
            errors.append(f"trufflehog error: {e}")
            logger.exception("trufflehog failed on %s", target)

        return ScanResult(
            tool="trufflehog",
            module=Module.SECRETS,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    # ---------- internals ----------

    async def _run(self, target: str, source: TruffleSource) -> list[dict]:
        if source == "filesystem":
            if not Path(target).exists():
                raise FileNotFoundError(target)
            cmd = [self.binary, "filesystem", target]
        elif source == "git":
            # target may be a local path or a remote URL (file://, https://)
            cmd = [self.binary, "git", target]
        else:
            raise ValueError(f"unknown source: {source}")

        # Machine-readable output: one JSON object per detection per line.
        cmd += ["--json", "--no-update"]

        if not self.verify:
            cmd.append("--no-verification")
        if self.only_verified:
            cmd.append("--only-verified")
        if self.include_detectors:
            cmd += ["--include-detectors", self.include_detectors]
        if self.exclude_detectors:
            cmd += ["--exclude-detectors", self.exclude_detectors]

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

        # trufflehog returns 0 even when secrets are found; non-zero = real error
        if proc.returncode != 0:
            raise RuntimeError(
                f"trufflehog exit {proc.returncode}: "
                f"{stderr.decode(errors='ignore')[:500]}"
            )

        # Output is newline-delimited JSON (NDJSON), one event per line.
        events: list[dict] = []
        for line in stdout.decode(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("trufflehog emitted non-JSON line; skipping")
        return events

    def _normalize(
        self, events: list[dict], tenant_id: UUID, asset_id: UUID,
    ) -> list[Finding]:
        out: list[Finding] = []
        for ev in events:
            detector = (ev.get("DetectorName") or "unknown").lower()
            verified = bool(ev.get("Verified", False))

            source_meta = ev.get("SourceMetadata", {}) or {}
            data = source_meta.get("Data", {}) or {}
            # Data has nested shapes depending on source; grab the first
            # populated child (Filesystem, Git, etc.)
            inner = next(iter(data.values()), {}) if data else {}

            file_path = inner.get("file") or inner.get("File") or ""
            line_no = inner.get("line") or inner.get("Line") or 0
            commit = inner.get("commit") or inner.get("Commit") or ""
            email = inner.get("email") or inner.get("Email") or ""
            repo = inner.get("repository") or inner.get("Repository") or ""

            severity = _VERIFIED_SEV if verified else _UNVERIFIED_SEV
            verified_tag = "VERIFIED-LIVE" if verified else "unverified"

            out.append(Finding(
                tenant_id=tenant_id,
                asset_id=asset_id,
                tool="trufflehog",
                module=Module.SECRETS,
                title=f"[{verified_tag}] Secret leaked: {detector}",
                description=(
                    f"TruffleHog detector '{detector}' matched a credential. "
                    f"Verification status: "
                    f"{'credential is currently VALID at the provider' if verified else 'not verified'}."
                ),
                cwe=["CWE-798"],  # Use of Hard-coded Credentials
                severity=severity,
                evidence=Evidence(
                    file=file_path,
                    line=int(line_no) if line_no else None,
                    # Never store the raw secret. Store only the
                    # structural context — the actual value is masked.
                    snippet="<redacted by vulnsuite>",
                    raw={
                        "detector": detector,
                        "verified": verified,
                        "commit": commit,
                        "author_email": email,
                        "repository": repo,
                        "decoder": ev.get("DecoderName"),
                        "source_type": ev.get("SourceType"),
                    },
                ),
                remediation=(
                    "1) REVOKE the credential at the provider immediately "
                    + ("(this key is currently valid — treat as active incident). " if verified else ". ")
                    + "2) Rotate the secret into Azure Key Vault / HashiCorp Vault. "
                    "3) Purge git history (git-filter-repo or BFG Repo-Cleaner). "
                    "4) Review provider access logs for unauthorized use "
                    "within the full lifetime the secret was exposed. "
                    + ("5) File CERT-In incident report within 6 hours "
                       "(applicable: verified-live leak on regulated data). "
                       if verified else "")
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/798.html",
                    "https://github.com/trufflesecurity/trufflehog",
                ],
            ))
        return out
