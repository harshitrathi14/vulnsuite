"""VulnSuite - Cosign verification collector for signed artifacts and images.

Supports three verification modes, selected automatically:

1. Keyless (Sigstore/Fulcio). Requires certificate_identity + certificate_oidc_issuer
   (exact or regex). This is the default for public-internet BFSI tenants.
2. Key-based. Used when an offline public key is configured via
   `SupplyChainSettings.cosign_public_key_path` — the air-gap fallback.
3. Attestation verification. When `require_attestation_type` is set we additionally
   run `cosign verify-attestation --type <predicate>` so SLSA/SBOM/VEX attestations
   are enforced, not just image signatures.

A missing or failing signature is a HIGH finding; a missing required attestation
(e.g. SLSA provenance) is also HIGH. Both ride under Module.SUPPLY_CHAIN so the
dedup engine groups them with Syft/SCA findings on the same artifact_digest.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from ...core.schema import Evidence, Finding, Module, ScanResult, Severity

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CosignPolicy:
    """Verification policy assembled from SupplyChainSettings.

    At least one of (public_key_path) or (identity+issuer) must be set; if both
    are set and `prefer_keyless` is True, keyless wins. attestation_type is
    optional and triggers a second `verify-attestation` pass.
    """
    prefer_keyless: bool = True
    public_key_path: Path | None = None
    identity: str | None = None
    identity_regexp: str | None = None
    issuer: str | None = None
    issuer_regexp: str | None = None
    attestation_type: str | None = None

    def keyless_usable(self) -> bool:
        return bool((self.identity or self.identity_regexp) and (self.issuer or self.issuer_regexp))

    def key_usable(self) -> bool:
        return self.public_key_path is not None and Path(self.public_key_path).exists()


class CosignNotInstalled(RuntimeError):
    pass


class CosignCollector:
    def __init__(
        self,
        binary: str = "cosign",
        timeout_seconds: int = 300,
        policy: CosignPolicy | None = None,
    ) -> None:
        if shutil.which(binary) is None:
            raise CosignNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.policy = policy or CosignPolicy()

    async def scan(self, artifacts: list[str], tenant_id: UUID, asset_id: UUID) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors: list[str] = []
        for artifact in artifacts:
            try:
                sig_ok, sig_out = await self._run(["verify"], artifact)
                if not sig_ok:
                    findings.append(self._unsigned_finding(artifact, sig_out, tenant_id, asset_id))
                    # No point asking for attestations on something we can't sign-verify.
                    continue
                if self.policy.attestation_type:
                    att_ok, att_out = await self._run(
                        ["verify-attestation", "--type", self.policy.attestation_type],
                        artifact,
                    )
                    if not att_ok:
                        findings.append(
                            self._missing_attestation_finding(artifact, att_out, tenant_id, asset_id)
                        )
            except asyncio.TimeoutError:
                errors.append(f"cosign timeout on {artifact} after {self.timeout}s")
            except Exception as exc:  # noqa: BLE001
                logger.exception("cosign failed")
                errors.append(f"cosign error on {artifact}: {exc}")
        return ScanResult(
            tool="cosign",
            module=Module.SUPPLY_CHAIN,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    async def _run(self, subcommand: list[str], artifact: str) -> tuple[bool, list[dict] | str]:
        cmd = [self.binary, *subcommand, *self._policy_flags(), artifact]
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
        if proc.returncode == 0:
            parsed: list[dict] = []
            for line in stdout.decode(errors="ignore").splitlines():
                if line.strip():
                    try:
                        parsed.append(json.loads(line))
                    except json.JSONDecodeError:
                        # cosign sometimes emits non-JSON preamble; skip it.
                        continue
            return (True, parsed)
        return (False, stderr.decode(errors="ignore")[:1000] or stdout.decode(errors="ignore")[:1000])

    def _policy_flags(self) -> list[str]:
        p = self.policy
        if p.prefer_keyless and p.keyless_usable():
            return self._keyless_flags()
        if p.key_usable():
            return ["--key", str(p.public_key_path)]
        if p.keyless_usable():
            return self._keyless_flags()
        # No credentials configured → pass nothing; cosign will fail closed
        # and we'll emit an unsigned finding. This is the safe BFSI default.
        return []

    def _keyless_flags(self) -> list[str]:
        p = self.policy
        flags: list[str] = []
        if p.identity:
            flags += ["--certificate-identity", p.identity]
        elif p.identity_regexp:
            flags += ["--certificate-identity-regexp", p.identity_regexp]
        if p.issuer:
            flags += ["--certificate-oidc-issuer", p.issuer]
        elif p.issuer_regexp:
            flags += ["--certificate-oidc-issuer-regexp", p.issuer_regexp]
        return flags

    @staticmethod
    def _unsigned_finding(
        artifact: str, output: list[dict] | str, tenant_id: UUID, asset_id: UUID
    ) -> Finding:
        return Finding(
            tenant_id=tenant_id,
            asset_id=asset_id,
            tool="cosign",
            module=Module.SUPPLY_CHAIN,
            title=f"Unsigned or unverifiable artifact: {artifact}",
            description="Cosign could not verify a trusted signature for the artifact under the configured policy.",
            severity=Severity.HIGH,
            evidence=Evidence(raw={"artifact": artifact, "verification_output": output}),
            remediation=(
                "Sign the artifact with Cosign keyless (Sigstore/Fulcio) or a trusted key "
                "before promoting to staging/production. Verify the identity + OIDC issuer "
                "policy matches the build pipeline's workload identity."
            ),
            references=["https://docs.sigstore.dev/cosign/verifying/verify/"],
        )

    @staticmethod
    def _missing_attestation_finding(
        artifact: str, output: list[dict] | str, tenant_id: UUID, asset_id: UUID
    ) -> Finding:
        return Finding(
            tenant_id=tenant_id,
            asset_id=asset_id,
            tool="cosign",
            module=Module.SUPPLY_CHAIN,
            title=f"Missing or invalid attestation on artifact: {artifact}",
            description=(
                "Cosign verified the artifact signature but could not verify the required "
                "attestation (e.g. SLSA provenance, SBOM, VEX)."
            ),
            severity=Severity.HIGH,
            evidence=Evidence(raw={"artifact": artifact, "verification_output": output}),
            remediation=(
                "Emit the required in-toto attestation from the build pipeline "
                "(e.g. slsa-github-generator for SLSA provenance) and re-sign. "
                "BFSI supply-chain policy should require SLSA Level 3 provenance "
                "for production promotion (RBI CSF 6.14)."
            ),
            references=[
                "https://slsa.dev/spec/v1.0/provenance",
                "https://docs.sigstore.dev/cosign/verifying/attestation/",
            ],
        )
