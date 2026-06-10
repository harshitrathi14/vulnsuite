"""VulnSuite AI - RBI CSF compliance mapping.

Primary path: structured classification with per-control rationale
(auditors require the "why", which the keyword heuristic cannot give).
Fallback path: the deterministic ``compliance.rbi_mapping`` heuristic,
used per-chunk whenever the model path fails — a finding never goes
unmapped because the AI layer was down.

Mappings land in ``evidence.raw["ai_rbi"]``.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..compliance.rbi_mapping import map_finding
from ..core.config import get_settings
from ..core.schema import Finding
from . import prompts
from .client import AIEnrichmentError, ai_active, parse_structured
from .payloads import render_user_turn
from .redaction import redact_finding
from .schemas import ComplianceMappingResult, RBIMappingVerdict

logger = logging.getLogger(__name__)


def _heuristic_verdict(finding: Finding) -> RBIMappingVerdict:
    return RBIMappingVerdict(
        finding_id=str(finding.finding_id),
        control_ids=map_finding(finding),
        rationale="heuristic module/keyword mapping (AI unavailable)",
    )


def _annotate(finding: Finding, verdict: RBIMappingVerdict) -> Finding:
    raw = dict(finding.evidence.raw or {})
    raw["ai_rbi"] = {
        **verdict.model_dump(mode="json"),
        "model": get_settings().ai.model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return finding.model_copy(
        update={"evidence": finding.evidence.model_copy(update={"raw": raw})}
    )


def map_findings_rbi(findings: list[Finding]) -> list[Finding]:
    """Attach RBI control mappings with rationale to every finding."""
    settings = get_settings()
    if not settings.ai.compliance_enabled or not findings:
        return findings

    verdicts: dict[str, RBIMappingVerdict] = {}
    chunk_size = settings.ai.max_findings_per_call
    use_model = ai_active()

    for i in range(0, len(findings), chunk_size):
        chunk = findings[i : i + chunk_size]
        if use_model:
            try:
                result = parse_structured(
                    system=prompts.COMPLIANCE_SYSTEM,
                    user=render_user_turn([redact_finding(f) for f in chunk]),
                    output_model=ComplianceMappingResult,
                    effort=settings.ai.compliance_effort,
                    tenant_id=chunk[0].tenant_id,
                )
                for v in result.mappings:
                    verdicts[v.finding_id] = v
                continue
            except AIEnrichmentError as exc:
                logger.warning("rbi mapping chunk failed, using heuristic: %s", exc)
        for f in chunk:
            verdicts[str(f.finding_id)] = _heuristic_verdict(f)

    return [
        _annotate(f, verdicts[str(f.finding_id)]) if str(f.finding_id) in verdicts else f
        for f in findings
    ]
