"""VulnSuite AI - Remediation plan generation.

Only buckets listed in ``settings.ai.remediation_buckets`` (default
P0/P1) get plans — that is where engineer attention actually goes,
and it bounds spend on large scans. Plans land in
``evidence.raw["ai_remediation"]``; the collector-supplied
``remediation`` string is left untouched as the deterministic fallback.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..core.config import get_settings
from ..core.schema import Asset, Finding
from . import prompts
from .client import AIEnrichmentError, ai_active, parse_structured
from .payloads import render_user_turn
from .redaction import redact_finding
from .schemas import RemediationBatchResult, RemediationPlan

logger = logging.getLogger(__name__)


def _annotate(finding: Finding, plan: RemediationPlan) -> Finding:
    raw = dict(finding.evidence.raw or {})
    raw["ai_remediation"] = {
        **plan.model_dump(mode="json"),
        "model": get_settings().ai.model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return finding.model_copy(
        update={"evidence": finding.evidence.model_copy(update={"raw": raw})}
    )


def remediate_findings(findings: list[Finding], asset: Asset | None = None) -> list[Finding]:
    """Generate plans for high-priority findings. Identity on failure."""
    settings = get_settings()
    if not ai_active() or not settings.ai.remediation_enabled or not findings:
        return findings

    eligible = [f for f in findings if f.risk_bucket in settings.ai.remediation_buckets]
    if not eligible:
        return findings

    plans: dict[str, RemediationPlan] = {}
    chunk_size = settings.ai.max_findings_per_call
    for i in range(0, len(eligible), chunk_size):
        chunk = eligible[i : i + chunk_size]
        try:
            result = parse_structured(
                system=prompts.REMEDIATION_SYSTEM,
                user=render_user_turn([redact_finding(f) for f in chunk], asset),
                output_model=RemediationBatchResult,
                effort=settings.ai.remediation_effort,
                tenant_id=chunk[0].tenant_id,
            )
        except AIEnrichmentError as exc:
            logger.warning("remediation chunk failed (%d findings): %s", len(chunk), exc)
            continue
        for plan in result.plans:
            plans[plan.finding_id] = plan

    logger.info("ai remediation: %d/%d eligible findings received plans", len(plans), len(eligible))
    return [
        _annotate(f, plans[str(f.finding_id)]) if str(f.finding_id) in plans else f
        for f in findings
    ]
