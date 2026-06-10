"""VulnSuite AI - Report narratives.

- ``executive_summary``: board-level briefing for the PDF report.
- ``certin_narrative``: factual first draft of the CERT-In incident
  description. Both are clearly stamped as AI-generated drafts; the
  existing human sign-off gate before regulatory submission is
  unchanged.
"""
from __future__ import annotations

import json
import logging
from collections import Counter

from ..core.config import get_settings
from ..core.schema import Finding
from . import prompts
from .client import AIEnrichmentError, ai_active, generate_text, parse_structured
from .payloads import finding_payload
from .redaction import redact_finding, redact_text
from .schemas import ExecutiveSummary

logger = logging.getLogger(__name__)


def _portfolio_digest(findings: list[Finding]) -> dict:
    """Aggregate stats + top findings only — narratives don't need every row."""
    buckets = Counter(f.risk_bucket or "P4" for f in findings)
    modules = Counter(
        f.module if isinstance(f.module, str) else f.module.value for f in findings
    )
    top = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:15]
    return {
        "total_findings": len(findings),
        "bucket_counts": dict(buckets),
        "module_counts": dict(modules),
        "top_findings": [finding_payload(redact_finding(f)) for f in top],
    }


def executive_summary(findings: list[Finding], tenant_name: str) -> ExecutiveSummary | None:
    """Board-level summary, or None when AI is off/unavailable."""
    settings = get_settings()
    if not ai_active() or not settings.ai.narrative_enabled or not findings:
        return None
    try:
        return parse_structured(
            system=prompts.NARRATIVE_SYSTEM,
            user=(
                f"Organisation: {tenant_name}\n\nScan portfolio digest:\n"
                + json.dumps(_portfolio_digest(findings), default=str, sort_keys=True)
            ),
            output_model=ExecutiveSummary,
            effort=settings.ai.narrative_effort,
            tenant_id=findings[0].tenant_id,
        )
    except AIEnrichmentError as exc:
        logger.warning("executive summary generation failed: %s", exc)
        return None


def render_summary_text(summary: ExecutiveSummary) -> str:
    """Flatten the structured summary into report-ready text."""
    lines = [summary.headline, "", summary.posture_assessment, "", "Top risks:"]
    lines += [f"• {risk}" for risk in summary.top_risks]
    lines += ["", "Recommended actions:"]
    lines += [f"• {action}" for action in summary.recommended_actions]
    return "\n".join(lines)


def certin_narrative(incident: dict, tenant_id: str) -> str | None:
    """Draft incident description for the CERT-In report, or None."""
    settings = get_settings()
    if not ai_active() or not settings.ai.narrative_enabled:
        return None
    safe_incident = json.loads(redact_text(json.dumps(incident, default=str)) or "{}")
    try:
        return generate_text(
            system=prompts.CERTIN_NARRATIVE_SYSTEM,
            user="Incident JSON:\n" + json.dumps(safe_incident, default=str, sort_keys=True),
            effort=settings.ai.narrative_effort,
            tenant_id=tenant_id,
        )
    except AIEnrichmentError as exc:
        logger.warning("CERT-In narrative generation failed: %s", exc)
        return None
