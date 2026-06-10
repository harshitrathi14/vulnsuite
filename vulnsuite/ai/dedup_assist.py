"""VulnSuite AI - Semantic dedup assist (suggestions only).

The deterministic dedup in core/dedup.py has no key for NETWORK,
CLOUD, and DISCOVERY findings — they pass through unmerged. This pass
asks for semantic merge candidates within those modules and records
them under ``evidence.raw["ai_merge_suggestion"]``. It NEVER merges:
an analyst confirms or dismisses.

Off by default (``VULNSUITE_AI_DEDUP_ASSIST_ENABLED``).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..core.config import get_settings
from ..core.schema import Finding, Module
from . import prompts
from .client import AIEnrichmentError, ai_active, parse_structured
from .payloads import render_user_turn
from .redaction import redact_finding

from .schemas import DedupSuggestions

logger = logging.getLogger(__name__)

# Modules dedup_findings() passes through unkeyed.
UNKEYED_MODULES = {Module.NETWORK.value, Module.CLOUD.value, Module.DISCOVERY.value}

_MIN_CONFIDENCE = 0.8


def suggest_merges(findings: list[Finding]) -> list[Finding]:
    """Annotate likely-duplicate findings in unkeyed modules."""
    settings = get_settings()
    if not ai_active() or not settings.ai.dedup_assist_enabled:
        return findings

    pool = [
        f for f in findings
        if (f.module if isinstance(f.module, str) else f.module.value) in UNKEYED_MODULES
    ]
    if len(pool) < 2:
        return findings

    try:
        result = parse_structured(
            system=prompts.DEDUP_SYSTEM,
            user=render_user_turn([redact_finding(f) for f in pool[: settings.ai.max_findings_per_call]]),
            output_model=DedupSuggestions,
            effort=settings.ai.triage_effort,
            tenant_id=pool[0].tenant_id,
        )
    except AIEnrichmentError as exc:
        logger.warning("dedup assist failed (%d findings): %s", len(pool), exc)
        return findings

    stamp = {
        "model": settings.ai.model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    by_id = {str(f.finding_id): f for f in findings}
    kept = 0
    for s in result.suggestions:
        if s.confidence < _MIN_CONFIDENCE:
            continue
        suggestion = {**s.model_dump(mode="json"), **stamp}
        for fid in [s.primary_finding_id, *s.duplicate_finding_ids]:
            f = by_id.get(fid)
            if f is None:
                continue
            raw = dict(f.evidence.raw or {})
            raw["ai_merge_suggestion"] = suggestion
            by_id[fid] = f.model_copy(
                update={"evidence": f.evidence.model_copy(update={"raw": raw})}
            )
        kept += 1

    logger.info("ai dedup assist: %d high-confidence suggestion(s)", kept)
    return [by_id[str(f.finding_id)] for f in findings]
