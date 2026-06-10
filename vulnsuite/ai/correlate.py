"""VulnSuite AI - Attack-chain correlation.

The flagship Fable 5 feature: the deterministic risk formula scores
findings independently, so it cannot see that an exposed secret, an
internet-facing service, and a vulnerable dependency on the same asset
compose into one attack path. This pass feeds the asset's entire
finding set into a single high-effort call and asks for chains.

Chains are advisory: each member finding gets the chain appended to
``evidence.raw["ai_attack_chains"]``, and when a chain's suggested
bucket outranks the finding's own, ``evidence.raw["ai_suggested_bucket"]``
records the escalation for analyst review. risk_bucket itself is never
mutated by AI.
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
from .schemas import CorrelationResult

logger = logging.getLogger(__name__)

_BUCKET_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}


def _outranks(suggested: str, current: str | None) -> bool:
    return _BUCKET_RANK.get(suggested, 9) < _BUCKET_RANK.get(current or "P4", 4)


def correlate_findings(findings: list[Finding], asset: Asset | None = None) -> list[Finding]:
    """Single-call attack-chain analysis over one asset's findings."""
    settings = get_settings()
    if not ai_active() or not settings.ai.correlation_enabled:
        return findings
    if len(findings) < 2:
        return findings  # nothing to chain

    pool = findings[: settings.ai.max_correlation_findings]
    try:
        result = parse_structured(
            system=prompts.CORRELATION_SYSTEM,
            user=render_user_turn(
                [redact_finding(f) for f in pool],
                asset,
                instruction="Identify attack chains across these findings, or return an "
                "empty chains list if none genuinely compose.",
            ),
            output_model=CorrelationResult,
            effort=settings.ai.correlation_effort,
            tenant_id=pool[0].tenant_id,
            max_tokens=16000,
        )
    except AIEnrichmentError as exc:
        logger.warning("correlation failed (%d findings): %s", len(pool), exc)
        return findings

    if not result.chains:
        logger.info("ai correlation: no chains found across %d findings", len(pool))
        return findings

    stamp = {
        "model": settings.ai.model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    by_id = {str(f.finding_id): f for f in findings}
    chained = 0
    for chain in result.chains:
        chain_dict = {**chain.model_dump(mode="json"), **stamp}
        for fid in chain.finding_ids:
            f = by_id.get(fid)
            if f is None:
                continue
            raw = dict(f.evidence.raw or {})
            raw.setdefault("ai_attack_chains", []).append(chain_dict)
            if _outranks(chain.suggested_bucket, f.risk_bucket):
                raw["ai_suggested_bucket"] = chain.suggested_bucket
            by_id[fid] = f.model_copy(
                update={"evidence": f.evidence.model_copy(update={"raw": raw})}
            )
            chained += 1

    logger.info(
        "ai correlation: %d chain(s) covering %d finding(s)", len(result.chains), chained,
    )
    return [by_id[str(f.finding_id)] for f in findings]
