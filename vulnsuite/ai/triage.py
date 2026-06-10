"""VulnSuite AI - Finding triage (false-positive analysis).

Two execution paths sharing one prompt and one output contract:
- ``triage_findings``: synchronous chunked calls, used for small sets.
- ``submit_triage_batches`` / ``apply_triage_batch``: Batches API at
  50% price for full-scan volumes; the Celery task in workers/tasks.py
  owns polling.

Verdicts are attached under ``evidence.raw["ai_triage"]``; the
finding's own status/score is never mutated here.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Iterable

from ..core.config import get_settings
from ..core.schema import Asset, Finding
from . import prompts
from .client import (
    AIEnrichmentError,
    ai_active,
    batch_status,
    build_batch_request,
    collect_batch,
    submit_batch,
)
from .client import parse_structured
from .payloads import render_user_turn
from .redaction import redact_finding
from .schemas import TriageBatchResult, TriageVerdict

logger = logging.getLogger(__name__)


def _chunks(items: list[Finding], size: int) -> Iterable[list[Finding]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _annotate(finding: Finding, verdict: TriageVerdict) -> Finding:
    raw = dict(finding.evidence.raw or {})
    raw["ai_triage"] = {
        **verdict.model_dump(mode="json"),
        "model": get_settings().ai.model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return finding.model_copy(
        update={"evidence": finding.evidence.model_copy(update={"raw": raw})}
    )


def apply_verdicts(
    findings: list[Finding], verdicts: dict[str, TriageVerdict],
) -> list[Finding]:
    return [
        _annotate(f, verdicts[str(f.finding_id)]) if str(f.finding_id) in verdicts else f
        for f in findings
    ]


# ---------- synchronous path ----------

def triage_findings(findings: list[Finding], asset: Asset | None = None) -> list[Finding]:
    """Triage in-process. Degrades to identity on any failure."""
    settings = get_settings()
    if not ai_active() or not settings.ai.triage_enabled or not findings:
        return findings

    verdicts: dict[str, TriageVerdict] = {}
    for chunk in _chunks(findings, settings.ai.max_findings_per_call):
        try:
            result = parse_structured(
                system=prompts.TRIAGE_SYSTEM,
                user=render_user_turn([redact_finding(f) for f in chunk], asset),
                output_model=TriageBatchResult,
                effort=settings.ai.triage_effort,
                tenant_id=chunk[0].tenant_id,
            )
        except AIEnrichmentError as exc:
            logger.warning("triage chunk failed (%d findings): %s", len(chunk), exc)
            continue
        for v in result.verdicts:
            verdicts[v.finding_id] = v

    logger.info("ai triage: %d/%d findings received verdicts", len(verdicts), len(findings))
    return apply_verdicts(findings, verdicts)


# ---------- Batches API path ----------

def submit_triage_batches(findings: list[Finding], asset: Asset | None = None) -> str:
    """Submit one message batch covering all chunks; returns batch_id."""
    settings = get_settings()
    requests = [
        build_batch_request(
            custom_id=f"triage-{i}",
            system=prompts.TRIAGE_SYSTEM,
            user=render_user_turn([redact_finding(f) for f in chunk], asset),
            output_model=TriageBatchResult,
            effort=settings.ai.triage_effort,
            tenant_id=findings[0].tenant_id,
        )
        for i, chunk in enumerate(_chunks(findings, settings.ai.max_findings_per_call))
    ]
    return submit_batch(requests)


def wait_for_batch(batch_id: str, *, poll_seconds: int = 30, max_wait_seconds: int = 5400) -> bool:
    """Poll until the batch ends. True if ended within the window."""
    deadline = time.monotonic() + max_wait_seconds
    while time.monotonic() < deadline:
        if batch_status(batch_id) == "ended":
            return True
        time.sleep(poll_seconds)
    return False


def apply_triage_batch(batch_id: str, findings: list[Finding]) -> list[Finding]:
    verdicts: dict[str, TriageVerdict] = {}
    for result in collect_batch(batch_id, TriageBatchResult).values():
        for v in result.verdicts:
            verdicts[v.finding_id] = v
    logger.info(
        "ai triage batch %s: %d/%d findings received verdicts",
        batch_id, len(verdicts), len(findings),
    )
    return apply_verdicts(findings, verdicts)
