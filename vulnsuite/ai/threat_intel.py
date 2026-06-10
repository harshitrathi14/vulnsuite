"""VulnSuite AI - Live threat intelligence (Fable 5 + web search).

EPSS is a static probability; this module answers the question that
actually drives a 2 a.m. patch decision: is this CVE being exploited
in the wild RIGHT NOW? For high-priority CVEs it runs a web-grounded
research pass (CISA KEV, vendor advisories, exploit databases) and a
structured extraction pass, then annotates every finding carrying
that CVE under ``evidence.raw["ai_threat_intel"]``.

Two-phase by design: server-side web tools emit citations, which are
incompatible with structured outputs — so phase 1 researches in free
text and phase 2 extracts the structured verdicts from it.

Only CVE IDs are sent off-host; no finding evidence is needed here.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..core.config import get_settings
from ..core.schema import Finding
from . import prompts
from .client import AIEnrichmentError, ai_active, parse_structured, research_web
from .schemas import ThreatIntelBatchResult, ThreatIntelVerdict

logger = logging.getLogger(__name__)


def _eligible_cves(findings: list[Finding]) -> list[str]:
    settings = get_settings()
    cves: dict[str, None] = {}  # ordered de-dup
    for f in findings:
        if f.risk_bucket not in settings.ai.threat_intel_buckets:
            continue
        for cve in f.cve:
            if cve.startswith("CVE-"):
                cves.setdefault(cve)
    return list(cves)


def _research_chunk(cves: list[str], tenant_id) -> dict[str, ThreatIntelVerdict]:
    settings = get_settings()
    cve_list = ", ".join(cves)
    research = research_web(
        system=prompts.THREAT_INTEL_SYSTEM,
        user=(
            f"Research the current exploitation status of these CVEs: {cve_list}.\n"
            "For each: CISA KEV status, credible in-the-wild exploitation reports, "
            "public PoC/weaponized exploits, patch availability. Cite source URLs."
        ),
        effort=settings.ai.threat_intel_effort,
        tenant_id=tenant_id,
    )
    extraction = parse_structured(
        system=prompts.THREAT_INTEL_SYSTEM,
        user=(
            f"Convert your research notes below into one verdict per CVE ({cve_list}). "
            "Use 'unknown' wherever the notes are inconclusive.\n\n"
            f"Research notes:\n{research}"
        ),
        output_model=ThreatIntelBatchResult,
        effort="low",  # pure extraction; the thinking happened in the research pass
        tenant_id=tenant_id,
    )
    return {v.cve.upper(): v for v in extraction.verdicts}


def enrich_threat_intel(findings: list[Finding]) -> list[Finding]:
    """Annotate findings whose CVEs have live-web threat verdicts."""
    settings = get_settings()
    if not ai_active() or not settings.ai.threat_intel_enabled or not findings:
        return findings

    cves = _eligible_cves(findings)
    if not cves:
        return findings

    verdicts: dict[str, ThreatIntelVerdict] = {}
    chunk_size = settings.ai.max_cves_per_intel_call
    for i in range(0, len(cves), chunk_size):
        chunk = cves[i : i + chunk_size]
        try:
            verdicts.update(_research_chunk(chunk, findings[0].tenant_id))
        except AIEnrichmentError as exc:
            logger.warning("threat intel chunk failed (%s): %s", ", ".join(chunk), exc)

    if not verdicts:
        return findings

    stamp = {
        "model": settings.ai.model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    out: list[Finding] = []
    annotated = 0
    for f in findings:
        hits = [verdicts[c] for c in f.cve if c in verdicts]
        if not hits:
            out.append(f)
            continue
        raw = dict(f.evidence.raw or {})
        raw["ai_threat_intel"] = {
            "verdicts": [v.model_dump(mode="json") for v in hits],
            # the single most urgent signal, for dashboards/SIEM filters
            "actively_exploited": any(v.actively_exploited.value == "yes" for v in hits),
            "kev_listed": any(v.kev_listed.value == "yes" for v in hits),
            **stamp,
        }
        out.append(f.model_copy(update={"evidence": f.evidence.model_copy(update={"raw": raw})}))
        annotated += 1

    logger.info(
        "ai threat intel: %d CVE verdict(s) across %d finding(s)", len(verdicts), annotated,
    )
    return out
