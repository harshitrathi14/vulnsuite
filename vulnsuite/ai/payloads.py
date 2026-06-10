"""VulnSuite AI - Compact finding payloads for model context.

One canonical serializer so every feature sends the same shape, the
prompt cache sees stable structure, and token spend stays bounded.
Findings MUST already be redacted (redaction.redact_finding) before
they reach these helpers.
"""
from __future__ import annotations

import json
from typing import Any

from ..core.config import get_settings
from ..core.schema import Asset, Finding

_EVIDENCE_RAW_KEYS = (
    # High-signal evidence keys collectors commonly stash; everything else is noise.
    "check_id", "rule_id", "control_id", "resource_name", "resource_type",
    "account", "region", "pkg_name", "package", "version", "fixed_version",
    "host", "port", "scheme", "service", "namespace", "kind", "name",
    "confidence", "impact", "likelihood", "category", "owasp",
    "secret_family", "detector", "corroborated_by",
)


def finding_payload(finding: Finding) -> dict[str, Any]:
    settings = get_settings()
    max_chars = settings.ai.max_snippet_chars
    evidence = finding.evidence
    raw = evidence.raw or {}
    payload: dict[str, Any] = {
        "finding_id": str(finding.finding_id),
        "tool": finding.tool,
        "module": finding.module if isinstance(finding.module, str) else finding.module.value,
        "title": finding.title[:300],
        "description": (finding.description or "")[:max_chars],
        "severity": finding.severity if isinstance(finding.severity, str) else finding.severity.value,
        "cve": finding.cve[:10],
        "cwe": finding.cwe[:10],
        "cvss_base": finding.cvss_base,
        "epss": finding.epss,
        "risk_score": finding.risk_score,
        "risk_bucket": finding.risk_bucket,
        "file": evidence.file,
        "line": evidence.line,
        "snippet": (evidence.snippet or "")[:max_chars] or None,
        "evidence": {k: raw[k] for k in _EVIDENCE_RAW_KEYS if k in raw},
    }
    return {k: v for k, v in payload.items() if v not in (None, "", [], {})}


def asset_payload(asset: Asset | None) -> dict[str, Any]:
    if asset is None:
        return {}
    return {
        "name": asset.name,
        "asset_type": asset.asset_type if isinstance(asset.asset_type, str) else asset.asset_type.value,
        "criticality_1_to_5": asset.criticality,
        "exposure": float(asset.exposure),
        "tags": asset.tags,
    }


def render_user_turn(
    findings: list[Finding],
    asset: Asset | None = None,
    instruction: str | None = None,
) -> str:
    """Volatile user-turn content: asset context + findings JSON."""
    parts: list[str] = []
    ctx = asset_payload(asset)
    if ctx:
        parts.append("Asset context:\n" + json.dumps(ctx, default=str, sort_keys=True))
    parts.append(
        "Findings:\n"
        + json.dumps([finding_payload(f) for f in findings], default=str, sort_keys=True)
    )
    if instruction:
        parts.append(instruction)
    return "\n\n".join(parts)
