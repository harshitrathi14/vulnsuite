"""VulnSuite - Cross-tool finding deduplication."""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Iterable

from .schema import Finding, Module

logger = logging.getLogger(__name__)

_SECRET_FAMILIES: dict[str, str] = {
    "aws": "aws",
    "aws-access-token": "aws",
    "aws-secret-key": "aws",
    "gcp": "gcp",
    "gcp-api-key": "gcp",
    "gcp-service-account": "gcp",
    "azure": "azure",
    "azure-storage-key": "azure",
    "github": "github",
    "github-pat": "github",
    "github-oauth": "github",
    "slack": "slack",
    "slack-bot": "slack",
    "slack-webhook": "slack",
    "stripe": "stripe",
    "stripe-api-key": "stripe",
    "private-key": "private-key",
    "rsa-private-key": "private-key",
    "ssh-private-key": "private-key",
    "pgp-private-key": "private-key",
}


def _secret_family(detector: str | None) -> str:
    if not detector:
        return "unknown"
    normalized = detector.lower().strip()
    if normalized in _SECRET_FAMILIES:
        return _SECRET_FAMILIES[normalized]
    for token, family in _SECRET_FAMILIES.items():
        if token in normalized:
            return family
    return normalized


def _key_for(finding: Finding) -> tuple | None:
    module = finding.module if isinstance(finding.module, str) else finding.module.value
    evidence = (finding.evidence.raw or {}) if finding.evidence else {}

    if module in (Module.SCA.value, Module.CONTAINER.value):
        package = evidence.get("pkg_name") or ""
        version = evidence.get("installed_version") or ""
        if finding.cve:
            return ("sca", str(finding.asset_id), finding.cve[0], package, version)
        advisory = evidence.get("advisory_id") or ""
        if advisory or package:
            return ("sca", str(finding.asset_id), advisory, package, version)
        return None

    if module == Module.SECRETS.value:
        file_path = (finding.evidence.file or "") if finding.evidence else ""
        line = (finding.evidence.line or 0) if finding.evidence else 0
        family = _secret_family(evidence.get("detector") or evidence.get("rule_id"))
        return ("secrets", str(finding.asset_id), file_path, line, family)

    if module == Module.SAST.value:
        file_path = (finding.evidence.file or "") if finding.evidence else ""
        line = (finding.evidence.line or 0) if finding.evidence else 0
        line_bucket = line // 5
        cwe = finding.cwe[0] if finding.cwe else "no-cwe"
        return ("sast", str(finding.asset_id), file_path, line_bucket, cwe)

    if module == Module.IAC.value:
        return (
            "iac",
            str(finding.asset_id),
            str(evidence.get("check_id") or evidence.get("bc_check_id") or "no-check"),
            (finding.evidence.file or "") if finding.evidence else "",
            str(evidence.get("resource") or "no-resource"),
        )

    if module == Module.KUBERNETES.value:
        return (
            "kubernetes",
            str(finding.asset_id),
            str(evidence.get("control_id") or evidence.get("check_id") or "no-control"),
            str(evidence.get("namespace") or "default"),
            str(evidence.get("kind") or "unknown"),
            str(evidence.get("name") or evidence.get("resource_name") or "unknown"),
        )

    if module == Module.ASM.value:
        return (
            "asm",
            str(finding.asset_id),
            str(evidence.get("host") or evidence.get("url") or ""),
            str(evidence.get("port") or "0"),
            str(evidence.get("scheme") or evidence.get("protocol") or ""),
            str(evidence.get("fingerprint") or evidence.get("id") or ""),
        )

    if module == Module.API_SECURITY.value:
        return (
            "api_security",
            str(finding.asset_id),
            str(evidence.get("rule_id") or "no-rule"),
            str(evidence.get("method") or ""),
            str(evidence.get("path_or_url") or evidence.get("url") or ""),
        )

    if module == Module.SUPPLY_CHAIN.value:
        return (
            "supply_chain",
            str(finding.asset_id),
            finding.cve[0] if finding.cve else str(evidence.get("rule_id") or evidence.get("component_name") or "no-id"),
            str(evidence.get("artifact_digest") or evidence.get("purl") or evidence.get("artifact") or ""),
        )

    return None


def dedup_key(finding: Finding) -> tuple | None:
    """Public accessor for the per-module dedup key (used by fingerprinting)."""
    return _key_for(finding)


def _merge_score(finding: Finding) -> tuple:
    evidence = (finding.evidence.raw or {}) if finding.evidence else {}
    has_fix = bool(evidence.get("fix_versions") or evidence.get("fixed_version"))
    return (finding.cvss_base, int(has_fix), finding.epss)


def _merge_pair(winner: Finding, loser: Finding) -> Finding:
    def _union(left: list[str], right: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for value in list(left) + list(right):
            if value and value not in seen:
                seen.add(value)
                out.append(value)
        return out

    merged_evidence = winner.evidence.model_copy()
    raw = dict(merged_evidence.raw or {})
    corroborated = list(raw.get("corroborated_by", []))
    corroborated.append(
        {
            "tool": loser.tool,
            "finding_id": str(loser.finding_id),
            "severity": loser.severity if isinstance(loser.severity, str) else loser.severity.value,
            "cvss_base": loser.cvss_base,
        }
    )
    raw["corroborated_by"] = corroborated
    merged_evidence = merged_evidence.model_copy(update={"raw": raw})

    return winner.model_copy(
        update={
            "cve": _union(winner.cve, loser.cve),
            "cwe": _union(winner.cwe, loser.cwe),
            "references": _union(winner.references, loser.references),
            "epss": max(winner.epss, loser.epss),
            "cvss_base": max(winner.cvss_base, loser.cvss_base),
            "evidence": merged_evidence,
            "first_seen": min(winner.first_seen, loser.first_seen),
            "last_seen": max(winner.last_seen, loser.last_seen),
        }
    )


def dedup_findings(findings: Iterable[Finding]) -> list[Finding]:
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    unkeyed: list[Finding] = []

    for finding in findings:
        key = _key_for(finding)
        if key is None:
            unkeyed.append(finding)
        else:
            groups[key].append(finding)

    out: list[Finding] = list(unkeyed)
    for key, group in groups.items():
        if len(group) == 1:
            out.append(group[0])
            continue
        group.sort(key=_merge_score, reverse=True)
        winner = group[0]
        for loser in group[1:]:
            winner = _merge_pair(winner, loser)
        logger.debug("merged %d findings into %s (key=%s)", len(group), winner.finding_id, key)
        out.append(winner)
    return out
