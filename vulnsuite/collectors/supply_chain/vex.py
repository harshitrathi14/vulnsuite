"""VulnSuite - VEX (Vulnerability Exploitability eXchange) post-processor.

Supports two formats, auto-detected per file:

- CycloneDX VEX  (CycloneDX 1.4+ / 1.5)
    {"vulnerabilities": [{"id": "CVE-...", "analysis": {"state": "not_affected", ...}}]}
- OpenVEX        (https://openvex.dev/)
    {"@context": "https://openvex.dev/ns", "statements": [
        {"vulnerability": {"name": "CVE-..."}, "status": "not_affected", ...}]}

Status states from both formats normalize into VulnSuite's `NOT_AFFECTED_STATES`,
which downgrade matched findings to INFO/P4. Audit-friendly: the original VEX
state, justification, and detail/impact statement are preserved on the finding
under `evidence.raw.vex_*`.

This is wired as a post-processor in the orchestrator pipeline (after dedup +
risk scoring), so the VEX downgrade is the last word — exactly where auditors
expect "this CVE is real but not exploitable in our deployment" to live.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from ...core.schema import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VEXStatus:
    state: str
    detail: str
    justification: str
    source_format: str          # "cyclonedx" | "openvex"


class VEXProcessor:
    # Both formats use overlapping but distinct vocabularies; the values below
    # are the union of "this finding is suppressed" states from CycloneDX VEX
    # and OpenVEX. Anything else (affected/exploitable/under_investigation/...) leaves
    # the finding alone but still annotates evidence.
    NOT_AFFECTED_STATES = {"not_affected", "resolved", "fixed"}

    def __init__(self, statuses: dict[str, VEXStatus]) -> None:
        self.statuses = statuses

    @classmethod
    def load_many(cls, paths: list[str]) -> "VEXProcessor":
        statuses: dict[str, VEXStatus] = {}
        for path in paths:
            try:
                payload = json.loads(Path(path).read_text() or "{}")
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("skipping unreadable VEX file %s: %s", path, exc)
                continue
            statuses.update(cls._parse(payload))
        return cls(statuses)

    @staticmethod
    def _parse(payload: dict) -> dict[str, VEXStatus]:
        # OpenVEX is identified by either the @context or the top-level "statements".
        ctx = str(payload.get("@context") or "")
        if "openvex.dev" in ctx or isinstance(payload.get("statements"), list):
            return _parse_openvex(payload)
        # Default to CycloneDX — its top-level shape is "vulnerabilities".
        if isinstance(payload.get("vulnerabilities"), list):
            return _parse_cyclonedx(payload)
        return {}

    def apply(self, findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        for finding in findings:
            status = next(
                (self.statuses.get(cve.upper()) for cve in finding.cve if cve.upper() in self.statuses),
                None,
            )
            if status is None:
                out.append(finding)
                continue
            raw = dict(finding.evidence.raw or {})
            raw["vex_status"] = status.state
            raw["vex_detail"] = status.detail
            raw["vex_justification"] = status.justification
            raw["vex_format"] = status.source_format
            updated = finding.model_copy(
                update={"evidence": finding.evidence.model_copy(update={"raw": raw})}
            )
            if status.state in self.NOT_AFFECTED_STATES:
                updated = updated.model_copy(
                    update={"severity": Severity.INFO, "risk_score": 0.0, "risk_bucket": "P4"}
                )
            out.append(updated)
        return out


def _parse_cyclonedx(payload: dict) -> dict[str, VEXStatus]:
    out: dict[str, VEXStatus] = {}
    for vuln in payload.get("vulnerabilities", []) or []:
        vuln_id = str(vuln.get("id") or "").upper()
        analysis = vuln.get("analysis", {}) or {}
        state = str(analysis.get("state") or "").lower()
        if vuln_id and state:
            out[vuln_id] = VEXStatus(
                state=state,
                detail=str(analysis.get("detail") or ""),
                justification=str(analysis.get("justification") or ""),
                source_format="cyclonedx",
            )
    return out


def _parse_openvex(payload: dict) -> dict[str, VEXStatus]:
    out: dict[str, VEXStatus] = {}
    for stmt in payload.get("statements", []) or []:
        # OpenVEX permits "vulnerability" as either a string (legacy) or an object
        # carrying a "name" plus optional aliases. Aliases are useful for GHSA IDs.
        vuln_field = stmt.get("vulnerability")
        ids: list[str] = []
        if isinstance(vuln_field, str):
            ids.append(vuln_field)
        elif isinstance(vuln_field, dict):
            if vuln_field.get("name"):
                ids.append(str(vuln_field["name"]))
            for alias in vuln_field.get("aliases", []) or []:
                ids.append(str(alias))
        state = str(stmt.get("status") or "").lower()
        if not state:
            continue
        record = VEXStatus(
            state=state,
            detail=str(stmt.get("impact_statement") or stmt.get("action_statement") or ""),
            justification=str(stmt.get("justification") or ""),
            source_format="openvex",
        )
        for vid in ids:
            normalized = vid.upper().strip()
            if normalized:
                out[normalized] = record
    return out
