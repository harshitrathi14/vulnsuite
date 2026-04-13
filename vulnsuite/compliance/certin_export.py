"""VulnSuite - CERT-In incident export.

Generates a CERT-In-compliant incident report JSON for P0 findings,
honoring the 28 April 2022 CERT-In Directions requiring reporting
within 6 hours of detection. Output is a self-contained JSON file
suitable for upload to CERT-In's incident reporting portal or for
email attachment to incident@cert-in.org.in.

This module does NOT transmit the report. Transmission is an
explicit human action (per BFSI control requirements — automated
regulatory submission requires legal sign-off per incident).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from ..core.schema import Finding

CERTIN_WINDOW_HOURS = 6
INCIDENT_CATEGORIES = {
    "secrets": "Unauthorized access / data breach (leaked credentials)",
    "sca": "Vulnerable software / unpatched systems",
    "container": "Vulnerable software / unpatched systems",
    "sast": "Insecure application code",
    "network": "Network scanning / exposed services",
    "cloud": "Cloud resource misconfiguration",
}


def build_incident_report(
    findings: Iterable[Finding],
    organization: str,
    contact_name: str,
    contact_email: str,
    contact_phone: str,
    incident_id: str | None = None,
    detection_time: datetime | None = None,
) -> dict:
    """Build a CERT-In incident report dict for P0 findings only."""
    findings = [f for f in findings if f.risk_bucket == "P0"]
    if not findings:
        return {}

    detection_time = detection_time or datetime.now(timezone.utc)
    deadline = detection_time + timedelta(hours=CERTIN_WINDOW_HOURS)
    incident_id = incident_id or _generate_id(findings, detection_time)

    # Categorize by module
    categories: dict[str, int] = {}
    for f in findings:
        mod = f.module if isinstance(f.module, str) else f.module.value
        cat = INCIDENT_CATEGORIES.get(mod, "Other")
        categories[cat] = categories.get(cat, 0) + 1

    affected_systems = sorted({
        (f.evidence.raw or {}).get("host")
        or (f.evidence.raw or {}).get("resource_name")
        or (f.evidence.file or "")
        for f in findings
        if f.evidence
    } - {""})

    return {
        "report_metadata": {
            "incident_id": incident_id,
            "report_version": "1.0",
            "standard": "CERT-In Directions 28 April 2022",
            "reporting_window_hours": CERTIN_WINDOW_HOURS,
            "detection_time_utc": detection_time.isoformat(),
            "reporting_deadline_utc": deadline.isoformat(),
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "organization": {
            "name": organization,
            "sector": "BFSI",
            "contact": {
                "name": contact_name,
                "email": contact_email,
                "phone": contact_phone,
            },
        },
        "incident_summary": {
            "total_critical_findings": len(findings),
            "categories": categories,
            "affected_systems_count": len(affected_systems),
            "highest_risk_score": max(f.risk_score for f in findings),
        },
        "affected_systems": affected_systems[:100],  # cap for readability
        "findings": [_finding_to_report(f) for f in findings],
        "recommended_actions": [
            "Isolate or patch affected systems within CERT-In window",
            "Preserve logs per CERT-In 180-day retention requirement",
            "Initiate internal forensic review",
            "Notify RBI as per Cyber Security Framework escalation matrix",
        ],
        "integrity": {
            "algorithm": "SHA-256",
            "content_hash": _content_hash(findings),
        },
    }


def write_report(
    report: dict, output_dir: str | Path,
) -> Path | None:
    if not report:
        return None
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    incident_id = report["report_metadata"]["incident_id"]
    path = output_dir / f"certin_{incident_id}.json"
    path.write_text(json.dumps(report, indent=2, default=str))
    return path


def _generate_id(findings: list[Finding], when: datetime) -> str:
    h = hashlib.sha256()
    h.update(when.isoformat().encode())
    for f in findings:
        h.update(str(f.finding_id).encode())
    return f"CERTIN-{when.strftime('%Y%m%d%H%M%S')}-{h.hexdigest()[:8].upper()}"


def _content_hash(findings: list[Finding]) -> str:
    h = hashlib.sha256()
    for f in sorted(findings, key=lambda x: str(x.finding_id)):
        h.update(f.model_dump_json().encode())
    return h.hexdigest()


def _finding_to_report(f: Finding) -> dict:
    raw = (f.evidence.raw or {}) if f.evidence else {}
    return {
        "finding_id": str(f.finding_id),
        "title": f.title,
        "description": f.description[:500],
        "severity": f.severity if isinstance(f.severity, str) else f.severity.value,
        "risk_score": f.risk_score,
        "cve": f.cve,
        "cwe": f.cwe,
        "tool": f.tool,
        "module": f.module if isinstance(f.module, str) else f.module.value,
        "affected_resource": (
            raw.get("host") or raw.get("resource_name")
            or (f.evidence.file if f.evidence else None)
        ),
        "first_seen_utc": f.first_seen.isoformat(),
        "remediation": f.remediation[:500],
    }
