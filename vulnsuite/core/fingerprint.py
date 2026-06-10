"""VulnSuite - Stable cross-scan finding fingerprints.

A fingerprint is the identity of a vulnerability *across re-scans*, so
the same issue found on Monday and Wednesday is one row whose
``first_seen`` / ``last_seen`` accumulate — not two duplicate rows.

It reuses the deterministic dedup key (which already encodes module +
asset + location/identity) and falls back to a tool/location/title
hash for modules dedup leaves unkeyed (network, cloud, discovery).
The result is a short hex digest suitable for a unique constraint.
"""
from __future__ import annotations

import hashlib

from .dedup import dedup_key
from .schema import Finding

_SEP = "\x1f"  # unit separator — cannot appear in the textual fields we join


def finding_fingerprint(finding: Finding) -> str:
    """Return a stable 32-char hex identity for this finding."""
    key = dedup_key(finding)
    if key is None:
        module = finding.module if isinstance(finding.module, str) else finding.module.value
        ev = finding.evidence
        raw = (ev.raw or {}) if ev else {}
        key = (
            "fallback",
            module,
            str(finding.asset_id),
            finding.tool,
            (ev.file or "") if ev else "",
            str((ev.line or 0) if ev else 0),
            finding.cve[0] if finding.cve else "",
            str(raw.get("check_id") or raw.get("rule_id") or raw.get("control_id") or ""),
            str(raw.get("host") or raw.get("resource_name") or ""),
            finding.title[:120],
        )
    digest = hashlib.sha256(_SEP.join(str(p) for p in key).encode("utf-8")).hexdigest()
    return digest[:32]
