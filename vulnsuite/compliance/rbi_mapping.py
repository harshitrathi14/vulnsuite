"""VulnSuite - RBI Cyber Security Framework control mapping.

Maps findings to RBI CSF Annex-I / Annex-II controls so audit
reports can show control-to-evidence traceability. The mapping is
heuristic (module + keywords + embedded citations from collectors).
"""
from __future__ import annotations

from collections import defaultdict

from ..core.schema import Finding, Module


RBI_CONTROLS: dict[str, str] = {
    "6.1": "Inventory management of business IT assets",
    "6.2": "Cryptographic controls and TLS configuration",
    "6.3": "Patch/vulnerability management",
    "6.4": "Secure configuration (web headers, hardening)",
    "6.5": "Certificate management and PKI",
    "6.6": "Access control and least privilege",
    "6.7": "Secure mail and messaging",
    "6.8": "Removable media and endpoint controls",
    "6.9": "Anti-malware and EDR",
    "6.10": "User/employee awareness and training",
    "6.11": "Customer education",
    "6.12": "Incident response and reporting",
    "6.13": "Cloud security controls",
    "6.14": "Application security lifecycle (SDLC)",
    "6.15": "Secrets management",
    "6.16": "Database security",
}


def map_finding(f: Finding) -> list[str]:
    """Return RBI control IDs that this finding maps to."""
    module = f.module if isinstance(f.module, str) else f.module.value
    raw = (f.evidence.raw or {}) if f.evidence else {}

    citation = str(raw.get("rbi_control") or "")
    hits: set[str] = set()
    for cid in RBI_CONTROLS:
        if cid in citation:
            hits.add(cid)

    if module in (Module.SCA.value, Module.CONTAINER.value):
        hits.add("6.3")
    if module == Module.SAST.value:
        hits.add("6.14")
    if module == Module.SECRETS.value:
        hits.add("6.15")
    if module == Module.NETWORK.value:
        hits.update({"6.2", "6.4"})
    if module == Module.CLOUD.value:
        hits.add("6.13")
    if module == Module.DISCOVERY.value:
        hits.add("6.1")
    if module == Module.IAC.value:
        hits.update({"6.4", "6.14"})
    if module == Module.KUBERNETES.value:
        hits.update({"6.3", "6.4", "6.13"})
    if module == Module.ASM.value:
        hits.update({"6.1", "6.2", "6.4"})
    if module == Module.API_SECURITY.value:
        hits.add("6.14")
    if module == Module.SUPPLY_CHAIN.value:
        hits.update({"6.3", "6.14"})

    # DB exposure heuristic from nmap service field
    service = (raw.get("service") or "").lower()
    if service in ("mysql", "postgresql", "mongodb", "redis", "mssql"):
        hits.add("6.16")

    return sorted(hits)


def control_summary(findings: list[Finding]) -> dict[str, dict]:
    """Return {control_id: {name, count, p0_count, statuses}} summary."""
    summary: dict[str, dict] = defaultdict(
        lambda: {"name": "", "count": 0, "p0": 0, "p1": 0, "status": "OK"}
    )
    for f in findings:
        for cid in map_finding(f):
            row = summary[cid]
            row["name"] = RBI_CONTROLS.get(cid, cid)
            row["count"] += 1
            if f.risk_bucket == "P0":
                row["p0"] += 1
            if f.risk_bucket == "P1":
                row["p1"] += 1
            if row["p0"] > 0:
                row["status"] = "CRITICAL BREACH"
            elif row["p1"] > 0:
                row["status"] = "BREACH"
            elif row["count"] > 0 and row["status"] == "OK":
                row["status"] = "WEAK"
    return dict(summary)
