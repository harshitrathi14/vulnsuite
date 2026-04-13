"""
VulnSuite - CISO-grade PDF report generator (Jinja2 + WeasyPrint)

Produces a board-ready PDF with:
  - Cover page (tenant, scan window, classification stamp)
  - Executive summary (P0-P4 counts, deltas vs previous scan)
  - Top 10 risks table (sorted by risk_score)
  - Module breakdown (SCA/SAST/Secrets/Network/Cloud/Container)
  - RBI CSF + CERT-In compliance snapshot
  - Full findings appendix grouped by asset
  - Audit block (generator version, operator, timestamp, hash)

Template is inlined as a string constant so the entire reporting
unit is one reviewable file. BFSI-appropriate: no external CSS
fetches, no web fonts, no JavaScript — WeasyPrint renders offline.

Requires: jinja2, weasyprint.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from uuid import UUID

from jinja2 import Environment, BaseLoader, select_autoescape
from weasyprint import HTML

from ..compliance.rbi_mapping import control_summary
from ..core.schema import Finding

logger = logging.getLogger(__name__)


@dataclass
class ReportMetadata:
    tenant_name: str
    scan_window_start: datetime
    scan_window_end: datetime
    operator: str
    classification: str = "CONFIDENTIAL — INTERNAL USE ONLY"
    generator_version: str = "VulnSuite 0.1"


TEMPLATE = r"""
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>VulnSuite Report</title>
<style>
@page { size: A4; margin: 2cm 1.8cm; @bottom-center { content: counter(page) " / " counter(pages); font-size: 9pt; color: #666; } }
body { font-family: "Helvetica", "Arial", sans-serif; color: #222; font-size: 10pt; line-height: 1.4; }
h1 { color: #0a2540; border-bottom: 3px solid #0a2540; padding-bottom: 6px; }
h2 { color: #0a2540; margin-top: 28px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
h3 { color: #333; margin-top: 18px; }
.cover { page-break-after: always; text-align: center; padding-top: 30%; }
.cover h1 { border: none; font-size: 28pt; }
.cover .subtitle { font-size: 14pt; color: #555; margin-top: 12px; }
.cover .classification { margin-top: 60px; padding: 8px; background: #b00020; color: white; font-weight: bold; letter-spacing: 2px; }
.meta { color: #555; font-size: 9pt; margin-top: 40px; }
table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 9pt; }
th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f0f4f8; font-weight: bold; }
.bucket-P0 { background: #b00020; color: white; font-weight: bold; text-align: center; }
.bucket-P1 { background: #d14; color: white; font-weight: bold; text-align: center; }
.bucket-P2 { background: #e67; color: white; text-align: center; }
.bucket-P3 { background: #f3a; color: white; text-align: center; }
.bucket-P4 { background: #eee; color: #555; text-align: center; }
.summary-grid { display: table; width: 100%; margin: 14px 0; }
.summary-cell { display: table-cell; text-align: center; padding: 14px; border: 1px solid #ccc; }
.summary-cell .n { font-size: 24pt; font-weight: bold; display: block; }
.evidence { font-family: "Courier New", monospace; font-size: 8pt; background: #f7f7f7; padding: 4px; }
.rbi-badge { background: #0a2540; color: white; padding: 1px 6px; border-radius: 3px; font-size: 8pt; }
.audit-block { margin-top: 40px; padding: 10px; border: 1px dashed #888; font-size: 8pt; color: #555; }
</style></head><body>

<div class="cover">
  <h1>Cybersecurity Vulnerability Assessment</h1>
  <div class="subtitle">{{ meta.tenant_name }}</div>
  <div class="subtitle">{{ meta.scan_window_start.strftime('%d %b %Y') }} — {{ meta.scan_window_end.strftime('%d %b %Y') }}</div>
  <div class="classification">{{ meta.classification }}</div>
  <div class="meta">
    Prepared by: {{ meta.operator }}<br>
    Generated: {{ now.strftime('%d %b %Y %H:%M %Z') }}<br>
    {{ meta.generator_version }}
  </div>
</div>

<h1>Executive Summary</h1>
<p>This report presents the results of a passive cybersecurity vulnerability assessment conducted across {{ asset_count }} asset(s) belonging to <strong>{{ meta.tenant_name }}</strong>. A total of <strong>{{ findings|length }}</strong> findings were identified across {{ module_count }} analysis modules, prioritized by the VulnSuite risk engine (CVSS × EPSS × asset criticality × exposure).</p>

<div class="summary-grid">
{% for bucket in ['P0','P1','P2','P3','P4'] %}
  <div class="summary-cell bucket-{{ bucket }}">
    <span class="n">{{ bucket_counts[bucket] }}</span>
    {{ bucket }}
  </div>
{% endfor %}
</div>

<p><strong>Immediate action (P0):</strong> {{ bucket_counts['P0'] }} finding(s) require remediation within 24 hours and may trigger CERT-In 6-hour incident reporting obligations where applicable under CERT-In Directions dated 28 April 2022.</p>

<h2>Top 10 Risks</h2>
<table>
<tr><th>#</th><th>Bucket</th><th>Score</th><th>Title</th><th>Asset</th><th>Tool</th><th>CVE</th></tr>
{% for f in top_risks %}
<tr>
  <td>{{ loop.index }}</td>
  <td class="bucket-{{ f.risk_bucket or 'P4' }}">{{ f.risk_bucket or '-' }}</td>
  <td>{{ "%.2f"|format(f.risk_score) }}</td>
  <td>{{ f.title }}</td>
  <td>{{ asset_names.get(f.asset_id|string, '-') }}</td>
  <td>{{ f.tool }}</td>
  <td>{{ f.cve|join(', ') or '-' }}</td>
</tr>
{% endfor %}
</table>

<h2>Module Breakdown</h2>
<table>
<tr><th>Module</th><th>Findings</th><th>P0</th><th>P1</th><th>P2</th><th>P3</th><th>P4</th></tr>
{% for mod, stats in module_stats.items() %}
<tr>
  <td>{{ mod }}</td>
  <td>{{ stats.total }}</td>
  <td>{{ stats.P0 }}</td><td>{{ stats.P1 }}</td><td>{{ stats.P2 }}</td><td>{{ stats.P3 }}</td><td>{{ stats.P4 }}</td>
</tr>
{% endfor %}
</table>

<h2>RBI CSF &amp; CERT-In Compliance Snapshot</h2>
<table>
<tr><th>Control Area</th><th>Findings</th><th>Status</th></tr>
{% for row in compliance_rows %}
<tr>
  <td><span class="rbi-badge">{{ row.control }}</span> {{ row.description }}</td>
  <td>{{ row.count }}</td>
  <td>{{ row.status }}</td>
</tr>
{% endfor %}
</table>

<h2>Findings Appendix</h2>
{% for asset_id, group in findings_by_asset.items() %}
<h3>{{ asset_names.get(asset_id, asset_id) }}</h3>
<table>
<tr><th>Bucket</th><th>Title</th><th>Severity</th><th>Evidence</th><th>Remediation</th></tr>
{% for f in group %}
<tr>
  <td class="bucket-{{ f.risk_bucket or 'P4' }}">{{ f.risk_bucket or '-' }}</td>
  <td>{{ f.title }}{% if f.cve %}<br><small>{{ f.cve|join(', ') }}</small>{% endif %}</td>
  <td>{{ f.severity }}</td>
  <td class="evidence">{{ (f.evidence.file or '')|truncate(60) }}{% if f.evidence.line %}:{{ f.evidence.line }}{% endif %}</td>
  <td>{{ f.remediation|truncate(200) }}</td>
</tr>
{% endfor %}
</table>
{% endfor %}

<div class="audit-block">
<strong>Audit Block</strong><br>
Generator: {{ meta.generator_version }}<br>
Operator: {{ meta.operator }}<br>
Tenant: {{ meta.tenant_name }}<br>
Scan window: {{ meta.scan_window_start.isoformat() }} — {{ meta.scan_window_end.isoformat() }}<br>
Report generated: {{ now.isoformat() }}<br>
Finding count: {{ findings|length }}<br>
Content hash (SHA-256): {{ content_hash }}<br>
Classification: {{ meta.classification }}
</div>

</body></html>
"""


class PDFReportGenerator:
    def __init__(self) -> None:
        self.env = Environment(
            loader=BaseLoader(),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.template = self.env.from_string(TEMPLATE)

    # ---------- public ----------

    def render(
        self,
        findings: Iterable[Finding],
        asset_names: dict[str, str],
        meta: ReportMetadata,
        output_path: str | Path,
    ) -> Path:
        findings = list(findings)
        output_path = Path(output_path)

        bucket_counts = self._bucket_counts(findings)
        top_risks = sorted(
            findings, key=lambda f: f.risk_score, reverse=True,
        )[:10]
        module_stats = self._module_stats(findings)
        compliance_rows = self._compliance_rows(findings)
        findings_by_asset = self._group_by_asset(findings)
        content_hash = self._hash_findings(findings)

        html = self.template.render(
            findings=findings,
            asset_count=len(findings_by_asset),
            module_count=len({self._m(f) for f in findings}),
            bucket_counts=bucket_counts,
            top_risks=top_risks,
            module_stats=module_stats,
            compliance_rows=compliance_rows,
            findings_by_asset=findings_by_asset,
            asset_names=asset_names,
            meta=meta,
            now=datetime.now(timezone.utc),
            content_hash=content_hash,
        )

        HTML(string=html).write_pdf(output_path)
        logger.info("wrote PDF report: %s (%d findings)", output_path, len(findings))
        return output_path

    # ---------- aggregations ----------

    @staticmethod
    def _m(f: Finding) -> str:
        return f.module if isinstance(f.module, str) else f.module.value

    def _bucket_counts(self, findings: list[Finding]) -> dict[str, int]:
        out = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for f in findings:
            if f.risk_bucket in out:
                out[f.risk_bucket] += 1
        return out

    def _module_stats(self, findings: list[Finding]) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for f in findings:
            mod = self._m(f)
            row = out.setdefault(
                mod, {"total": 0, "P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0},
            )
            row["total"] += 1
            if f.risk_bucket in row:
                row[f.risk_bucket] += 1
        return out

    def _compliance_rows(self, findings: list[Finding]) -> list[dict]:
        """One row per RBI control with a hit, sorted by control id, plus a
        synthesized CERT-In countdown row. Uses compliance/rbi_mapping for the
        module → control matrix so new collectors flow in automatically."""
        summary = control_summary(findings)
        rows = [
            {
                "control": cid,
                "description": data["name"],
                "count": data["count"],
                "status": data["status"],
            }
            for cid, data in sorted(summary.items())
        ]
        certin_count = sum(1 for f in findings if f.risk_bucket == "P0")
        rows.append({
            "control": "CERT-In",
            "description": "6-hour reportable (P0 findings)",
            "count": certin_count,
            "status": "BREACH" if certin_count else "OK",
        })
        return rows

    def _group_by_asset(
        self, findings: list[Finding],
    ) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in sorted(findings, key=lambda x: x.risk_score, reverse=True):
            out.setdefault(str(f.asset_id), []).append(f)
        return out

    @staticmethod
    def _hash_findings(findings: list[Finding]) -> str:
        h = hashlib.sha256()
        for f in sorted(findings, key=lambda x: str(x.finding_id)):
            h.update(str(f.finding_id).encode())
            h.update(f.title.encode())
            h.update(str(f.risk_score).encode())
        return h.hexdigest()
