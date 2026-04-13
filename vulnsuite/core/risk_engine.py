"""
VulnSuite - Risk Engine

Formula:  risk = CVSS_base * EPSS * (criticality/5) * exposure_factor
  - CVSS_base       : 0..10  (technical severity)
  - EPSS            : 0..1   (probability of exploit in next 30 days)
  - criticality/5   : 0.2..1 (business impact, from Asset.criticality 1-5)
  - exposure_factor : 0.3/0.6/1.0 (isolated/internal/internet)

Max possible score = 10 * 1 * 1 * 1 = 10.0
Buckets (aligned to BFSI risk register P0..P4):
  P0 critical  >= 7.0    immediate action, CERT-In 6h clock may apply
  P1 high      >= 4.5    fix within SLA (e.g. 7d)
  P2 medium    >= 2.0    fix within 30d
  P3 low       >= 0.5    backlog
  P4 info       < 0.5    informational
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, Protocol

from .schema import Finding, Asset, Severity

logger = logging.getLogger(__name__)


class EPSSProvider(Protocol):
    """Pluggable so we can swap FIRST.org API, Redis cache, or stub in tests."""
    def get(self, cve: str) -> float: ...


class StaticEPSS:
    """Fallback when no CVE or lookup fails. Derived from CVSS as a proxy."""
    def get(self, cve: str) -> float:  # noqa: ARG002
        return 0.1


@dataclass(frozen=True)
class RiskConfig:
    p0: float = 7.0
    p1: float = 4.5
    p2: float = 2.0
    p3: float = 0.5
    # Minimum EPSS floor so a finding with no CVE still carries some weight
    epss_floor: float = 0.05


class RiskEngine:
    def __init__(
        self,
        epss_provider: EPSSProvider | None = None,
        config: RiskConfig | None = None,
    ) -> None:
        self.epss = epss_provider or StaticEPSS()
        self.cfg = config or RiskConfig()

    # ---------- core math ----------

    def _effective_epss(self, finding: Finding) -> float:
        if not finding.cve:
            return max(finding.epss, self.cfg.epss_floor)
        # Take the max EPSS across associated CVEs - worst case wins
        scores = [self.epss.get(c) for c in finding.cve]
        scores.append(finding.epss)  # respect pre-populated value
        return max(max(scores), self.cfg.epss_floor)

    def score(self, finding: Finding, asset: Asset) -> float:
        cvss = finding.cvss_base or self._severity_to_cvss(finding.severity)
        epss = self._effective_epss(finding)
        crit = asset.criticality / 5.0
        exposure = float(asset.exposure) if asset.exposure else 0.6
        raw = cvss * epss * crit * exposure
        return round(min(raw, 10.0), 3)

    @staticmethod
    def _severity_to_cvss(sev: Severity | str) -> float:
        """Fallback when CVSS is missing (e.g. secrets, some SAST findings)."""
        s = sev.value if isinstance(sev, Severity) else sev
        return {
            "critical": 9.5, "high": 7.5, "medium": 5.0,
            "low": 3.0, "info": 1.0,
        }.get(s, 1.0)

    def bucket(self, score: float) -> str:
        c = self.cfg
        if score >= c.p0: return "P0"
        if score >= c.p1: return "P1"
        if score >= c.p2: return "P2"
        if score >= c.p3: return "P3"
        return "P4"

    # ---------- public API ----------

    def enrich(self, finding: Finding, asset: Asset) -> Finding:
        """Return a copy of finding with risk_score + risk_bucket populated."""
        if finding.asset_id != asset.asset_id:
            raise ValueError("asset/finding mismatch")
        s = self.score(finding, asset)
        return finding.model_copy(update={"risk_score": s, "risk_bucket": self.bucket(s)})

    def enrich_batch(
        self, findings: Iterable[Finding], assets: dict[str, Asset],
    ) -> list[Finding]:
        out: list[Finding] = []
        for f in findings:
            a = assets.get(str(f.asset_id))
            if a is None:
                logger.warning("no asset for finding %s; skipping scoring", f.finding_id)
                out.append(f)
                continue
            out.append(self.enrich(f, a))
        return out
