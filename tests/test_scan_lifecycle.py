"""Regression tests for the scan pipeline's EPSS scoring and auto-close guard.

1. EPSS must actually reach the risk engine during an async scan (it used to
   silently fall back to the 0.05 floor, collapsing everything to P3/P4).
2. A collector that crashes, times out, is skipped, or reports errors must
   not cause its previously-seen findings to be auto-closed as "fixed".
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from vulnsuite.core import orchestrator as orch_mod
from vulnsuite.core.db import _reporting_tools, reconcile_plan
from vulnsuite.core.orchestrator import Orchestrator, OrchestratorConfig
from vulnsuite.core.risk_engine import RiskEngine
from vulnsuite.core.schema import Asset, AssetType, ExposureFactor, Module, ScanResult


def _asset() -> Asset:
    return Asset(
        tenant_id=uuid4(),
        name="payments-api",
        asset_type=AssetType.REPO,
        criticality=5,
        exposure=ExposureFactor.INTERNET,
    )


def _result(asset: Asset, tool: str, findings=(), errors=()) -> ScanResult:
    now = datetime.now(timezone.utc)
    return ScanResult(
        tool=tool, module=Module.SCA, asset_id=asset.asset_id,
        started_at=now, finished_at=now,
        findings=list(findings), errors=list(errors),
    )


class WarmOnlyEPSS:
    """Mimics CachedEPSSProvider inside a running loop: get() only sees
    what warm() has already loaded; anything else returns the floor."""

    def __init__(self, scores: dict[str, float]) -> None:
        self._remote = scores
        self._cache: dict[str, float] = {}
        self.warmed: set[str] = set()

    def get(self, cve: str) -> float:
        return self._cache.get(cve, 0.0)

    async def warm(self, cves) -> None:
        self.warmed |= set(cves)
        for c in cves:
            if c in self._remote:
                self._cache[c] = self._remote[c]


# ---------- 1) EPSS reaches scoring ----------

def test_orchestrator_prefetches_epss_before_scoring(make_finding) -> None:
    asset = _asset()
    finding = make_finding(
        Module.SCA, tenant_id=asset.tenant_id, asset_id=asset.asset_id,
        tool="trivy", cve=["CVE-2024-3094"], cvss_base=9.8, epss=0.0,
    )
    epss = WarmOnlyEPSS({"CVE-2024-3094": 0.9})
    orch = Orchestrator(RiskEngine(epss_provider=epss), OrchestratorConfig(persist=False))

    async def call():
        return _result(asset, "trivy", [finding])

    report = asyncio.run(orch.run(asset, [call]))

    assert epss.warmed == {"CVE-2024-3094"}
    scored = report.findings_after_dedup[0]
    # 9.8 * 0.9 * 1.0 * 1.0 = 8.82 -> P0. Without the prefetch it was
    # 9.8 * 0.05 floor = 0.49 -> P4.
    assert scored.risk_bucket == "P0"
    assert scored.risk_score == pytest.approx(8.82)


def test_epss_prefetch_failure_does_not_fail_the_scan(make_finding) -> None:
    asset = _asset()
    finding = make_finding(
        Module.SCA, tenant_id=asset.tenant_id, asset_id=asset.asset_id,
        cve=["CVE-2024-0001"], epss=0.0,
    )

    class BrokenEPSS(WarmOnlyEPSS):
        async def warm(self, cves) -> None:
            raise RuntimeError("FIRST.org down")

    orch = Orchestrator(RiskEngine(epss_provider=BrokenEPSS({})), OrchestratorConfig(persist=False))

    async def call():
        return _result(asset, "trivy", [finding])

    report = asyncio.run(orch.run(asset, [call]))
    assert report.findings_after_dedup[0].risk_bucket is not None


def test_cached_provider_offline_csv_used_inside_running_loop(tmp_path) -> None:
    pytest.importorskip("redis")
    from vulnsuite.core.epss_provider import CachedEPSSProvider

    csv = tmp_path / "epss.csv"
    csv.write_text("#model_version:v2025\ncve,epss,percentile\nCVE-2024-3094,0.91,0.99\n")
    provider = CachedEPSSProvider(offline_csv_path=str(csv))

    async def inside_loop():
        return provider.get("cve-2024-3094"), provider.get("CVE-1999-0001")

    hit, miss = asyncio.run(inside_loop())
    assert hit == pytest.approx(0.91)
    assert miss == 0.0


def test_cached_provider_get_sees_warmed_scores_inside_running_loop() -> None:
    pytest.importorskip("redis")
    from vulnsuite.core.epss_provider import CachedEPSSProvider

    class FakeHTTP:
        async def get(self, url, params, timeout):
            rows = [{"cve": c, "epss": "0.42"} for c in params["cve"].split(",")]
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"data": rows})

    provider = CachedEPSSProvider(http_client=FakeHTTP())

    async def inside_loop():
        before = provider.get("CVE-2024-3094")
        await provider.warm(["CVE-2024-3094"])
        return before, provider.get("CVE-2024-3094")

    before, after = asyncio.run(inside_loop())
    assert before == 0.0
    assert after == pytest.approx(0.42)


# ---------- 2) auto-close guard ----------

def test_reconcile_plan_only_closes_closable_fingerprints() -> None:
    existing = {"trivy-1": "open", "gitleaks-1": "open", "accepted-1": "accepted"}
    plan = reconcile_plan(existing, current=set(), closable={"trivy-1", "accepted-1"})
    assert plan["close"] == ["trivy-1"]


def test_reconcile_plan_without_guard_keeps_legacy_behaviour() -> None:
    plan = reconcile_plan({"a": "open", "b": "fixed"}, current=set())
    assert plan["close"] == ["a"]


def test_reporting_tools_includes_corroborating_tools() -> None:
    row = SimpleNamespace(
        tool="grype",
        evidence={"raw": {"corroborated_by": [{"tool": "trivy"}, {"tool": "osv"}]}},
    )
    assert _reporting_tools(row) == {"grype", "trivy", "osv"}
    assert _reporting_tools(SimpleNamespace(tool="bandit", evidence={})) == {"bandit"}


def test_orchestrator_passes_only_cleanly_completed_tools(monkeypatch) -> None:
    asset = _asset()
    captured: dict = {}

    async def fake_reconcile(tenant_id, asset_id, findings, completed_tools=None):
        captured["completed_tools"] = completed_tools
        return {"new": 0, "reopened": 0, "fixed": 0, "updated": 0, "total": 0}

    monkeypatch.setattr(orch_mod, "reconcile_findings", fake_reconcile)

    async def ok():
        return _result(asset, "semgrep")

    async def reported_error():   # collector caught its own failure
        return _result(asset, "trivy", errors=["trivy timeout after 600s"])

    async def skipped():          # offline-mode _skip_call stub
        return _result(asset, "nuclei", errors=["not run: offline mode"])

    async def crashed():
        raise RuntimeError("boom")

    async def hung():
        await asyncio.sleep(5)
        return _result(asset, "gitleaks")

    orch = Orchestrator(RiskEngine(), OrchestratorConfig(per_collector_timeout=0.05))
    asyncio.run(orch.run(asset, [ok, reported_error, skipped, crashed, hung]))

    assert captured["completed_tools"] == {"semgrep"}
