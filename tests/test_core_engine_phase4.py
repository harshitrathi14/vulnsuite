"""Phase 4 tests: core-engine enhancements (offline, no DB required).

- finding fingerprints are stable across re-scans and distinct per issue
- reconcile_plan classifies insert/update/reopen/close correctly
- CISA KEV escalation forces real-world-exploited findings up the queue
- live-exploitation escalation re-scores after threat intel
- asset auto-criticality derives honest scores from tags
"""
from __future__ import annotations

from uuid import uuid4

from vulnsuite.core.asset_rules import apply_asset_rules
from vulnsuite.core.config import AssetPolicySettings
from vulnsuite.core.db import reconcile_plan
from vulnsuite.core.fingerprint import finding_fingerprint
from vulnsuite.core.kev_provider import KEVProvider, _parse_catalog
from vulnsuite.core.risk_engine import RiskConfig, RiskEngine
from vulnsuite.core.schema import Asset, AssetType, Evidence, ExposureFactor, Module, Severity


# ---------- fingerprints ----------

class TestFingerprint:
    def test_stable_across_identical_findings(self, make_finding):
        aid = uuid4()
        f1 = make_finding(Module.SAST, asset_id=aid,
                          evidence=Evidence(file="app.py", line=42, raw={"check_id": "X"}),
                          cwe=["CWE-89"])
        f2 = make_finding(Module.SAST, asset_id=aid,
                          evidence=Evidence(file="app.py", line=42, raw={"check_id": "X"}),
                          cwe=["CWE-89"])
        # different finding_id (new scan), same underlying issue
        assert finding_fingerprint(f1) == finding_fingerprint(f2)

    def test_distinct_for_different_issues(self, make_finding):
        aid = uuid4()
        a = make_finding(Module.SAST, asset_id=aid,
                         evidence=Evidence(file="a.py", line=1, raw={"check_id": "X"}), cwe=["CWE-89"])
        b = make_finding(Module.SAST, asset_id=aid,
                         evidence=Evidence(file="b.py", line=9, raw={"check_id": "Y"}), cwe=["CWE-79"])
        assert finding_fingerprint(a) != finding_fingerprint(b)

    def test_unkeyed_module_gets_fallback_fingerprint(self, make_finding):
        # NETWORK has no dedup key -> fallback path must still be stable
        aid = uuid4()
        f1 = make_finding(Module.NETWORK, asset_id=aid, tool="nmap", title="Open 22/tcp",
                          evidence=Evidence(raw={"host": "10.0.0.1"}))
        f2 = make_finding(Module.NETWORK, asset_id=aid, tool="nmap", title="Open 22/tcp",
                          evidence=Evidence(raw={"host": "10.0.0.1"}))
        assert finding_fingerprint(f1) == finding_fingerprint(f2)


# ---------- reconcile planner ----------

class TestReconcilePlan:
    def test_new_finding_inserted(self):
        plan = reconcile_plan({}, {"fp1"})
        assert plan["insert"] == ["fp1"]
        assert plan["close"] == []

    def test_seen_again_updated_not_closed(self):
        plan = reconcile_plan({"fp1": "open"}, {"fp1"})
        assert plan["update"] == ["fp1"]
        assert plan["close"] == []

    def test_disappeared_finding_closed(self):
        plan = reconcile_plan({"fp1": "open"}, set())
        assert plan["close"] == ["fp1"]

    def test_fixed_finding_reappears_is_reopened(self):
        plan = reconcile_plan({"fp1": "fixed"}, {"fp1"})
        assert plan["reopen"] == ["fp1"]
        assert "fp1" in plan["update"]

    def test_already_fixed_and_still_gone_not_reclosed(self):
        plan = reconcile_plan({"fp1": "fixed"}, set())
        assert plan["close"] == []

    def test_analyst_owned_statuses_never_auto_closed(self):
        existing = {"fp_fp": "false_positive", "fp_acc": "accepted", "fp_open": "open"}
        plan = reconcile_plan(existing, set())
        assert set(plan["close"]) == {"fp_open"}


# ---------- KEV escalation ----------

class TestKEVEscalation:
    def _asset(self):
        return Asset(asset_id=uuid4(), tenant_id=uuid4(), name="dev-box",
                     asset_type=AssetType.HOST, criticality=1,
                     exposure=ExposureFactor.ISOLATED)

    def test_kev_forces_p0_on_otherwise_low_finding(self, make_finding):
        asset = self._asset()
        # low criticality + isolated -> would normally score very low
        f = make_finding(Module.SCA, asset_id=asset.asset_id, cve=["CVE-2024-3094"],
                         cvss_base=9.8, epss=0.4, severity=Severity.CRITICAL)
        engine = RiskEngine(kev_provider=KEVProvider({"CVE-2024-3094"}))
        out = engine.enrich(f, asset)
        assert out.risk_bucket == "P0"
        assert out.risk_score >= 7.0
        assert "cisa-kev" in out.evidence.raw["risk_escalated_by"]
        assert out.evidence.raw["kev_listed"] is True

    def test_non_kev_finding_not_escalated(self, make_finding):
        asset = self._asset()
        f = make_finding(Module.SCA, asset_id=asset.asset_id, cve=["CVE-2000-0001"],
                         cvss_base=9.8, epss=0.4)
        engine = RiskEngine(kev_provider=KEVProvider({"CVE-2024-3094"}))
        out = engine.enrich(f, asset)
        assert out.risk_bucket != "P0"
        assert "risk_escalated_by" not in (out.evidence.raw or {})

    def test_escalation_can_be_disabled(self, make_finding):
        asset = self._asset()
        f = make_finding(Module.SCA, asset_id=asset.asset_id, cve=["CVE-2024-3094"])
        engine = RiskEngine(
            kev_provider=KEVProvider({"CVE-2024-3094"}),
            config=RiskConfig(escalation_enabled=False),
        )
        out = engine.enrich(f, asset)
        assert "risk_escalated_by" not in (out.evidence.raw or {})


class TestExploitationEscalation:
    def test_active_exploitation_forces_p0(self, make_finding):
        f = make_finding(Module.SCA, cve=["CVE-2024-3094"], risk_score=2.0, risk_bucket="P2")
        engine = RiskEngine()
        out = engine.apply_exploitation_escalation(f, actively_exploited=True)
        assert out.risk_bucket == "P0"
        assert out.risk_score >= 7.0
        assert "active-exploitation" in out.evidence.raw["risk_escalated_by"]

    def test_noop_when_no_evidence(self, make_finding):
        f = make_finding(Module.SCA, risk_score=3.0, risk_bucket="P2")
        engine = RiskEngine()
        out = engine.apply_exploitation_escalation(f, kev=False, actively_exploited=False)
        assert out is f

    def test_does_not_downgrade_existing_high_score(self, make_finding):
        f = make_finding(Module.SCA, risk_score=9.0, risk_bucket="P0")
        engine = RiskEngine()
        out = engine.apply_exploitation_escalation(f, actively_exploited=True)
        assert out.risk_score == 9.0  # floor never lowers an already-higher score


# ---------- KEV catalog parsing ----------

class TestKEVCatalog:
    def test_parse_catalog_extracts_cve_ids(self):
        payload = {"vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
            {"cveID": "cve-2024-3094"},
            {"notACve": "x"},
        ]}
        ids = _parse_catalog(payload)
        assert ids == {"CVE-2021-44228", "CVE-2024-3094"}

    def test_provider_case_insensitive(self):
        p = KEVProvider({"CVE-2021-44228"})
        assert p.is_kev("cve-2021-44228")
        assert p.any_kev(["CVE-0000-0000", "CVE-2021-44228"])
        assert not p.is_kev("CVE-2000-0001")


# ---------- asset auto-criticality ----------

class TestAssetRules:
    def _asset(self, tags, criticality=2, exposure=ExposureFactor.INTERNAL):
        return Asset(asset_id=uuid4(), tenant_id=uuid4(), name="svc",
                     asset_type=AssetType.HOST, criticality=criticality,
                     exposure=exposure, tags=tags)

    def test_prod_tag_raises_to_5(self):
        out = apply_asset_rules(self._asset({"env": "prod"}), AssetPolicySettings())
        assert out.criticality == 5

    def test_internet_tag_sets_exposure(self):
        out = apply_asset_rules(self._asset({"network": "internet-facing"}), AssetPolicySettings())
        assert float(out.exposure) == float(ExposureFactor.INTERNET)

    def test_sensitive_tag_bumps_one_notch(self):
        out = apply_asset_rules(self._asset({"data": "pci"}, criticality=3), AssetPolicySettings())
        assert out.criticality == 4

    def test_never_lowers_explicit_criticality(self):
        # dev tag must not pull a hand-set criticality 5 down
        out = apply_asset_rules(self._asset({"env": "dev"}, criticality=5), AssetPolicySettings())
        assert out.criticality == 5

    def test_disabled_policy_is_noop(self):
        asset = self._asset({"env": "prod"})
        out = apply_asset_rules(asset, AssetPolicySettings(auto_criticality=False))
        assert out is asset

    def test_no_tags_unchanged(self):
        asset = self._asset({})
        out = apply_asset_rules(asset, AssetPolicySettings())
        assert out is asset


# ---------- escalation surfaced to SIEM ----------

class TestEscalationSurfacing:
    def test_siem_envelope_carries_escalation(self, make_finding):
        from vulnsuite.integrations.siem import normalize_for_siem

        f = make_finding(
            Module.SCA,
            risk_bucket="P0",
            cve=["CVE-2024-3094"],
            evidence=Evidence(raw={"risk_escalated_by": ["cisa-kev"], "kev_listed": True}),
        )
        doc = normalize_for_siem(f, "Tenant Bank")
        assert doc["risk_escalated"] is True
        assert "cisa-kev" in doc["risk_escalated_by"]
        assert doc["ai_kev_listed"] is True

    def test_siem_envelope_clean_without_escalation(self, make_finding):
        from vulnsuite.integrations.siem import normalize_for_siem

        doc = normalize_for_siem(make_finding(Module.SAST), "Tenant Bank")
        assert doc["risk_escalated"] is False
        assert doc["risk_escalated_by"] == []
