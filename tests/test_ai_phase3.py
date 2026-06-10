"""Phase 3 tests: AI enrichment layer (Claude Fable 5).

All tests run offline — model calls are monkeypatched. What we verify:
- the redaction boundary actually strips secret material
- enrichment is strictly additive (ai_* keys in evidence.raw only)
- every feature degrades to identity when AI is off or errors
- the activation gate honours the air-gap flag
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest

from vulnsuite.ai import client as ai_client
from vulnsuite.ai import compliance as ai_compliance
from vulnsuite.ai import correlate as ai_correlate
from vulnsuite.ai import redaction
from vulnsuite.ai import remediate as ai_remediate
from vulnsuite.ai import triage as ai_triage
from vulnsuite.ai.payloads import finding_payload, render_user_turn
from vulnsuite.ai.schemas import (
    AttackChain,
    ChainSeverity,
    CorrelationResult,
    Exploitability,
    RemediationBatchResult,
    RemediationPlan,
    SuggestedStatus,
    TriageBatchResult,
    TriageVerdict,
)
from vulnsuite.core.config import get_settings
from vulnsuite.core.schema import Evidence, Module, Severity


@pytest.fixture
def ai_on(monkeypatch):
    """Force the AI layer 'on' without touching the real gate inputs."""
    settings = get_settings()
    monkeypatch.setattr(settings.ai, "enabled", True)
    monkeypatch.setattr(settings.scanning, "offline_mode", False)
    yield settings


# ---------- redaction boundary ----------

class TestRedaction:
    def test_aws_key_masked(self):
        out = redaction.redact_text("key=AKIAIOSFODNN7EXAMPLE in config")
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert redaction.REDACTED in out

    def test_private_key_block_masked(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
        assert "MIIEow" not in redaction.redact_text(pem)

    def test_password_assignment_masked(self):
        out = redaction.redact_text('db_password = "Sup3rS3cret!"')
        assert "Sup3rS3cret!" not in out

    def test_jwt_and_github_token_masked(self):
        text = (
            "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
            " and ghp_abcdefghijklmnopqrstuvwxyz123456"
        )
        out = redaction.redact_text(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in out
        assert "ghp_abcdefghijklmnop" not in out

    def test_url_credentials_masked(self):
        out = redaction.redact_text("postgresql://admin:hunter22@db.internal:5432/x")
        assert "hunter22" not in out

    def test_secrets_module_snippet_blanked(self, make_finding):
        f = make_finding(
            Module.SECRETS,
            evidence=Evidence(
                file="src/cfg.py",
                line=3,
                snippet="aws_secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
                raw={"secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "detector": "gitleaks"},
            ),
        )
        safe = redaction.redact_finding(f)
        dumped = json.dumps(safe.model_dump(mode="json"))
        assert "wJalrXUtnFEMI" not in dumped
        assert safe.evidence.raw["detector"] == "gitleaks"   # non-secret keys survive
        # original untouched
        assert "wJalrXUtnFEMI" in f.evidence.raw["secret"]

    def test_payload_built_from_redacted_finding_is_clean(self, make_finding):
        f = make_finding(
            Module.SAST,
            evidence=Evidence(file="a.py", line=1, snippet="api_key = 'AKIAIOSFODNN7EXAMPLE'", raw={}),
        )
        payload = finding_payload(redaction.redact_finding(f))
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(payload)


# ---------- activation gate ----------

class TestActivationGate:
    def test_disabled_by_default(self):
        assert ai_client.ai_active() is False

    def test_offline_mode_wins_over_enabled(self, monkeypatch):
        settings = get_settings()
        monkeypatch.setattr(settings.ai, "enabled", True)
        monkeypatch.setattr(settings.scanning, "offline_mode", True)
        assert ai_client.ai_active() is False

    def test_enabled_and_online(self, ai_on):
        assert ai_client.ai_active() is True


# ---------- triage ----------

class TestTriage:
    def _verdict(self, finding_id: str) -> TriageVerdict:
        return TriageVerdict(
            finding_id=finding_id,
            fp_likelihood=0.9,
            confidence=0.85,
            exploitability=Exploitability.LOW,
            reasoning="Detector fired inside test fixtures.",
            suggested_status=SuggestedStatus.FALSE_POSITIVE,
        )

    def test_noop_when_disabled(self, make_finding):
        f = make_finding(Module.SAST)
        out = ai_triage.triage_findings([f])
        assert out == [f]

    def test_verdict_annotated_additively(self, ai_on, monkeypatch, make_finding):
        f = make_finding(Module.SAST, evidence=Evidence(raw={"check_id": "x"}))

        def fake_parse(**kwargs):
            return TriageBatchResult(verdicts=[self._verdict(str(f.finding_id))])

        monkeypatch.setattr(ai_triage, "parse_structured", fake_parse)
        out = ai_triage.triage_findings([f])

        triaged = out[0]
        assert triaged.evidence.raw["ai_triage"]["fp_likelihood"] == 0.9
        assert triaged.evidence.raw["check_id"] == "x"           # existing evidence kept
        assert triaged.status == f.status                         # status never mutated
        assert triaged.risk_score == f.risk_score

    def test_model_failure_degrades_to_identity(self, ai_on, monkeypatch, make_finding):
        f = make_finding(Module.SCA)

        def boom(**kwargs):
            raise ai_client.AIEnrichmentError("api down")

        monkeypatch.setattr(ai_triage, "parse_structured", boom)
        assert ai_triage.triage_findings([f]) == [f]

    def test_unknown_finding_ids_ignored(self, ai_on, monkeypatch, make_finding):
        f = make_finding(Module.SAST)

        def fake_parse(**kwargs):
            return TriageBatchResult(verdicts=[self._verdict(str(uuid4()))])

        monkeypatch.setattr(ai_triage, "parse_structured", fake_parse)
        out = ai_triage.triage_findings([f])
        assert "ai_triage" not in (out[0].evidence.raw or {})


# ---------- remediation ----------

class TestRemediation:
    def test_only_configured_buckets_get_plans(self, ai_on, monkeypatch, make_finding):
        p0 = make_finding(Module.SCA, risk_bucket="P0")
        p3 = make_finding(Module.SCA, risk_bucket="P3")
        captured: list[str] = []

        def fake_parse(**kwargs):
            payload = json.loads(kwargs["user"].split("Findings:\n", 1)[1])
            captured.extend(item["finding_id"] for item in payload)
            return RemediationBatchResult(
                plans=[
                    RemediationPlan(
                        finding_id=str(p0.finding_id),
                        summary="Pin the package.",
                        steps=["bump version"],
                        validation="re-run trivy",
                        estimated_effort="trivial",
                    )
                ]
            )

        monkeypatch.setattr(ai_remediate, "parse_structured", fake_parse)
        out = ai_remediate.remediate_findings([p0, p3])

        assert captured == [str(p0.finding_id)]   # P3 never sent
        assert "ai_remediation" in out[0].evidence.raw
        assert "ai_remediation" not in (out[1].evidence.raw or {})
        assert out[0].remediation == p0.remediation  # deterministic text untouched


# ---------- attack-chain correlation ----------

class TestCorrelation:
    def test_chain_annotates_members_and_escalation(self, ai_on, monkeypatch, make_finding):
        secret = make_finding(Module.SECRETS, risk_bucket="P2")
        exposed = make_finding(Module.ASM, risk_bucket="P1")
        unrelated = make_finding(Module.SAST, risk_bucket="P4")

        chain = AttackChain(
            finding_ids=[str(secret.finding_id), str(exposed.finding_id)],
            narrative="Leaked credential unlocks the internet-facing service.",
            composite_severity=ChainSeverity.CRITICAL,
            likelihood=0.7,
            suggested_bucket="P0",
            kill_chain_stage="initial-access",
        )

        def fake_parse(**kwargs):
            return CorrelationResult(chains=[chain], posture_note="tight chain")

        monkeypatch.setattr(ai_correlate, "parse_structured", fake_parse)
        out = ai_correlate.correlate_findings([secret, exposed, unrelated])
        by_id = {str(f.finding_id): f for f in out}

        assert by_id[str(secret.finding_id)].evidence.raw["ai_suggested_bucket"] == "P0"
        assert len(by_id[str(exposed.finding_id)].evidence.raw["ai_attack_chains"]) == 1
        assert "ai_attack_chains" not in (by_id[str(unrelated.finding_id)].evidence.raw or {})
        # deterministic bucket never mutated
        assert by_id[str(secret.finding_id)].risk_bucket == "P2"

    def test_single_finding_skips_call(self, ai_on, monkeypatch, make_finding):
        def boom(**kwargs):
            raise AssertionError("should not be called")

        monkeypatch.setattr(ai_correlate, "parse_structured", boom)
        f = make_finding(Module.SAST)
        assert ai_correlate.correlate_findings([f]) == [f]


# ---------- compliance fallback ----------

class TestComplianceMapping:
    def test_falls_back_to_heuristic_on_model_failure(self, ai_on, monkeypatch, make_finding):
        f = make_finding(Module.SECRETS)

        def boom(**kwargs):
            raise ai_client.AIEnrichmentError("api down")

        monkeypatch.setattr(ai_compliance, "parse_structured", boom)
        out = ai_compliance.map_findings_rbi([f])

        verdict = out[0].evidence.raw["ai_rbi"]
        assert "6.15" in verdict["control_ids"]            # secrets -> 6.15 heuristic
        assert "heuristic" in verdict["rationale"]


# ---------- batch schema sanitization ----------

class TestSchemaCleaning:
    def test_constraints_stripped_and_objects_closed(self):
        schema = ai_client.clean_schema(TriageBatchResult)
        dumped = json.dumps(schema)
        for banned in ("minimum", "maximum", "minLength", "maxLength", "pattern"):
            assert f'"{banned}"' not in dumped
        assert schema["additionalProperties"] is False

    def test_user_turn_is_deterministic(self, make_finding):
        f = make_finding(Module.SAST, severity=Severity.HIGH)
        assert render_user_turn([f]) == render_user_turn([f])
