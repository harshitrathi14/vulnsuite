from __future__ import annotations

from vulnsuite.core.dedup import dedup_findings
from vulnsuite.core.schema import Evidence, Module


def test_dedup_iac_by_check_file_and_resource(make_finding) -> None:
    evidence = Evidence(file="main.tf", raw={"check_id": "CKV_AWS_1", "resource": "aws_s3_bucket.logs"})
    first = make_finding(Module.IAC, evidence=evidence, tool="checkov")
    second = make_finding(Module.IAC, evidence=evidence, tool="trivy-config")
    second = second.model_copy(update={"asset_id": first.asset_id, "tenant_id": first.tenant_id})

    deduped = dedup_findings([first, second])

    assert len(deduped) == 1
    assert deduped[0].evidence.raw["corroborated_by"][0]["tool"] == "trivy-config"


def test_dedup_api_security_by_rule_method_and_url(make_finding) -> None:
    evidence = Evidence(raw={"rule_id": "zap-1001", "method": "GET", "path_or_url": "https://api.example.com/users"})
    first = make_finding(Module.API_SECURITY, evidence=evidence, tool="zap")
    second = make_finding(Module.API_SECURITY, evidence=evidence, tool="nuclei")
    second = second.model_copy(update={"asset_id": first.asset_id, "tenant_id": first.tenant_id})

    deduped = dedup_findings([first, second])

    assert len(deduped) == 1
    assert deduped[0].tool in {"zap", "nuclei"}
