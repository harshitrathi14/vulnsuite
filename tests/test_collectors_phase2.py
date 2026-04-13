from __future__ import annotations

from uuid import uuid4

from vulnsuite.collectors.api_security.nuclei import NucleiCollector
from vulnsuite.collectors.api_security.zap import ZAPAutomationCollector
from vulnsuite.collectors.iac.checkov import CheckovCollector
from vulnsuite.collectors.kubernetes.kubescape import KubescapeCollector
from vulnsuite.collectors.supply_chain.syft import SyftCollector
from vulnsuite.collectors.supply_chain.vex import VEXProcessor
from vulnsuite.core.schema import Evidence, Module, Severity


def test_checkov_normalizes_failed_checks() -> None:
    collector = object.__new__(CheckovCollector)
    raw = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "S3 bucket public read",
                    "file_path": "main.tf",
                    "resource": "aws_s3_bucket.public",
                    "severity": "HIGH",
                    "guideline": "https://example/guideline",
                }
            ]
        }
    }
    findings = collector._normalize(raw, uuid4(), uuid4(), Module.IAC)
    assert findings[0].module == Module.IAC
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence.file == "main.tf"


def test_kubescape_normalizes_failed_controls() -> None:
    collector = object.__new__(KubescapeCollector)
    raw = {
        "results": [
            {
                "status": "failed",
                "controlID": "C-001",
                "name": "Privileged container",
                "severity": "critical",
                "namespace": "prod",
                "kind": "Deployment",
                "resourceName": "api",
            }
        ]
    }
    findings = collector._normalize(raw, uuid4(), uuid4())
    assert findings[0].module == Module.KUBERNETES
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].evidence.raw["namespace"] == "prod"


def test_zap_normalizes_instances() -> None:
    collector = object.__new__(ZAPAutomationCollector)
    report = {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "10001",
                        "name": "Missing header",
                        "riskdesc": "Medium (Medium)",
                        "desc": "Header missing",
                        "cweid": "16",
                        "instances": [{"uri": "https://api.example.com/users", "method": "GET"}],
                    }
                ]
            }
        ]
    }
    findings = collector._normalize(report, uuid4(), uuid4())
    assert findings[0].module == Module.API_SECURITY
    assert findings[0].cwe == ["CWE-16"]


def test_nuclei_normalizes_api_finding() -> None:
    collector = object.__new__(NucleiCollector)
    raw = [
        {
            "template-id": "exposed-config",
            "matched-at": "https://api.example.com/.env",
            "host": "api.example.com",
            "type": "http",
            "info": {
                "name": "Exposed config",
                "severity": "high",
                "reference": ["https://example/ref"],
                "classification": {"cve-id": ["CVE-2025-0001"], "cwe-id": ["200"]},
            },
        }
    ]
    findings = collector._normalize(raw, uuid4(), uuid4())
    assert findings[0].cve == ["CVE-2025-0001"]
    assert findings[0].severity == Severity.HIGH


def test_syft_normalizes_missing_identity_components() -> None:
    collector = object.__new__(SyftCollector)
    sbom = {"components": [{"name": "requests", "type": "library", "version": ""}]}
    findings = collector._normalize(sbom, uuid4(), uuid4())
    assert findings[0].module == Module.SUPPLY_CHAIN
    assert "missing purl" in findings[0].title.lower()


def test_vex_processor_downgrades_not_affected(make_finding, tmp_path) -> None:
    vex_path = tmp_path / "vex.json"
    vex_path.write_text(
        """
        {
          "vulnerabilities": [
            {
              "id": "CVE-2025-1234",
              "analysis": {
                "state": "not_affected",
                "detail": "Component not reachable",
                "justification": "code_not_present"
              }
            }
          ]
        }
        """
    )
    finding = make_finding(
        Module.SUPPLY_CHAIN,
        cve=["CVE-2025-1234"],
        evidence=Evidence(raw={"purl": "pkg:pypi/demo@1.0.0"}),
        risk_score=5.0,
        risk_bucket="P1",
    )
    processor = VEXProcessor.load_many([str(vex_path)])
    updated = processor.apply([finding])[0]
    assert updated.severity == Severity.INFO
    assert updated.risk_bucket == "P4"
    assert updated.evidence.raw["vex_status"] == "not_affected"
