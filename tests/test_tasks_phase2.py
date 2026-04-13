from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from vulnsuite.collectors.kubernetes.inventory import WorkloadImageRef
from vulnsuite.core.schema import AssetType, DASTMode, Evidence, Finding, Module, ScanResult, Severity
from vulnsuite.workers import tasks


class _FakeEPSS:
    async def aclose(self) -> None:
        return None


class _FakeOrchestrator:
    def __init__(self, *args, **kwargs) -> None:
        pass

    async def run(self, asset, collector_calls, post_processors=None):
        results = [await call() for call in collector_calls]
        findings = [finding for result in results for finding in result.findings]
        errors = [error for result in results for error in result.errors]
        for processor in post_processors or []:
            findings = processor(findings)
        summary = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for finding in findings:
            if finding.risk_bucket in summary:
                summary[finding.risk_bucket] += 1
        return SimpleNamespace(summary=summary, persisted_count=len(findings), errors=errors)


def _scan_result(tool: str, module: Module) -> ScanResult:
    finding = Finding(
        tenant_id=uuid4(),
        asset_id=uuid4(),
        tool=tool,
        module=module,
        title=f"{tool}-{module.value}",
        severity=Severity.INFO,
        evidence=Evidence(raw={}),
        remediation="n/a",
        risk_bucket="P4",
    )
    return ScanResult(
        tool=tool,
        module=module,
        asset_id=uuid4(),
        started_at=tasks.datetime.now(tasks.timezone.utc),
        finished_at=tasks.datetime.now(tasks.timezone.utc),
        findings=[finding],
        errors=[],
    )


@pytest.fixture(autouse=True)
def patch_core(monkeypatch):
    async def _fake_build_default_provider(*args, **kwargs):
        return _FakeEPSS()

    monkeypatch.setattr(tasks, "build_default_provider", _fake_build_default_provider)
    monkeypatch.setattr(tasks, "Orchestrator", _FakeOrchestrator)


def test_validate_dast_targets_rejects_non_allowlisted(monkeypatch) -> None:
    monkeypatch.setattr(tasks.settings.api_security, "dast_allowlist", ["internal.example.com"])
    targets = tasks.ScanTargets(
        api_base_urls=["https://api.example.com"],
        dast_mode=DASTMode.BASELINE,
    )

    with pytest.raises(ValueError):
        tasks.validate_dast_targets(targets)


def test_scan_asset_offline_root_domains_returns_not_run(monkeypatch) -> None:
    monkeypatch.setattr(tasks.settings.scanning, "offline_mode", True)
    result = tasks.scan_asset.run(
        SimpleNamespace(retry=lambda **kwargs: None),
        tenant_id=str(uuid4()),
        asset_id=str(uuid4()),
        asset_name="public-root",
        asset_type=AssetType.DOMAIN.value,
        criticality=3,
        exposure=1.0,
        targets={"root_domains": ["example.com"], "dast_mode": "off"},
    )
    monkeypatch.setattr(tasks.settings.scanning, "offline_mode", False)
    assert any("offline mode disables ASM passive discovery" in error for error in result["errors"])


def test_scan_asset_routes_phase2_collectors(monkeypatch) -> None:
    monkeypatch.setattr(tasks.settings.api_security, "dast_allowlist", ["api.example.com"])
    invoked: list[str] = []

    class FakeCheckov:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def scan(self, paths, tenant_id, asset_id, frameworks=None, module=Module.IAC):
            invoked.append(f"checkov:{module.value}")
            return _scan_result("checkov", module)

    class FakeTrivyConfig:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def scan(self, paths, tenant_id, asset_id, module=Module.IAC):
            invoked.append(f"trivy-config:{module.value}")
            return _scan_result("trivy-config", module)

    class FakeKubescape:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def scan(self, tenant_id, asset_id, kube_context=None, kubeconfig_path=None):
            invoked.append("kubescape:kubernetes")
            return _scan_result("kubescape", Module.KUBERNETES)

    class FakeInventory:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def list_workload_images(self, kube_context=None, kubeconfig_path=None):
            return [WorkloadImageRef(cluster="c1", namespace="prod", kind="Deployment", name="api", image="ghcr.io/demo/api:1.0")]

    class FakeTrivy:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def scan(self, target, kind, tenant_id, asset_id):
            invoked.append(f"trivy:{kind}")
            return _scan_result("trivy", Module.CONTAINER if kind == "image" else Module.SUPPLY_CHAIN)

    monkeypatch.setattr(tasks, "CheckovCollector", FakeCheckov)
    monkeypatch.setattr(tasks, "TrivyConfigCollector", FakeTrivyConfig)
    monkeypatch.setattr(tasks, "KubescapeCollector", FakeKubescape)
    monkeypatch.setattr(tasks, "KubernetesInventoryCollector", FakeInventory)
    monkeypatch.setattr(tasks, "TrivyCollector", FakeTrivy)

    result = tasks.scan_asset.run(
        SimpleNamespace(retry=lambda **kwargs: None),
        tenant_id=str(uuid4()),
        asset_id=str(uuid4()),
        asset_name="cluster-1",
        asset_type=AssetType.KUBERNETES_CLUSTER.value,
        criticality=4,
        exposure=0.6,
        targets={
            "iac_paths": ["infra"],
            "api_specs": ["openapi.yaml"],
            "kube_context": "dev-cluster",
            "dast_mode": "off",
        },
    )

    assert result["persisted"] == 5
    assert "checkov:iac" in invoked
    assert "checkov:api_security" in invoked
    assert "trivy-config:iac" in invoked
    assert "kubescape:kubernetes" in invoked
    assert "trivy:image" in invoked
