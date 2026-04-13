from __future__ import annotations

import pytest

from vulnsuite.core.schema import DASTMode, Module, ScanTargets


def test_scan_targets_iac_paths_are_deduplicated() -> None:
    targets = ScanTargets(
        iac_paths=["infra", "infra"],
        terraform_plan_paths=["plan.json"],
        helm_chart_paths=["charts/app"],
        k8s_manifest_paths=["k8s/deploy.yaml"],
        api_specs=["openapi.yaml"],
    )

    assert targets.iac_scan_paths() == [
        "infra",
        "plan.json",
        "charts/app",
        "k8s/deploy.yaml",
        "openapi.yaml",
    ]


def test_scan_targets_requires_api_targets_for_dast() -> None:
    with pytest.raises(ValueError):
        ScanTargets(dast_mode=DASTMode.BASELINE)


def test_new_phase2_modules_exist() -> None:
    assert Module.IAC.value == "iac"
    assert Module.KUBERNETES.value == "kubernetes"
    assert Module.ASM.value == "asm"
    assert Module.API_SECURITY.value == "api_security"
    assert Module.SUPPLY_CHAIN.value == "supply_chain"
