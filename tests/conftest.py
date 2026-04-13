from __future__ import annotations

import sys
import types
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if "celery" not in sys.modules:
    celery_module = types.ModuleType("celery")

    def shared_task(*args, **kwargs):
        def decorator(func):
            func.run = func
            return func

        return decorator

    celery_module.shared_task = shared_task
    sys.modules["celery"] = celery_module

from vulnsuite.core.schema import Evidence, Finding, Module, Severity


@pytest.fixture
def make_finding():
    def _make(module: Module, **kwargs) -> Finding:
        return Finding(
            tenant_id=uuid4(),
            asset_id=uuid4(),
            tool=kwargs.pop("tool", "test-tool"),
            module=module,
            title=kwargs.pop("title", "finding"),
            severity=kwargs.pop("severity", Severity.MEDIUM),
            evidence=kwargs.pop("evidence", Evidence(raw={})),
            cve=kwargs.pop("cve", []),
            cwe=kwargs.pop("cwe", []),
            cvss_base=kwargs.pop("cvss_base", 5.0),
            epss=kwargs.pop("epss", 0.1),
            remediation=kwargs.pop("remediation", "fix it"),
            references=kwargs.pop("references", []),
            **kwargs,
        )

    return _make
