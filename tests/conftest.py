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

    class Celery:
        """Enough of celery.Celery for workers/celery_app.py to import;
        `conf` is a plain dict so tests can read routes and beat schedule."""

        def __init__(self, *args, **kwargs):
            self.conf = {}

    celery_module.Celery = Celery
    sys.modules["celery"] = celery_module

try:
    import redis  # noqa: F401
except ImportError:  # worker modules import redis.asyncio at module load
    redis_module = types.ModuleType("redis")
    redis_asyncio = types.ModuleType("redis.asyncio")

    class _Redis:
        @classmethod
        def from_url(cls, url, **kwargs):
            return cls()

    redis_asyncio.Redis = _Redis
    redis_module.asyncio = redis_asyncio
    sys.modules["redis"] = redis_module
    sys.modules["redis.asyncio"] = redis_asyncio

from vulnsuite.core.schema import Evidence, Finding, Module, Severity


@pytest.fixture
def make_finding():
    def _make(module: Module, **kwargs) -> Finding:
        return Finding(
            tenant_id=kwargs.pop("tenant_id", uuid4()),
            asset_id=kwargs.pop("asset_id", uuid4()),
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
