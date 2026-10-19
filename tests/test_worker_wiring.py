"""Queue routing and the beat schedule must line up with what the deployed
worker actually consumes and what the scheduled task actually accepts.
Two Compose-level bugs motivated this: AI enrichment was routed to a queue
no worker listened on, and beat called a task without its required tenant."""
from __future__ import annotations

import re
import types
from pathlib import Path
from uuid import uuid4

import pytest

from vulnsuite.workers import tasks
from vulnsuite.workers.celery_app import celery_app

ROOT = Path(__file__).resolve().parents[1] / "vulnsuite"


def _conf() -> dict:
    return dict(celery_app.conf)


def _compose_worker_queues() -> set[str]:
    yaml = pytest.importorskip("yaml")
    compose = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text())
    command = compose["services"]["worker"]["command"]
    match = re.search(r"--queues=([\w.,-]+)", command)
    assert match, "worker command has no --queues"
    return set(match.group(1).split(","))


def test_every_routed_queue_is_consumed_by_the_compose_worker() -> None:
    routed = {route["queue"] for route in _conf()["task_routes"].values()}
    routed.add(_conf()["task_default_queue"])
    missing = routed - _compose_worker_queues()
    assert not missing, f"queues routed to but never consumed: {sorted(missing)}"


def test_beat_schedules_only_tasks_that_need_no_arguments() -> None:
    for name, entry in _conf()["beat_schedule"].items():
        assert "args" not in entry and "kwargs" not in entry
        task_name = entry["task"]
        func = next(
            (f for f in vars(tasks).values() if getattr(f, "__name__", "") == task_name.rsplit(".", 1)[1]),
            None,
        )
        assert func is not None, f"{name}: {task_name} is not defined in workers/tasks.py"
        assert func.__code__.co_argcount == 0, f"{name}: {task_name} requires arguments beat cannot supply"


def test_scheduled_discovery_fans_out_per_tenant(monkeypatch) -> None:
    good = [str(uuid4()), str(uuid4())]
    queued: list[str] = []
    monkeypatch.setattr(
        tasks.settings.scanning, "scheduled_discovery_tenants", [good[0], "not-a-uuid", f" {good[1]} "],
    )
    monkeypatch.setattr(
        tasks, "discover_assets", types.SimpleNamespace(delay=lambda tenant_id: queued.append(tenant_id)),
    )
    result = tasks.scheduled_discovery()
    assert queued == good
    assert result == {"queued": good, "skipped": ["not-a-uuid"]}


def test_scheduled_discovery_with_no_tenants_warns_and_queues_nothing(monkeypatch, caplog) -> None:
    monkeypatch.setattr(tasks.settings.scanning, "scheduled_discovery_tenants", [])
    monkeypatch.setattr(tasks, "discover_assets", types.SimpleNamespace(delay=lambda **kw: pytest.fail("queued")))
    with caplog.at_level("WARNING"):
        assert tasks.scheduled_discovery() == {"queued": [], "skipped": []}
    assert "no tenants configured" in caplog.text
