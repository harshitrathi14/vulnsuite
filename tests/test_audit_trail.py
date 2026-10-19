"""API audit trail: every authenticated /api/ call yields one event with
actor, tenant, method, path, outcome and handler detail; audit failures
never fail the request; unauthenticated denials are logged, not stored."""
from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from vulnsuite.api.audit import AuditEvent, AuditMiddleware, audit_detail, outcome_for
from vulnsuite.core.db import RLS_DDL

TENANT = UUID("00000000-0000-0000-0000-000000000001")
PRINCIPAL = SimpleNamespace(tenant_id=TENANT, sub="user-42", email="a@example.com", roles=frozenset({"analyst", "admin"}))


def _app(recorder, include_reads=True):
    app = FastAPI()
    app.add_middleware(AuditMiddleware, record=recorder, include_reads=include_reads)

    async def principal(request: Request):
        request.state.principal = PRINCIPAL     # what api/auth.py::get_principal does
        return PRINCIPAL

    @app.post("/api/v1/things", status_code=201)
    async def create(request: Request, p=Depends(principal)):
        audit_detail(request, thing_id="t-1")
        audit_detail(request, extra=True)
        return {"ok": True}

    @app.get("/api/v1/things")
    async def read(p=Depends(principal)):
        return []

    @app.get("/api/v1/forbidden")
    async def forbidden(p=Depends(principal)):
        raise HTTPException(403, "insufficient application role")

    @app.get("/api/v1/anon")
    async def anon():
        raise HTTPException(401, "missing bearer token")

    @app.get("/api/v1/boom")
    async def boom(p=Depends(principal)):
        raise RuntimeError("boom")

    @app.get("/healthz")
    async def health():
        return {"ok": True}

    return app


class _Recorder:
    def __init__(self, fail=False):
        self.events: list[AuditEvent] = []
        self.fail = fail

    async def __call__(self, event: AuditEvent) -> None:
        if self.fail:
            raise RuntimeError("db down")
        self.events.append(event)


def test_outcome_mapping() -> None:
    assert [outcome_for(s) for s in (201, 401, 403, 404, 422, 500)] == [
        "success", "denied", "denied", "rejected", "rejected", "error",
    ]


def test_mutating_call_is_recorded_with_actor_and_detail() -> None:
    rec = _Recorder()
    client = TestClient(_app(rec))
    resp = client.post("/api/v1/things", headers={"X-Request-Id": "gw-abc.123"})
    assert resp.status_code == 201
    assert resp.headers["X-Request-Id"] == "gw-abc.123"
    (event,) = rec.events
    assert event.tenant_id == TENANT
    assert event.actor_sub == "user-42" and event.actor_email == "a@example.com"
    assert event.actor_roles == ["admin", "analyst"]
    assert (event.method, event.path, event.status_code, event.outcome) == ("POST", "/api/v1/things", 201, "success")
    assert event.request_id == "gw-abc.123"
    assert event.detail == {"thing_id": "t-1", "extra": True}
    assert event.client_ip is not None and event.duration_ms >= 0


def test_malformed_incoming_request_id_is_replaced() -> None:
    rec = _Recorder()
    resp = TestClient(_app(rec)).post("/api/v1/things", headers={"X-Request-Id": "bad id\nwith newline"})
    assert resp.headers["X-Request-Id"] != "bad id\nwith newline"
    assert len(resp.headers["X-Request-Id"]) == 32


def test_denied_call_with_principal_is_recorded_as_denied() -> None:
    rec = _Recorder()
    assert TestClient(_app(rec)).get("/api/v1/forbidden").status_code == 403
    assert rec.events[0].outcome == "denied" and rec.events[0].status_code == 403


def test_unauthenticated_denial_and_healthz_are_not_stored() -> None:
    rec = _Recorder()
    client = TestClient(_app(rec))
    assert client.get("/api/v1/anon").status_code == 401
    assert client.get("/healthz").status_code == 200
    assert rec.events == []


def test_reads_can_be_excluded() -> None:
    rec = _Recorder()
    client = TestClient(_app(rec, include_reads=False))
    client.get("/api/v1/things")
    client.post("/api/v1/things")
    assert [e.method for e in rec.events] == ["POST"]


def test_audit_write_failure_does_not_fail_the_request(caplog) -> None:
    rec = _Recorder(fail=True)
    with caplog.at_level("ERROR", logger="vulnsuite.audit"):
        resp = TestClient(_app(rec)).post("/api/v1/things")
    assert resp.status_code == 201
    assert "AUDIT WRITE FAILED" in caplog.text and "user-42" in caplog.text


def test_unhandled_exception_is_recorded_as_error() -> None:
    rec = _Recorder()
    resp = TestClient(_app(rec), raise_server_exceptions=False).get("/api/v1/boom")
    assert resp.status_code == 500
    assert rec.events[0].outcome == "error" and rec.events[0].status_code == 500


def test_audit_table_is_append_only_in_ddl() -> None:
    ddl = "\n".join(RLS_DDL)
    assert "BEFORE UPDATE OR DELETE ON audit_events" in ddl
    assert "ALTER TABLE audit_events FORCE ROW LEVEL SECURITY" in ddl
