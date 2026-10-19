"""
VulnSuite - API audit trail

Every authenticated call under /api/ produces one append-only row in
`audit_events`: who (sub, email, roles, tenant), what (method, path,
handler-supplied detail), result (status, outcome), where from (client
IP), and correlation (request id, duration). Rows are tenant-isolated by
RLS and a database trigger rejects UPDATE/DELETE — see core/db.py.

The write happens after the response is built and never fails the
request: a security product that goes down when its audit table hiccups
is worse than one that logs the gap loudly. Unauthenticated denials
(401/403 with no principal) have no tenant to attach to, so they go to
the application log instead of the table.

Handlers add specifics with `audit_detail(request, asset_id=..., ...)`.
"""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from uuid import UUID, uuid4

from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("vulnsuite.audit")

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class AuditEvent(BaseModel):
    tenant_id: UUID
    occurred_at: datetime
    actor_sub: str
    actor_email: str | None = None
    actor_roles: list[str] = Field(default_factory=list)
    method: str
    path: str
    status_code: int
    outcome: str                      # success | denied | rejected | error
    client_ip: str | None = None
    request_id: str
    duration_ms: int
    detail: dict[str, Any] = Field(default_factory=dict)


def outcome_for(status_code: int) -> str:
    if status_code < 400:
        return "success"
    if status_code in (401, 403):
        return "denied"
    if status_code < 500:
        return "rejected"
    return "error"


def request_id_for(request: Request) -> str:
    """Honour a well-formed incoming X-Request-Id so events correlate with
    the caller's gateway logs; otherwise mint one."""
    incoming = request.headers.get("x-request-id", "")
    return incoming if _REQUEST_ID.match(incoming) else uuid4().hex


def audit_detail(request: Request, **fields: Any) -> None:
    """Attach handler-level specifics (asset_id, task_id, targets...) to
    the event the middleware will write for this request."""
    current = getattr(request.state, "audit", None) or {}
    request.state.audit = {**current, **fields}


def build_event(
    request: Request,
    principal: Any,
    status_code: int,
    request_id: str,
    duration_ms: int,
) -> AuditEvent:
    return AuditEvent(
        tenant_id=principal.tenant_id,
        occurred_at=datetime.now(timezone.utc),
        actor_sub=principal.sub,
        actor_email=getattr(principal, "email", None),
        actor_roles=sorted(principal.roles),
        method=request.method,
        path=request.url.path,
        status_code=status_code,
        outcome=outcome_for(status_code),
        client_ip=request.client.host if request.client else None,
        request_id=request_id,
        duration_ms=duration_ms,
        detail=dict(getattr(request.state, "audit", None) or {}),
    )


async def record_audit_event(event: AuditEvent) -> None:
    from ..core.db import AuditEventRow, tenant_session

    async with tenant_session(event.tenant_id) as session:
        session.add(AuditEventRow(**event.model_dump()))
        await session.commit()


Recorder = Callable[[AuditEvent], Awaitable[None]]


class AuditMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        record: Recorder = record_audit_event,
        include_reads: bool = True,
        path_prefix: str = "/api/",
    ) -> None:
        super().__init__(app)
        self._record = record
        self._include_reads = include_reads
        self._prefix = path_prefix

    async def dispatch(self, request: Request, call_next) -> Response:
        if not request.url.path.startswith(self._prefix):
            return await call_next(request)

        request_id = request_id_for(request)
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # Unhandled exception: record it as a 500 if we know who called.
            await self._write(request, 500, request_id, started)
            raise
        response.headers["X-Request-Id"] = request_id
        await self._write(request, response.status_code, request_id, started)
        return response

    async def _write(self, request: Request, status_code: int, request_id: str, started: float) -> None:
        principal = getattr(request.state, "principal", None)
        if principal is None:
            if status_code in (401, 403):
                logger.warning(
                    "unauthenticated %s %s denied (%d) from %s request_id=%s",
                    request.method, request.url.path, status_code,
                    request.client.host if request.client else "?", request_id,
                )
            return
        if request.method == "GET" and not self._include_reads:
            return
        duration_ms = int((time.perf_counter() - started) * 1000)
        event = build_event(request, principal, status_code, request_id, duration_ms)
        try:
            await self._record(event)
        except Exception:  # noqa: BLE001
            logger.exception(
                "AUDIT WRITE FAILED: %s %s by %s tenant=%s status=%d request_id=%s",
                event.method, event.path, event.actor_sub, event.tenant_id,
                event.status_code, event.request_id,
            )
