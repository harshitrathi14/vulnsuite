"""Separate fail-closed API: python -m uvicorn ...service:create_app --factory.

Static configuration is read at startup. Deploy one instance/database per organisation.
Agent credentials bind to a host; verified operator identities enforce role-based
access. Enrollment, policies and credential changes persist in the operational store.
"""
import hmac
import json
import os
import time
from uuid import UUID
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import ValidationError

from .models import Batch, BlockRequest, Receipt
from .response import allowed_ip
from .store import Store
from .operations_api import mount_operations


def create_app(config: dict | None = None, store: Store | None = None) -> FastAPI:
    cfg = config if config is not None else json.loads(
        Path(os.environ["VULNSUITE_PROTECTION_CONFIG"]).read_text())
    hosts = cfg.get("hosts", {})
    operators = dict(cfg.get("operators", {}))
    if cfg.get("operator_token"):
        operators["bootstrap-operator"] = {"token": cfg["operator_token"], "roles": ["admin"]}
    verifier = None
    if cfg.get("operator_auth"):
        from ..api.auth import JWTVerifier
        from ..core.config import AuthSettings
        verifier = JWTVerifier(AuthSettings(**cfg["operator_auth"]))
        UUID(cfg["organisation_id"])
        # SSO mode has no fallback to a shared bootstrap credential.
        operators = {}
    if not operators and verifier is None:
        raise ValueError("operator identity configuration required")
    keys = [op["token"] for op in operators.values()] + [host["token"] for host in hosts.values()]
    if any(len(key) < 32 or key.startswith("REPLACE_") for key in keys) or len(set(keys)) != len(keys):
        raise ValueError("distinct operator and per-host tokens of at least 32 characters required")
    for op in operators.values():
        if not op.get("roles") or set(op["roles"]) - {"admin", "analyst", "viewer", "auditor"}:
            raise ValueError("unknown operator roles")
    # Validate policy at startup, including when enforcement is disabled.
    import ipaddress
    host_addresses = {}
    for name, host in hosts.items():
        for address in host.get("addresses", []):
            address = str(ipaddress.ip_address(address))
            if address in host_addresses:
                raise ValueError("each host address must have one enrolled owner")
            host_addresses[address] = name
        for net in host.get("protected_networks", []) + host.get("permitted_networks", []):
            ipaddress.ip_network(net)
        if host.get("allow_response") and not host.get("protected_networks"):
            raise ValueError("response requires explicit management/protected networks")
    if cfg.get("assessment_api") and cfg.get("organisation_id"):
        if UUID(cfg["assessment_api"]["tenant_id"]) != UUID(cfg["organisation_id"]):
            raise ValueError("assessment API must use the same organisation tenant")
    dbstore = store or Store(cfg["database"], host_addresses, int(cfg.get("retention_days", 7)))
    dbstore.seed_hosts(hosts)
    dbstore.connector_names = list(cfg.get("integrations", {}))
    dbstore.response_policies = dict(cfg.get("response", {}).get("hosts", {}))
    dbstore.host_addresses = {address: name for name, policy in dbstore.host_policies().items()
                             for address in policy.get("addresses", [])}
    app = FastAPI(title="VulnSuite Server Protection", version="0.4.0",
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def private_responses(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def token(authorization: str | None):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing credentials")
        return authorization[7:]

    def agent(authorization: str | None = Header(default=None)):
        host = dbstore.authenticate_agent(token(authorization))
        if host is None:
            raise HTTPException(401, "invalid or revoked agent credentials")
        return host

    async def identity(authorization: str | None = Header(default=None)):
        value = token(authorization)
        if verifier is not None:
            from ..api.auth import AuthenticationError
            try:
                principal = await verifier.verify(value, expected_tenant=cfg["organisation_id"])
            except AuthenticationError:
                raise HTTPException(401, "invalid operator token") from None
            return {"sub": principal.sub, "roles": list(principal.roles)}
        for name, op in operators.items():
            if hmac.compare_digest(value.encode(), op["token"].encode()):
                return {"sub": name, "roles": op["roles"]}
        raise HTTPException(403, "operator credentials required")

    def require_operator(*allowed):
        async def check(principal=Depends(identity)):
            if not set(principal["roles"]) & set(allowed):
                raise HTTPException(403, "operator role does not permit this action")
            return principal
        return check

    operator = require_operator("admin", "analyst", "viewer", "auditor")
    writer = require_operator("admin", "analyst")
    administrator = require_operator("admin")

    async def body(request, model):
        payload = bytearray()
        async for chunk in request.stream():
            payload.extend(chunk)
            if len(payload) > 262144:
                raise HTTPException(413, "request exceeds 256 KiB")
        try:
            return model.model_validate_json(bytes(payload))
        except ValidationError:
            raise HTTPException(422, "invalid request body") from None

    @app.get("/v1/me")
    async def current_operator(actor=Depends(operator)):
        return actor

    @app.post("/v1/events")
    async def ingest(request: Request, host=Depends(agent)):
        batch = await body(request, Batch)
        try:
            alerts = dbstore.ingest(host, batch.events, time.time())
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return {"accepted": len(batch.events), "alerts": alerts,
                "archived": sum(e.occurred_at.timestamp() < time.time() - 300 for e in batch.events)}

    @app.get("/v1/alerts", dependencies=[Depends(operator)])
    def alerts():
        return {"alerts": dbstore.list_alerts()}

    @app.get("/v1/hosts", dependencies=[Depends(operator)])
    def health():
        now = time.time()
        with dbstore.connect() as db:
            hosts_result = []
            for row in db.execute("SELECT host,status,metadata,last_seen,policy FROM enrolled_hosts ORDER BY host"):
                policy = json.loads(row["policy"])
                metadata = json.loads(row["metadata"])
                hosts_result.append({"host": row["host"], "status": row["status"],
                    "last_seen": row["last_seen"], "stale": not row["last_seen"] or now-row["last_seen"] > 120,
                    "metadata": metadata, "desired_version": policy.get("desired_version"),
                    "version_drift": bool(policy.get("desired_version") and metadata.get("agent_version") != policy["desired_version"]),
                    "sensors": [{**dict(s), "stale": now-s["received"]>120} for s in db.execute(
                        "SELECT sensor,status,detail,received FROM sensors WHERE host=?", (row["host"],))]})
        return {"hosts": hosts_result}

    @app.post("/v1/blocks", status_code=201)
    async def queue_block(request: Request, actor=Depends(writer)):
        payload = await body(request, BlockRequest)
        with dbstore.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            alert = db.execute("SELECT * FROM alerts WHERE id=?", (payload.alert_id,)).fetchone()
            if not alert:
                raise HTTPException(404, "alert not found")
            policy = dbstore.host_policies().get(alert["host"], {})
            if not policy.get("allow_response", False):
                raise HTTPException(403, "host response disabled")
            if time.time() - alert["created"] > 300 or not alert["ip"]:
                raise HTTPException(409, "requires a recent alert with a source address")
            try:
                ip = allowed_ip(alert["ip"], policy.get("protected_networks", []),
                                policy.get("permitted_networks", []))
            except ValueError:
                raise HTTPException(403, "source address denied by response policy") from None
            previous = db.execute("SELECT id FROM commands WHERE alert_id=?", (payload.alert_id,)).fetchone()
            if previous:
                raise HTTPException(409, "response already requested for this alert")
            cursor = db.execute(
                "INSERT INTO commands(host,alert_id,ip,duration,created,status,reason) "
                "VALUES(?,?,?,?,?,'pending',?)",
                (alert["host"], payload.alert_id, ip, payload.duration_seconds,
                 time.time(), payload.reason),
            )
            dbstore.audit(db, "block_requested", actor["sub"],
                          json.dumps({"command_id": cursor.lastrowid, "reason": payload.reason}))
            return {"command_id": cursor.lastrowid, "status": "pending"}

    @app.get("/v1/commands")
    def commands(host=Depends(agent)):
        with dbstore.connect() as db:
            return {"commands": [dict(row) for row in db.execute(
                "SELECT id,ip,duration,created FROM commands WHERE host=? "
                "AND status='pending' AND created>=? ORDER BY id LIMIT 20", (host, time.time() - 300))]}

    @app.get("/v1/responses", dependencies=[Depends(operator)])
    def responses():
        with dbstore.connect() as db:
            return {"responses": [dict(r) for r in db.execute(
                "SELECT * FROM commands ORDER BY id DESC LIMIT 100")]}

    @app.get("/v1/audit", dependencies=[Depends(operator)])
    def audit():
        with dbstore.connect() as db:
            return {"audit": [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100")]}

    @app.post("/v1/commands/{command_id}/receipt")
    async def receipt(command_id: int, request: Request, host=Depends(agent)):
        result = await body(request, Receipt)
        if (result.status == "applied") != (result.detail == "blocked"):
            raise HTTPException(422, "inconsistent receipt")
        with dbstore.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM commands WHERE id=? AND host=?", (command_id, host)).fetchone()
            if not row:
                raise HTTPException(404, "command not found")
            if row["status"] in ("applied", "failed"):
                if row["status"] != result.status or row["detail"] != result.detail:
                    raise HTTPException(409, "receipt already recorded")
                return {"status": row["status"]}
            if row["status"] != "pending":
                raise HTTPException(409, "command is no longer pending")
            db.execute("UPDATE commands SET status=?,detail=? WHERE id=?",
                       (result.status, result.detail, command_id))
            dbstore.audit(db, "block_receipt", host,
                          json.dumps({"command_id": command_id, **result.model_dump()}))
        return {"status": result.status}

    mount_operations(app, dbstore, cfg, operator, writer, administrator, agent, body)
    return app
