"""VulnSuite - FastAPI application (routes + auth inline)."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from ..ai.client import AIEnrichmentError, ai_active
from ..core.cloud_accounts import (
    CloudAccessError,
    CloudBinding,
    CloudProvider,
    authorize,
    load_cloud_bindings,
)
from ..core.config import get_settings
from ..core.db import (
    AssetRow,
    AuditEventRow,
    CloudAccountRow,
    FindingRow,
    TenantScopeRow,
    init_db,
    tenant_session,
)
from ..core.schema import Asset, AssetType, ExposureFactor, ScanTargets
from ..core.scopes import (
    ScopeError,
    TenantScope,
    authorize_root_domains,
    classify_host,
    load_scopes,
    split_host_port,
)
from ..core.triage import TriageRequest, apply_triage
from .audit import AuditMiddleware, audit_detail
from ..workers.tasks import (
    discover_assets,
    discover_aws_assets,
    discover_domains,
    discover_gcp_assets,
    discover_kubernetes_clusters,
    generate_report,
    scan_asset,
    validate_dast_targets,
)
from .auth import Principal, get_principal, require_role

settings = get_settings()
app = FastAPI(
    title="VulnSuite API",
    version="0.4.0",
    description="Cybersecurity vulnerability analysis suite (BFSI-tuned)",
)

if settings.api.cors_origins:
    # Explicit origins only (VULNSUITE_API_CORS_ORIGINS). The old default,
    # "*" with credentials, is rejected by browsers and invites CSRF.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Tenant-Id", "X-Request-Id"],
        expose_headers=["X-Request-Id"],
    )
if settings.audit.enabled:
    # Inner to CORS so preflight OPTIONS is not audited; see api/audit.py.
    app.add_middleware(AuditMiddleware, include_reads=settings.audit.include_reads)

class AssetCreate(BaseModel):
    name: str
    asset_type: AssetType
    criticality: int
    exposure: ExposureFactor = ExposureFactor.INTERNAL
    owner: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    asset_id: UUID
    targets: ScanTargets


class AWSDiscoveryRequest(BaseModel):
    account_ids: list[str] = Field(default_factory=list)


class GCPDiscoveryRequest(BaseModel):
    project_ids: list[str] = Field(default_factory=list)


class DomainDiscoveryRequest(BaseModel):
    root_domains: list[str] = Field(default_factory=list)


class KubernetesDiscoveryRequest(BaseModel):
    kubeconfig_path: str | None = None


class CopilotRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


class FindingResponse(BaseModel):
    finding_id: UUID
    title: str
    severity: str
    risk_score: float
    risk_bucket: str | None
    tool: str
    module: str
    cve: list[str]
    status: str
    # Lifecycle (cross-scan)
    is_new: bool = False
    risk_escalated_by: list[str] = Field(default_factory=list)
    # AI enrichment (Claude Fable 5) — advisory signals, None when not enriched
    ai_fp_likelihood: float | None = None
    ai_actively_exploited: bool = False
    ai_kev_listed: bool = False
    ai_suggested_bucket: str | None = None
    ai_attack_chain_count: int = 0
    # Analyst triage (core/triage.py)
    owner: str | None = None
    triage_note: str = ""
    triaged_by: str | None = None
    triaged_at: datetime | None = None
    accepted_until: datetime | None = None


def _ai_fields(evidence: dict | None) -> dict:
    raw = (evidence or {}).get("raw") or {}
    intel = raw.get("ai_threat_intel") or {}
    return {
        "risk_escalated_by": list(raw.get("risk_escalated_by") or []),
        "ai_fp_likelihood": (raw.get("ai_triage") or {}).get("fp_likelihood"),
        "ai_actively_exploited": bool(intel.get("actively_exploited")),
        "ai_kev_listed": bool(intel.get("kev_listed")) or bool(raw.get("kev_listed")),
        "ai_suggested_bucket": raw.get("ai_suggested_bucket"),
        "ai_attack_chain_count": len(raw.get("ai_attack_chains") or []),
    }


def _finding_response(row) -> "FindingResponse":
    return FindingResponse(
        finding_id=row.finding_id,
        title=row.title,
        severity=row.severity,
        risk_score=row.risk_score,
        risk_bucket=row.risk_bucket,
        tool=row.tool,
        module=row.module,
        cve=list(row.cve or []),
        status=row.status,
        is_new=bool(getattr(row, "is_new", False)),
        owner=getattr(row, "owner", None),
        triage_note=getattr(row, "triage_note", None) or "",
        triaged_by=getattr(row, "triaged_by", None),
        triaged_at=getattr(row, "triaged_at", None),
        accepted_until=getattr(row, "accepted_until", None),
        **_ai_fields(row.evidence),
    )


@app.on_event("startup")
async def _startup() -> None:
    issues = settings.validate_production()
    if issues:
        raise RuntimeError(f"config issues: {issues}")
    await init_db()


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/api/v1/assets", status_code=201)
async def create_asset(
    payload: AssetCreate,
    request: Request,
    p: Principal = Depends(require_role("admin", "analyst")),
) -> dict:
    asset = Asset(tenant_id=p.tenant_id, **payload.model_dump())
    audit_detail(request, asset_id=str(asset.asset_id), name=asset.name)
    async with tenant_session(p.tenant_id) as session:
        session.add(
            AssetRow(
                asset_id=asset.asset_id,
                tenant_id=asset.tenant_id,
                name=asset.name,
                asset_type=asset.asset_type if isinstance(asset.asset_type, str) else asset.asset_type.value,
                criticality=asset.criticality,
                exposure=float(asset.exposure),
                owner=asset.owner,
                tags=asset.tags,
                created_at=asset.created_at,
            )
        )
        await session.commit()
    return {"asset_id": str(asset.asset_id)}


@app.get("/api/v1/assets")
async def list_assets(
    p: Principal = Depends(get_principal),
    limit: int = 100,
) -> list[dict]:
    async with tenant_session(p.tenant_id) as session:
        result = await session.execute(select(AssetRow).limit(limit))
        return [
            {
                "asset_id": str(row.asset_id),
                "name": row.name,
                "asset_type": row.asset_type,
                "criticality": row.criticality,
                "exposure": row.exposure,
                "tags": row.tags,
            }
            for row in result.scalars()
        ]


@app.post("/api/v1/scans", status_code=202)
async def trigger_scan(
    req: ScanRequest,
    request: Request,
    p: Principal = Depends(require_role("admin", "analyst")),
) -> dict:
    if not req.targets.has_any():
        raise HTTPException(status_code=400, detail="no targets configured")
    try:
        validate_dast_targets(req.targets)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await _require_cloud_bindings(p.tenant_id, req.targets)
    await _require_scopes(p.tenant_id, req.targets)
    audit_detail(
        request,
        asset_id=str(req.asset_id),
        targets={k: v for k, v in req.targets.model_dump(mode="json").items() if v},
    )

    async with tenant_session(p.tenant_id) as session:
        row = (
            await session.execute(select(AssetRow).where(AssetRow.asset_id == req.asset_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="asset not found")
        task = scan_asset.delay(
            tenant_id=str(p.tenant_id),
            asset_id=str(row.asset_id),
            asset_name=row.name,
            asset_type=row.asset_type,
            criticality=row.criticality,
            exposure=row.exposure,
            targets=req.targets.model_dump(mode="json"),
        )
    audit_detail(request, task_id=task.id)
    return {"task_id": task.id, "status": "queued"}


async def _authorize_cloud(tenant_id: UUID, provider: CloudProvider, requested: list[str] | None) -> None:
    """403 unless every requested account is bound to the caller's tenant.
    The worker repeats this check; a bypassed API is still caught there."""
    try:
        authorize(await load_cloud_bindings(tenant_id, provider), provider, requested)
    except CloudAccessError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


async def _require_cloud_bindings(tenant_id: UUID, targets: ScanTargets) -> None:
    if targets.azure:
        await _authorize_cloud(tenant_id, CloudProvider.AZURE, None)
    if targets.aws_accounts:
        await _authorize_cloud(tenant_id, CloudProvider.AWS, list(targets.aws_accounts))
    if targets.gcp_projects:
        await _authorize_cloud(tenant_id, CloudProvider.GCP, list(targets.gcp_projects))


async def _require_scopes(tenant_id: UUID, targets: ScanTargets) -> None:
    """403 unless every public network target sits inside a tenant scope.
    The worker repeats this check (workers/tasks.py::scan_asset)."""
    if not (targets.host or targets.tls_endpoint or targets.root_domains):
        return
    scopes = await load_scopes(tenant_id)
    try:
        if targets.host:
            await classify_host(targets.host, scopes)
        if targets.tls_endpoint:
            await classify_host(split_host_port(targets.tls_endpoint), scopes)
        if targets.root_domains:
            authorize_root_domains(targets.root_domains, scopes)
    except ScopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/v1/discover/azure", status_code=202)
async def trigger_azure_discovery(
    request: Request,
    p: Principal = Depends(require_role("admin")),
) -> dict:
    await _authorize_cloud(p.tenant_id, CloudProvider.AZURE, None)
    task = discover_assets.delay(tenant_id=str(p.tenant_id))
    audit_detail(request, task_id=task.id, provider="azure")
    return {"task_id": task.id, "status": "queued"}


@app.post("/api/v1/discover/aws", status_code=202)
async def trigger_aws_discovery(
    payload: AWSDiscoveryRequest,
    request: Request,
    p: Principal = Depends(require_role("admin")),
) -> dict:
    await _authorize_cloud(p.tenant_id, CloudProvider.AWS, payload.account_ids)
    task = discover_aws_assets.delay(tenant_id=str(p.tenant_id), account_ids=payload.account_ids)
    audit_detail(request, task_id=task.id, provider="aws", account_ids=payload.account_ids)
    return {"task_id": task.id, "status": "queued"}


@app.post("/api/v1/discover/gcp", status_code=202)
async def trigger_gcp_discovery(
    payload: GCPDiscoveryRequest,
    request: Request,
    p: Principal = Depends(require_role("admin")),
) -> dict:
    await _authorize_cloud(p.tenant_id, CloudProvider.GCP, payload.project_ids)
    task = discover_gcp_assets.delay(tenant_id=str(p.tenant_id), project_ids=payload.project_ids)
    audit_detail(request, task_id=task.id, provider="gcp", project_ids=payload.project_ids)
    return {"task_id": task.id, "status": "queued"}


# ---------- tenant cloud account bindings (admin) ----------

@app.post("/api/v1/cloud-accounts", status_code=201)
async def create_cloud_account(
    payload: CloudBinding,
    request: Request,
    p: Principal = Depends(require_role("admin")),
) -> dict:
    """Bind a cloud account to the caller's tenant. `credentials` holds
    references only (role ARN, SA file path, env prefix); the model rejects
    anything that looks like a secret."""
    row = CloudAccountRow(
        tenant_id=p.tenant_id,
        provider=payload.provider,
        account_id=payload.account_id,
        display_name=payload.display_name,
        credentials=dict(payload.credentials),
        created_at=datetime.now(timezone.utc),
    )
    async with tenant_session(p.tenant_id) as session:
        session.add(row)
        try:
            await session.commit()
        except IntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail=f"{payload.provider} account {payload.account_id} is already bound",
            ) from exc
    audit_detail(request, binding_id=str(row.id), provider=payload.provider, account_id=payload.account_id)
    return {"id": str(row.id)}


@app.get("/api/v1/cloud-accounts")
async def list_cloud_accounts(
    p: Principal = Depends(require_role("admin", "analyst", "auditor")),
) -> list[dict]:
    async with tenant_session(p.tenant_id) as session:
        rows = (await session.execute(select(CloudAccountRow))).scalars()
        return [
            {
                "id": str(row.id),
                "provider": row.provider,
                "account_id": row.account_id,
                "display_name": row.display_name,
                "credentials": row.credentials,   # references only, never secrets
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]


@app.delete("/api/v1/cloud-accounts/{binding_id}", status_code=204)
async def delete_cloud_account(
    binding_id: UUID,
    request: Request,
    p: Principal = Depends(require_role("admin")),
) -> None:
    async with tenant_session(p.tenant_id) as session:
        row = (
            await session.execute(select(CloudAccountRow).where(CloudAccountRow.id == binding_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="cloud account binding not found")
        audit_detail(request, binding_id=str(row.id), provider=row.provider, account_id=row.account_id)
        await session.delete(row)
        await session.commit()


# ---------- tenant target scopes (admin) ----------

@app.post("/api/v1/scopes", status_code=201)
async def create_scope(
    payload: TenantScope,
    request: Request,
    p: Principal = Depends(require_role("admin")),
) -> dict:
    """Authorise a domain (and its subdomains) or a public network range
    for this tenant. Private address space never needs a scope."""
    row = TenantScopeRow(
        tenant_id=p.tenant_id,
        kind=payload.kind,
        value=payload.value,
        note=payload.note,
        created_at=datetime.now(timezone.utc),
    )
    async with tenant_session(p.tenant_id) as session:
        session.add(row)
        try:
            await session.commit()
        except IntegrityError as exc:
            raise HTTPException(
                status_code=409, detail=f"{payload.kind} scope {payload.value} already exists",
            ) from exc
    audit_detail(request, scope_id=str(row.id), kind=payload.kind, value=payload.value)
    return {"id": str(row.id), "kind": payload.kind, "value": payload.value}


@app.get("/api/v1/scopes")
async def list_scopes(
    p: Principal = Depends(require_role("admin", "analyst", "auditor")),
) -> list[dict]:
    async with tenant_session(p.tenant_id) as session:
        rows = (await session.execute(select(TenantScopeRow))).scalars()
        return [
            {
                "id": str(row.id),
                "kind": row.kind,
                "value": row.value,
                "note": row.note,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]


@app.delete("/api/v1/scopes/{scope_id}", status_code=204)
async def delete_scope(
    scope_id: UUID,
    request: Request,
    p: Principal = Depends(require_role("admin")),
) -> None:
    async with tenant_session(p.tenant_id) as session:
        row = (
            await session.execute(select(TenantScopeRow).where(TenantScopeRow.id == scope_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="scope not found")
        audit_detail(request, scope_id=str(row.id), kind=row.kind, value=row.value)
        await session.delete(row)
        await session.commit()


# ---------- audit trail (read-only) ----------

@app.get("/api/v1/audit-events")
async def list_audit_events(
    p: Principal = Depends(require_role("admin", "auditor")),
    limit: int = Query(100, ge=1, le=500),
    outcome: str | None = Query(None, pattern="^(success|denied|rejected|error)$"),
    actor: str | None = Query(None, max_length=256),
) -> list[dict]:
    stmt = select(AuditEventRow).order_by(AuditEventRow.occurred_at.desc()).limit(limit)
    if outcome:
        stmt = stmt.where(AuditEventRow.outcome == outcome)
    if actor:
        stmt = stmt.where(AuditEventRow.actor_sub == actor)
    async with tenant_session(p.tenant_id) as session:
        rows = (await session.execute(stmt)).scalars()
        return [
            {
                "id": str(row.id),
                "occurred_at": row.occurred_at.isoformat(),
                "actor_sub": row.actor_sub,
                "actor_email": row.actor_email,
                "actor_roles": list(row.actor_roles or []),
                "method": row.method,
                "path": row.path,
                "status_code": row.status_code,
                "outcome": row.outcome,
                "client_ip": row.client_ip,
                "request_id": row.request_id,
                "duration_ms": row.duration_ms,
                "detail": row.detail or {},
            }
            for row in rows
        ]


@app.post("/api/v1/discover/domains", status_code=202)
async def trigger_domain_discovery(
    payload: DomainDiscoveryRequest,
    request: Request,
    p: Principal = Depends(require_role("admin")),
) -> dict:
    try:
        roots = authorize_root_domains(payload.root_domains, await load_scopes(p.tenant_id))
    except ScopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    task = discover_domains.delay(tenant_id=str(p.tenant_id), root_domains=roots)
    audit_detail(request, task_id=task.id, root_domains=roots)
    return {"task_id": task.id, "status": "queued"}


@app.post("/api/v1/discover/kubernetes", status_code=202)
async def trigger_kubernetes_discovery(
    payload: KubernetesDiscoveryRequest,
    request: Request,
    p: Principal = Depends(require_role("admin")),
) -> dict:
    task = discover_kubernetes_clusters.delay(
        tenant_id=str(p.tenant_id),
        kubeconfig_path=payload.kubeconfig_path,
    )
    audit_detail(request, task_id=task.id, kubeconfig_path=payload.kubeconfig_path)
    return {"task_id": task.id, "status": "queued"}


@app.get("/api/v1/findings")
async def list_findings(
    p: Principal = Depends(get_principal),
    bucket: str | None = None,
    status: str | None = Query(None, pattern="^(open|triaged|accepted|fixed|false_positive)$"),
    limit: int = Query(100, ge=1, le=1000),
) -> list[FindingResponse]:
    async with tenant_session(p.tenant_id) as session:
        stmt = select(FindingRow).order_by(FindingRow.risk_score.desc()).limit(limit)
        if bucket:
            stmt = stmt.where(FindingRow.risk_bucket == bucket)
        if status:
            stmt = stmt.where(FindingRow.status == status)
        rows = (await session.execute(stmt)).scalars().all()
        return [_finding_response(row) for row in rows]


@app.patch("/api/v1/findings/{finding_id}")
async def triage_finding(
    finding_id: UUID,
    payload: TriageRequest,
    request: Request,
    p: Principal = Depends(require_role("admin", "analyst")),
) -> FindingResponse:
    """Analyst triage: open / triaged / accepted (with expiry) / false_positive.
    Rules live in core/triage.py; accepted and false_positive are never
    auto-closed or reopened by re-scans, except when an acceptance expires."""
    async with tenant_session(p.tenant_id) as session:
        row = (
            await session.execute(select(FindingRow).where(FindingRow.finding_id == finding_id))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="finding not found")
        delta = apply_triage(row, payload, actor=p.sub, now=datetime.now(timezone.utc))
        await session.commit()
        await session.refresh(row)
        audit_detail(request, finding_id=str(finding_id), **delta)
        return _finding_response(row)


@app.get("/api/v1/findings/new")
async def list_new_findings(
    p: Principal = Depends(get_principal),
    limit: int = 100,
) -> list[FindingResponse]:
    """Findings first seen in the most recent scan — the 'catch it early' delta."""
    async with tenant_session(p.tenant_id) as session:
        stmt = (
            select(FindingRow)
            .where(FindingRow.is_new.is_(True))
            .where(FindingRow.status == "open")
            .order_by(FindingRow.risk_score.desc())
            .limit(limit)
        )
        rows = (await session.execute(stmt)).scalars().all()
        return [_finding_response(row) for row in rows]


@app.get("/api/v1/findings/summary")
async def findings_summary(
    p: Principal = Depends(get_principal),
) -> dict:
    async with tenant_session(p.tenant_id) as session:
        stmt = select(FindingRow.risk_bucket, func.count()).group_by(FindingRow.risk_bucket)
        rows = (await session.execute(stmt)).all()
        out = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for bucket, count in rows:
            if bucket in out:
                out[bucket] = count
        new_open = (
            await session.execute(
                select(func.count())
                .select_from(FindingRow)
                .where(FindingRow.is_new.is_(True))
                .where(FindingRow.status == "open")
            )
        ).scalar_one()
        fixed = (
            await session.execute(
                select(func.count())
                .select_from(FindingRow)
                .where(FindingRow.status == "fixed")
            )
        ).scalar_one()
        return {**out, "new": int(new_open), "fixed": int(fixed)}


@app.post("/api/v1/copilot/query")
async def copilot_query(
    req: CopilotRequest,
    p: Principal = Depends(require_role("admin", "analyst", "viewer", "auditor")),
) -> dict:
    """Natural-language questions over the tenant's findings (Claude Fable 5).

    The copilot only sees read-only, tenant-scoped query tools; it never
    composes SQL and RLS remains the isolation boundary.
    """
    if not ai_active() or not settings.ai.copilot_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI copilot is disabled (VULNSUITE_AI_ENABLED / offline mode)",
        )
    from ..ai import copilot

    try:
        result = await copilot.ask(p.tenant_id, req.question)
    except AIEnrichmentError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"answer": result.answer, "tool_calls": result.tool_calls}


@app.post("/api/v1/reports", status_code=202)
async def create_report(
    p: Principal = Depends(require_role("admin", "analyst", "auditor")),
) -> dict:
    async with tenant_session(p.tenant_id) as session:
        findings = (await session.execute(select(FindingRow))).scalars().all()
        assets = (await session.execute(select(AssetRow.asset_id, AssetRow.name))).all()
    task = generate_report.delay(
        tenant_id=str(p.tenant_id),
        tenant_name="Tenant",
        operator=p.sub,
        findings_json=[
            {
                "finding_id": str(row.finding_id),
                "tenant_id": str(row.tenant_id),
                "asset_id": str(row.asset_id),
                "tool": row.tool,
                "module": row.module,
                "title": row.title,
                "description": row.description,
                "cve": list(row.cve or []),
                "cwe": list(row.cwe or []),
                "cvss_vector": row.cvss_vector,
                "cvss_base": row.cvss_base,
                "epss": row.epss,
                "severity": row.severity,
                "evidence": row.evidence or {},
                "remediation": row.remediation,
                "references": list(row.references or []),
                "first_seen": row.first_seen.isoformat(),
                "last_seen": row.last_seen.isoformat(),
                "status": row.status,
                "risk_score": row.risk_score,
                "risk_bucket": row.risk_bucket,
            }
            for row in findings
        ],
        asset_names={str(asset_id): name for asset_id, name in assets},
    )
    return {"task_id": task.id, "status": "queued"}
