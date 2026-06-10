"""VulnSuite - FastAPI application (routes + auth inline)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ..ai.client import AIEnrichmentError, ai_active
from ..core.config import get_settings
from ..core.db import AssetRow, FindingRow, init_db, tenant_session
from ..core.schema import Asset, AssetType, ExposureFactor, ScanTargets
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

settings = get_settings()
app = FastAPI(
    title="VulnSuite API",
    version="0.2.0",
    description="Cybersecurity vulnerability analysis suite (BFSI-tuned)",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if not settings.is_production else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ROLES = {"admin", "analyst", "viewer", "auditor"}


class Principal(BaseModel):
    sub: str
    tenant_id: UUID
    role: str
    email: str | None = None


async def get_principal(
    authorization: Annotated[str | None, Header()] = None,
    x_tenant_id: Annotated[str | None, Header()] = None,
) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    if not x_tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing X-Tenant-Id header")
    return Principal(
        sub="stub-user",
        tenant_id=UUID(x_tenant_id),
        role="analyst",
        email="stub@vulnsuite.local",
    )


def require_role(*allowed: str):
    def _check(p: Principal = Depends(get_principal)) -> Principal:
        if p.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role {p.role} not in {allowed}",
            )
        return p

    return _check


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
    p: Principal = Depends(require_role("admin", "analyst")),
) -> dict:
    asset = Asset(tenant_id=p.tenant_id, **payload.model_dump())
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
    p: Principal = Depends(require_role("admin", "analyst")),
) -> dict:
    if not req.targets.has_any():
        raise HTTPException(status_code=400, detail="no targets configured")
    try:
        validate_dast_targets(req.targets)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

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
    return {"task_id": task.id, "status": "queued"}


@app.post("/api/v1/discover/azure", status_code=202)
async def trigger_azure_discovery(
    p: Principal = Depends(require_role("admin")),
) -> dict:
    task = discover_assets.delay(tenant_id=str(p.tenant_id))
    return {"task_id": task.id, "status": "queued"}


@app.post("/api/v1/discover/aws", status_code=202)
async def trigger_aws_discovery(
    payload: AWSDiscoveryRequest,
    p: Principal = Depends(require_role("admin")),
) -> dict:
    task = discover_aws_assets.delay(tenant_id=str(p.tenant_id), account_ids=payload.account_ids)
    return {"task_id": task.id, "status": "queued"}


@app.post("/api/v1/discover/gcp", status_code=202)
async def trigger_gcp_discovery(
    payload: GCPDiscoveryRequest,
    p: Principal = Depends(require_role("admin")),
) -> dict:
    task = discover_gcp_assets.delay(tenant_id=str(p.tenant_id), project_ids=payload.project_ids)
    return {"task_id": task.id, "status": "queued"}


@app.post("/api/v1/discover/domains", status_code=202)
async def trigger_domain_discovery(
    payload: DomainDiscoveryRequest,
    p: Principal = Depends(require_role("admin")),
) -> dict:
    task = discover_domains.delay(tenant_id=str(p.tenant_id), root_domains=payload.root_domains)
    return {"task_id": task.id, "status": "queued"}


@app.post("/api/v1/discover/kubernetes", status_code=202)
async def trigger_kubernetes_discovery(
    payload: KubernetesDiscoveryRequest,
    p: Principal = Depends(require_role("admin")),
) -> dict:
    task = discover_kubernetes_clusters.delay(
        tenant_id=str(p.tenant_id),
        kubeconfig_path=payload.kubeconfig_path,
    )
    return {"task_id": task.id, "status": "queued"}


@app.get("/api/v1/findings")
async def list_findings(
    p: Principal = Depends(get_principal),
    bucket: str | None = None,
    limit: int = 100,
) -> list[FindingResponse]:
    async with tenant_session(p.tenant_id) as session:
        stmt = select(FindingRow).order_by(FindingRow.risk_score.desc()).limit(limit)
        if bucket:
            stmt = stmt.where(FindingRow.risk_bucket == bucket)
        rows = (await session.execute(stmt)).scalars().all()
        return [_finding_response(row) for row in rows]


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
