"""
VulnSuite - Database layer (SQLAlchemy 2.0 async + PostgreSQL)

Mirrors core/schema.py. Multi-tenant isolation is enforced at the
DATABASE level via PostgreSQL Row-Level Security, not application code.
Every session must SET app.tenant_id before querying.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import AsyncIterator
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON, Boolean, Float, ForeignKey, Index, Integer, String, DateTime,
    UniqueConstraint, text, select,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .asset_rules import apply_asset_rules
from .fingerprint import finding_fingerprint
from .schema import Asset, Finding


DATABASE_URL = os.getenv(
    "VULNSUITE_DB_URL",
    "postgresql+asyncpg://vulnsuite:vulnsuite@localhost:5432/vulnsuite",
)


class Base(DeclarativeBase):
    pass


# ---------- Tables ----------

class AssetRow(Base):
    __tablename__ = "assets"

    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False)
    criticality: Mapped[int] = mapped_column(Integer, nullable=False)
    exposure: Mapped[float] = mapped_column(Float, nullable=False, default=0.6)
    owner: Mapped[str | None] = mapped_column(String(256))
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (Index("ix_assets_tenant_type", "tenant_id", "asset_type"),)


class FindingRow(Base):
    __tablename__ = "findings"

    finding_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    asset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("assets.asset_id", ondelete="CASCADE"), index=True,
    )
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    module: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(1024), nullable=False)
    description: Mapped[str] = mapped_column(String, default="")
    cve: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    cwe: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    cvss_base: Mapped[float] = mapped_column(Float, default=0.0)
    epss: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str] = mapped_column(String, default="")
    references: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_bucket: Mapped[str | None] = mapped_column(String(4), index=True)
    # ---- lifecycle tracking (stable across re-scans) ----
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    is_new: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    scan_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_findings_tenant_severity_score", "tenant_id", "severity", "risk_score"),
        Index("ix_findings_tenant_status", "tenant_id", "status"),
        Index("ix_findings_tenant_isnew", "tenant_id", "is_new"),
        UniqueConstraint("tenant_id", "fingerprint", name="uq_findings_tenant_fingerprint"),
    )


# ---------- Row-Level Security ----------

RLS_DDL = [
    "ALTER TABLE assets   ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE findings ENABLE ROW LEVEL SECURITY;",
    """CREATE POLICY tenant_isolation_assets ON assets
       USING (tenant_id = current_setting('app.tenant_id')::uuid);""",
    """CREATE POLICY tenant_isolation_findings ON findings
       USING (tenant_id = current_setting('app.tenant_id')::uuid);""",
]


# ---------- Engine / session ----------

_engine: AsyncEngine | None = None
_session_local: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _session_local
    if _session_local is None:
        _session_local = async_sessionmaker(
            get_engine(),
            expire_on_commit=False,
            class_=AsyncSession,
        )
    return _session_local


async def init_db() -> None:
    """Create tables + apply RLS. Idempotent-safe for dev; use Alembic in prod."""
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for stmt in RLS_DDL:
            try:
                await conn.execute(text(stmt))
            except Exception:
                pass  # policy already exists


@asynccontextmanager
async def tenant_session(tenant_id: UUID) -> AsyncIterator[AsyncSession]:
    """Yield a session scoped to one tenant. RLS does the filtering."""
    async with get_sessionmaker()() as session:
        await session.execute(
            text("SET LOCAL app.tenant_id = :tid"), {"tid": str(tenant_id)}
        )
        yield session


def _asset_identity(asset: Asset) -> tuple[str, str, str]:
    tags = asset.tags or {}
    external_id = (
        tags.get("azure_id")
        or tags.get("aws_arn")
        or tags.get("gcp_full_name")
        or tags.get("cluster")
        or tags.get("domain")
        or tags.get("artifact_digest")
        or asset.name
    )
    asset_type = asset.asset_type if isinstance(asset.asset_type, str) else asset.asset_type.value
    return (asset_type, external_id, asset.name)


async def upsert_assets(tenant_id: UUID, assets: list[Asset]) -> int:
    """Insert or update assets by a best-effort identity tuple."""
    if not assets:
        return 0

    async with tenant_session(tenant_id) as session:
        rows = (
            await session.execute(select(AssetRow).where(AssetRow.tenant_id == tenant_id))
        ).scalars().all()
        existing = {
            (
                row.asset_type,
                (
                    (row.tags or {}).get("azure_id")
                    or (row.tags or {}).get("aws_arn")
                    or (row.tags or {}).get("gcp_full_name")
                    or (row.tags or {}).get("cluster")
                    or (row.tags or {}).get("domain")
                    or (row.tags or {}).get("artifact_digest")
                    or row.name
                ),
                row.name,
            ): row
            for row in rows
        }

        from .config import get_settings

        policy = get_settings().asset_policy
        touched = 0
        for asset in assets:
            asset = apply_asset_rules(asset, policy)
            key = _asset_identity(asset)
            row = existing.get(key)
            if row is None:
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
            else:
                row.name = asset.name
                row.criticality = asset.criticality
                row.exposure = float(asset.exposure)
                row.owner = asset.owner
                row.tags = asset.tags
            touched += 1

        await session.commit()
        return touched


# ---------- Finding lifecycle (cross-scan reconciliation) ----------

# Statuses an analyst owns — never auto-closed or reopened by a re-scan.
_PROTECTED_STATUSES = frozenset({"false_positive", "accepted"})


def reconcile_plan(
    existing: dict[str, str], current: set[str],
) -> dict[str, list[str]]:
    """Pure planner: decide per-fingerprint actions for one asset.

    existing: {fingerprint: current_status} already in the DB for this asset.
    current:  fingerprints produced by this scan.

    Returns lists of fingerprints to insert / update / reopen / close.
    Kept side-effect-free so it is unit-testable without a database.
    """
    insert = [fp for fp in current if fp not in existing]
    update = [fp for fp in current if fp in existing]
    reopen = [fp for fp in current if existing.get(fp) == "fixed"]
    close = [
        fp for fp, status in existing.items()
        if fp not in current
        and status != "fixed"
        and status not in _PROTECTED_STATUSES
    ]
    return {"insert": insert, "update": update, "reopen": reopen, "close": close}


def _finding_to_row(
    finding: Finding, fingerprint: str, now: datetime, *, is_new: bool,
) -> FindingRow:
    module = finding.module if isinstance(finding.module, str) else finding.module.value
    severity = finding.severity if isinstance(finding.severity, str) else finding.severity.value
    status = finding.status if isinstance(finding.status, str) else finding.status.value
    return FindingRow(
        finding_id=finding.finding_id,
        tenant_id=finding.tenant_id,
        asset_id=finding.asset_id,
        tool=finding.tool,
        module=module,
        title=finding.title,
        description=finding.description,
        cve=list(finding.cve),
        cwe=list(finding.cwe),
        cvss_vector=finding.cvss_vector,
        cvss_base=finding.cvss_base,
        epss=finding.epss,
        severity=severity,
        evidence=finding.evidence.model_dump(mode="json") if finding.evidence else {},
        remediation=finding.remediation,
        references=list(finding.references),
        first_seen=finding.first_seen,
        last_seen=now,
        status=status,
        risk_score=finding.risk_score,
        risk_bucket=finding.risk_bucket,
        fingerprint=fingerprint,
        is_new=is_new,
        scan_count=1,
        fixed_at=None,
    )


async def reconcile_findings(
    tenant_id: UUID, asset_id: UUID, findings: list[Finding],
) -> dict[str, int]:
    """Upsert this scan's findings for one asset and auto-close the rest.

    - New fingerprint        -> insert, is_new=True
    - Seen-again fingerprint -> update mutable fields, accumulate last_seen
                                + scan_count, is_new=False
    - Previously fixed, back  -> reopen (status=open), is_new=True
    - Was present, now gone   -> auto-close (status=fixed, fixed_at=now),
                                unless analyst-owned (false_positive/accepted)

    Returns counts: {new, reopened, fixed, updated, total}.
    """
    now = datetime.now(tz=__import__("datetime").timezone.utc)
    by_fp: dict[str, Finding] = {}
    for f in findings:
        by_fp[finding_fingerprint(f)] = f  # last write wins (post-dedup, so unique)

    async with tenant_session(tenant_id) as session:
        rows = (
            await session.execute(
                select(FindingRow).where(FindingRow.asset_id == asset_id)
            )
        ).scalars().all()
        existing_rows = {r.fingerprint: r for r in rows if r.fingerprint}
        plan = reconcile_plan(
            {fp: r.status for fp, r in existing_rows.items()}, set(by_fp),
        )
        reopen = set(plan["reopen"])

        new_count = reopened = updated = 0
        for fp in plan["insert"]:
            session.add(_finding_to_row(by_fp[fp], fp, now, is_new=True))
            new_count += 1

        for fp in plan["update"]:
            f = by_fp[fp]
            row = existing_rows[fp]
            row.last_seen = now
            row.scan_count = (row.scan_count or 1) + 1
            row.is_new = fp in reopen
            row.tool = f.tool
            row.title = f.title
            row.description = f.description
            row.cve = list(f.cve)
            row.cwe = list(f.cwe)
            row.cvss_base = f.cvss_base
            row.epss = f.epss
            row.severity = f.severity if isinstance(f.severity, str) else f.severity.value
            row.evidence = f.evidence.model_dump(mode="json") if f.evidence else {}
            row.remediation = f.remediation
            row.references = list(f.references)
            row.risk_score = f.risk_score
            row.risk_bucket = f.risk_bucket
            if fp in reopen:
                row.status = "open"
                row.fixed_at = None
                reopened += 1
            updated += 1

        for fp in plan["close"]:
            row = existing_rows[fp]
            row.status = "fixed"
            row.fixed_at = now

        await session.commit()

    return {
        "new": new_count,
        "reopened": reopened,
        "fixed": len(plan["close"]),
        "updated": updated,
        "total": len(by_fp),
    }
