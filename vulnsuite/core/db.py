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
    JSON, Float, ForeignKey, Index, Integer, String, DateTime, text, select,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .schema import Asset


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

    __table_args__ = (
        Index("ix_findings_tenant_severity_score", "tenant_id", "severity", "risk_score"),
        Index("ix_findings_tenant_status", "tenant_id", "status"),
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

        touched = 0
        for asset in assets:
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
