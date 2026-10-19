"""Boundary tests; PostgreSQL runtime verification belongs in deployment staging."""
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from sqlalchemy.dialects.postgresql.asyncpg import PGDialect_asyncpg
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsuite.core import db


@pytest.mark.asyncio
async def test_tenant_context_is_bound_on_each_transaction_and_listener_removed(monkeypatch):
    session = AsyncSession()
    monkeypatch.setattr(db, "get_sessionmaker", lambda: lambda: session)
    tenant_id = UUID("00000000-0000-0000-0000-000000000001")
    connection = MagicMock()
    async with db.tenant_session(tenant_id):
        for _ in range(2):
            session.sync_session.dispatch.after_begin(session.sync_session, None, connection)
    assert connection.execute.call_count == 2
    statement, params = connection.execute.call_args.args
    assert "set_config('app.tenant_id', $1, true)" in str(statement.compile(dialect=PGDialect_asyncpg()))
    assert params == {"tid": str(tenant_id)}
    session.sync_session.dispatch.after_begin(session.sync_session, None, connection)
    assert connection.execute.call_count == 2


@pytest.mark.asyncio
async def test_invalid_tenant_rejected_before_session_creation(monkeypatch):
    factory = MagicMock()
    monkeypatch.setattr(db, "get_sessionmaker", factory)
    with pytest.raises(ValueError):
        async with db.tenant_session("malformed"):
            pytest.fail("tenant scope must not open")
    factory.assert_not_called()


def fake_engine(monkeypatch, bypass=False):
    conn = AsyncMock()
    conn.scalar.return_value = bypass
    engine = MagicMock()
    engine.begin.return_value.__aenter__.return_value = conn
    monkeypatch.setattr(db, "get_engine", lambda: engine)
    return conn


@pytest.mark.asyncio
async def test_init_db_applies_write_checks_and_forces_owner_isolation(monkeypatch):
    conn = fake_engine(monkeypatch)
    await db.init_db()
    sql = [str(call.args[0]) for call in conn.execute.call_args_list]
    assert "ALTER TABLE assets   FORCE ROW LEVEL SECURITY;" in sql
    assert "ALTER TABLE findings FORCE ROW LEVEL SECURITY;" in sql
    policies = [stmt for stmt in sql if stmt.startswith("CREATE POLICY")]
    assert len(policies) == 2
    assert all("WITH CHECK" in statement and "NULLIF" in statement for statement in policies)


@pytest.mark.asyncio
async def test_database_policy_failure_aborts_initialization(monkeypatch):
    conn = fake_engine(monkeypatch)
    conn.execute.side_effect = RuntimeError("permission denied")
    with pytest.raises(RuntimeError, match="permission denied"):
        await db.init_db()


@pytest.mark.asyncio
async def test_superuser_or_bypass_role_cannot_initialize_api(monkeypatch):
    conn = fake_engine(monkeypatch, bypass=True)
    with pytest.raises(RuntimeError, match="NOBYPASSRLS"):
        await db.init_db()
    conn.run_sync.assert_not_called()
