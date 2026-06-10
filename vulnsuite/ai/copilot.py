"""VulnSuite AI - Security copilot (natural-language findings queries).

A manual agentic loop over three READ-ONLY tools. Design constraints:
- The model never composes SQL. Tools accept typed filters and execute
  parameterized SELECTs through ``tenant_session``, so PostgreSQL RLS
  remains the isolation boundary exactly as for the REST API.
- Bounded loop (settings.ai.copilot_max_turns) and bounded row limits.
- Tool results are compact JSON; full evidence blobs never enter the
  conversation.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import func, select

from ..core.config import get_settings
from ..core.db import AssetRow, FindingRow, tenant_session
from . import prompts
from .client import AIEnrichmentError, ai_active, get_async_client
from .schemas import CopilotAnswer

logger = logging.getLogger(__name__)

_MAX_ROWS = 200

TOOLS: list[dict[str, Any]] = [
    {
        "name": "query_findings",
        "description": (
            "Query the tenant's vulnerability findings with typed filters. "
            "Call this whenever the question concerns specific findings, CVEs, "
            "tools, files, or assets. Returns up to `limit` rows ordered by "
            "risk_score descending."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "bucket": {
                    "type": ["string", "null"],
                    "enum": ["P0", "P1", "P2", "P3", "P4", None],
                    "description": "Risk bucket filter",
                },
                "module": {
                    "type": ["string", "null"],
                    "description": "Module filter, e.g. sast, sca, secrets, cloud, asm",
                },
                "severity": {
                    "type": ["string", "null"],
                    "enum": ["critical", "high", "medium", "low", "info", None],
                },
                "status": {
                    "type": ["string", "null"],
                    "enum": ["open", "triaged", "accepted", "fixed", "false_positive", None],
                },
                "cve": {
                    "type": ["string", "null"],
                    "description": "Exact CVE ID, e.g. CVE-2024-3094",
                },
                "min_risk_score": {"type": ["number", "null"]},
                "limit": {"type": "integer", "description": "Max rows, 1-200"},
            },
            "required": ["bucket", "module", "severity", "status", "cve", "min_risk_score", "limit"],
            "additionalProperties": False,
        },
    },
    {
        "name": "findings_summary",
        "description": (
            "Aggregate counts of the tenant's findings grouped by risk bucket and "
            "by module. Call this first for any 'how many / overview / posture' question."
        ),
        "strict": True,
        "input_schema": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    },
    {
        "name": "list_assets",
        "description": "List the tenant's assets with criticality and exposure.",
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max rows, 1-200"}},
            "required": ["limit"],
            "additionalProperties": False,
        },
    },
]


def _clamp_limit(value: Any) -> int:
    try:
        return max(1, min(int(value), _MAX_ROWS))
    except (TypeError, ValueError):
        return 50


async def _query_findings(tenant_id: UUID, args: dict[str, Any]) -> list[dict]:
    stmt = select(FindingRow).order_by(FindingRow.risk_score.desc())
    if args.get("bucket"):
        stmt = stmt.where(FindingRow.risk_bucket == args["bucket"])
    if args.get("module"):
        stmt = stmt.where(FindingRow.module == args["module"])
    if args.get("severity"):
        stmt = stmt.where(FindingRow.severity == args["severity"])
    if args.get("status"):
        stmt = stmt.where(FindingRow.status == args["status"])
    if args.get("min_risk_score") is not None:
        stmt = stmt.where(FindingRow.risk_score >= float(args["min_risk_score"]))
    stmt = stmt.limit(_clamp_limit(args.get("limit")))

    async with tenant_session(tenant_id) as session:
        rows = (await session.execute(stmt)).scalars().all()

    cve_filter = (args.get("cve") or "").upper().strip()
    out = []
    for row in rows:
        cves = list(row.cve or [])
        if cve_filter and cve_filter not in cves:
            continue
        out.append(
            {
                "finding_id": str(row.finding_id),
                "title": row.title,
                "tool": row.tool,
                "module": row.module,
                "severity": row.severity,
                "risk_score": row.risk_score,
                "risk_bucket": row.risk_bucket,
                "status": row.status,
                "cve": cves[:5],
                "asset_id": str(row.asset_id),
                "file": (row.evidence or {}).get("file"),
                "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            }
        )
    return out


async def _findings_summary(tenant_id: UUID) -> dict:
    async with tenant_session(tenant_id) as session:
        by_bucket = (
            await session.execute(
                select(FindingRow.risk_bucket, func.count()).group_by(FindingRow.risk_bucket)
            )
        ).all()
        by_module = (
            await session.execute(
                select(FindingRow.module, func.count()).group_by(FindingRow.module)
            )
        ).all()
    return {
        "by_bucket": {bucket or "unbucketed": count for bucket, count in by_bucket},
        "by_module": {module: count for module, count in by_module},
    }


async def _list_assets(tenant_id: UUID, args: dict[str, Any]) -> list[dict]:
    async with tenant_session(tenant_id) as session:
        rows = (
            (await session.execute(select(AssetRow).limit(_clamp_limit(args.get("limit")))))
            .scalars()
            .all()
        )
    return [
        {
            "asset_id": str(row.asset_id),
            "name": row.name,
            "asset_type": row.asset_type,
            "criticality": row.criticality,
            "exposure": row.exposure,
            "tags": row.tags,
        }
        for row in rows
    ]


async def execute_tool(tenant_id: UUID, name: str, args: dict[str, Any]) -> str:
    """Dispatch one tool call; always returns a JSON string."""
    try:
        if name == "query_findings":
            result: Any = await _query_findings(tenant_id, args)
        elif name == "findings_summary":
            result = await _findings_summary(tenant_id)
        elif name == "list_assets":
            result = await _list_assets(tenant_id, args)
        else:
            return json.dumps({"error": f"unknown tool: {name}"})
        return json.dumps(result, default=str)
    except Exception as exc:  # noqa: BLE001 - tool errors go back to the model
        logger.exception("copilot tool %s failed", name)
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"})


async def ask(tenant_id: UUID, question: str) -> CopilotAnswer:
    """Run the bounded agentic loop and return the final answer."""
    settings = get_settings()
    if not ai_active() or not settings.ai.copilot_enabled:
        raise AIEnrichmentError("copilot disabled")

    client = get_async_client()
    messages: list[dict[str, Any]] = [{"role": "user", "content": question}]
    tool_calls = 0

    for _ in range(settings.ai.copilot_max_turns):
        response = await client.messages.create(
            model=settings.ai.model,
            max_tokens=8000,
            thinking={"type": "adaptive"},
            output_config={"effort": settings.ai.copilot_effort},
            system=[{"type": "text", "text": prompts.COPILOT_SYSTEM, "cache_control": {"type": "ephemeral"}}],
            metadata={"user_id": f"tenant:{tenant_id}"},
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason != "tool_use":
            answer = "".join(b.text for b in response.content if b.type == "text").strip()
            return CopilotAnswer(answer=answer or "(no answer)", tool_calls=tool_calls)

        messages.append({"role": "assistant", "content": response.content})
        results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            tool_calls += 1
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": await execute_tool(tenant_id, block.name, dict(block.input)),
                }
            )
        messages.append({"role": "user", "content": results})

    return CopilotAnswer(
        answer="I hit the tool-call budget before finishing. Try a narrower question.",
        tool_calls=tool_calls,
    )
