"""
VulnSuite - Orchestrator

Runs multiple collectors in parallel against one asset, deduplicates
findings across tools, enriches via the risk engine, and persists
everything through a tenant-scoped DB session.

This is the "integration seam" of the suite. Collectors are async and
independent; the orchestrator owns concurrency, cross-tool dedup, and
the final risk-scoring pass. Celery workers in workers/tasks.py will
call `Orchestrator.run()` — see workers/tasks.py for the queueing layer.

Design principles:
- Collectors are plug-ins implementing `async scan(...) -> ScanResult`.
- Failures in one collector do NOT fail the run; errors are aggregated
  into the ScanResult envelope and surfaced in the final report.
- Dedup is cross-tool and keyed on (asset, normalized_key). The
  canonical finding wins; corroborating tools are appended to evidence.
- Risk enrichment is the LAST step, so dedup happens on raw severity
  and scoring reflects the merged view.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Protocol
from uuid import UUID

from .schema import Asset, Finding, ScanResult, Module
from .risk_engine import RiskEngine
from .dedup import dedup_findings  # sibling module, separate turn
from .db import reconcile_findings

logger = logging.getLogger(__name__)


class Collector(Protocol):
    """Structural type every collector already satisfies."""
    async def scan(self, *args, **kwargs) -> ScanResult: ...


CollectorCall = Callable[[], Awaitable[ScanResult]]
FindingPostProcessor = Callable[[list[Finding]], list[Finding]]


@dataclass
class OrchestratorConfig:
    max_parallel_collectors: int = 4     # one asset, N tools at once
    persist: bool = True                  # False for dry-run / CLI preview
    fail_fast: bool = False               # True only in dev
    per_collector_timeout: int = 1800     # hard ceiling per collector


@dataclass
class RunReport:
    asset_id: UUID
    tenant_id: UUID
    started_at: datetime
    finished_at: datetime
    scan_results: list[ScanResult] = field(default_factory=list)
    findings_after_dedup: list[Finding] = field(default_factory=list)
    persisted_count: int = 0
    # Cross-scan lifecycle deltas (filled by reconcile_findings on persist)
    new_count: int = 0          # findings never seen before this scan
    reopened_count: int = 0     # previously-fixed findings that came back
    fixed_count: int = 0        # findings that disappeared -> auto-closed
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        buckets = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for f in self.findings_after_dedup:
            if f.risk_bucket in buckets:
                buckets[f.risk_bucket] += 1
        return buckets


class Orchestrator:
    def __init__(
        self,
        risk_engine: RiskEngine,
        config: OrchestratorConfig | None = None,
    ) -> None:
        self.risk = risk_engine
        self.cfg = config or OrchestratorConfig()

    # ---------- public ----------

    async def run(
        self,
        asset: Asset,
        collector_calls: list[CollectorCall],
        post_processors: list[FindingPostProcessor] | None = None,
    ) -> RunReport:
        """
        asset:            the target being scanned (must carry tenant_id)
        collector_calls:  zero-arg coroutines, each returning a ScanResult.
                          Build these in the worker layer — this keeps the
                          orchestrator ignorant of collector constructors.
        """
        started = datetime.now(timezone.utc)
        report = RunReport(
            asset_id=asset.asset_id,
            tenant_id=asset.tenant_id,
            started_at=started,
            finished_at=started,
        )

        if not collector_calls:
            report.errors.append("no collectors configured")
            report.finished_at = datetime.now(timezone.utc)
            return report

        # 1) fan-out with bounded concurrency
        scan_results = await self._run_parallel(collector_calls)
        report.scan_results = scan_results

        # 2) aggregate raw findings + bubble up collector errors
        raw_findings: list[Finding] = []
        for sr in scan_results:
            raw_findings.extend(sr.findings)
            for err in sr.errors:
                report.errors.append(f"{sr.tool}: {err}")

        # 3) cross-tool dedup (merges corroborating evidence)
        deduped = dedup_findings(raw_findings)
        logger.info(
            "asset=%s raw=%d deduped=%d",
            asset.asset_id, len(raw_findings), len(deduped),
        )

        # 4) risk-score the merged set
        enriched = self.risk.enrich_batch(
            deduped, {str(asset.asset_id): asset},
        )
        for processor in post_processors or []:
            enriched = processor(enriched)
        report.findings_after_dedup = enriched

        # 5) reconcile through tenant-scoped session (RLS does isolation).
        # Upserts by stable fingerprint, accumulates first/last_seen, and
        # auto-closes findings that disappeared since the previous scan.
        if self.cfg.persist:
            try:
                deltas = await reconcile_findings(
                    asset.tenant_id, asset.asset_id, enriched,
                )
                report.persisted_count = deltas["total"]
                report.new_count = deltas["new"]
                report.reopened_count = deltas["reopened"]
                report.fixed_count = deltas["fixed"]
                logger.info(
                    "asset=%s reconciled: new=%d reopened=%d fixed=%d total=%d",
                    asset.asset_id, deltas["new"], deltas["reopened"],
                    deltas["fixed"], deltas["total"],
                )
            except Exception as e:  # noqa: BLE001
                logger.exception("reconcile failed")
                report.errors.append(f"persist: {e}")

        report.finished_at = datetime.now(timezone.utc)
        return report

    # ---------- internals ----------

    async def _run_parallel(
        self, calls: list[CollectorCall],
    ) -> list[ScanResult]:
        sem = asyncio.Semaphore(self.cfg.max_parallel_collectors)

        async def _one(call: CollectorCall) -> ScanResult | None:
            async with sem:
                try:
                    return await asyncio.wait_for(
                        call(), timeout=self.cfg.per_collector_timeout,
                    )
                except asyncio.TimeoutError:
                    logger.warning("collector timed out")
                    return None
                except Exception:  # noqa: BLE001
                    logger.exception("collector crashed")
                    if self.cfg.fail_fast:
                        raise
                    return None

        results = await asyncio.gather(*[_one(c) for c in calls])
        return [r for r in results if r is not None]
