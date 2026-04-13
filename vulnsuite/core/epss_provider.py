"""
VulnSuite - EPSS provider (Redis-cached FIRST.org client)

EPSS (Exploit Prediction Scoring System) is published by FIRST.org
and gives each CVE a score in [0, 1] representing the probability
that the CVE will be exploited in the wild in the next 30 days.

Why this matters for BFSI risk prioritization:
  A bank's scanner typically finds ~20,000 open criticals by CVSS
  alone. The subset actually being weaponized at any given moment is
  usually <5% of that. EPSS is what lets the CISO dashboard show
  "47 criticals currently being exploited" instead of "20,000
  criticals" — the difference between an actionable queue and an
  unusable firehose.

Caching strategy:
  - L1: in-process dict (per worker, zero-latency repeat lookups)
  - L2: Redis (shared across workers, 24h TTL)
  - L3: FIRST.org API (https://api.first.org/data/v1/epss)
  Batch lookups: the API supports `?cve=CVE-...,CVE-...` up to ~100
  CVEs per request. We batch aggressively to minimize egress.

Air-gapped BFSI mode:
  Set `offline_csv_path` to a pre-downloaded EPSS daily CSV
  (https://epss.cyentia.com/epss_scores-current.csv.gz). The provider
  loads it into memory and never hits the network. Banks that
  prohibit scanner egress to the public internet use this mode.
"""
from __future__ import annotations

import asyncio
import csv
import gzip
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import httpx
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
REDIS_KEY_PREFIX = "vulnsuite:epss:"
REDIS_TTL_SECONDS = 24 * 3600     # daily refresh aligned to FIRST.org cadence
BATCH_SIZE = 100
REQUEST_TIMEOUT = 10.0


class CachedEPSSProvider:
    """
    Satisfies the EPSSProvider Protocol in core/risk_engine.py.

    NOTE: risk_engine expects a sync `.get(cve)` signature, so we
    expose a sync wrapper that schedules onto a running loop. In the
    Celery worker path this is fine because workers use asyncio
    natively. For pure-sync call sites, use `get_many_sync`.
    """

    def __init__(
        self,
        redis: Redis | None = None,
        http_client: httpx.AsyncClient | None = None,
        offline_csv_path: str | None = None,
        floor: float = 0.0,
    ) -> None:
        self._l1: dict[str, float] = {}
        self._redis = redis
        self._http = http_client
        self._floor = floor
        self._offline: dict[str, float] = {}
        if offline_csv_path:
            self._load_offline(offline_csv_path)

    # ---------- offline mode ----------

    def _load_offline(self, path: str) -> None:
        """Load FIRST.org daily CSV (gzipped or plain) into memory."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"EPSS CSV not found: {path}")

        opener = gzip.open if p.suffix == ".gz" else open
        loaded = 0
        with opener(p, "rt", encoding="utf-8") as fh:
            # FIRST.org CSV has a metadata comment line, then header,
            # then rows: cve,epss,percentile
            reader = csv.reader(fh)
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                if row[0].lower() == "cve":
                    continue
                if len(row) < 2:
                    continue
                try:
                    self._offline[row[0].upper()] = float(row[1])
                    loaded += 1
                except ValueError:
                    continue
        logger.info("loaded %d EPSS scores from offline CSV", loaded)

    # ---------- public async API ----------

    async def get_many(self, cves: Iterable[str]) -> dict[str, float]:
        """Preferred entry point. Returns {CVE: epss} for all requested."""
        wanted = {c.upper().strip() for c in cves if c}
        if not wanted:
            return {}

        result: dict[str, float] = {}
        remaining: set[str] = set()

        # L0: offline CSV wins if loaded (air-gapped mode)
        if self._offline:
            for cve in wanted:
                if cve in self._offline:
                    result[cve] = max(self._offline[cve], self._floor)
            return {**{c: self._floor for c in wanted}, **result}

        # L1: in-process cache
        for cve in wanted:
            if cve in self._l1:
                result[cve] = self._l1[cve]
            else:
                remaining.add(cve)

        # L2: Redis
        if remaining and self._redis is not None:
            keys = [f"{REDIS_KEY_PREFIX}{c}" for c in remaining]
            try:
                vals = await self._redis.mget(keys)
                for cve, v in zip(list(remaining), vals):
                    if v is not None:
                        score = float(v)
                        result[cve] = score
                        self._l1[cve] = score
                remaining = {c for c in remaining if c not in result}
            except Exception:  # noqa: BLE001
                logger.exception("redis EPSS lookup failed; falling through")

        # L3: FIRST.org API, batched
        if remaining and self._http is not None:
            fetched = await self._fetch_from_first(remaining)
            for cve, score in fetched.items():
                result[cve] = score
                self._l1[cve] = score
            # Write-through to Redis
            if self._redis is not None and fetched:
                try:
                    pipe = self._redis.pipeline()
                    for cve, score in fetched.items():
                        pipe.setex(
                            f"{REDIS_KEY_PREFIX}{cve}",
                            REDIS_TTL_SECONDS,
                            str(score),
                        )
                    await pipe.execute()
                except Exception:  # noqa: BLE001
                    logger.exception("redis EPSS write-through failed")

        # Apply floor + fill misses with floor
        return {
            c: max(result.get(c, self._floor), self._floor)
            for c in wanted
        }

    async def _fetch_from_first(
        self, cves: Iterable[str],
    ) -> dict[str, float]:
        out: dict[str, float] = {}
        batch: list[str] = []
        cve_list = list(cves)
        for i in range(0, len(cve_list), BATCH_SIZE):
            batch = cve_list[i : i + BATCH_SIZE]
            try:
                resp = await self._http.get(
                    FIRST_EPSS_URL,
                    params={"cve": ",".join(batch)},
                    timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                data = resp.json()
                for row in data.get("data", []) or []:
                    cve = (row.get("cve") or "").upper()
                    try:
                        out[cve] = float(row.get("epss") or 0.0)
                    except ValueError:
                        continue
            except Exception:  # noqa: BLE001
                logger.exception(
                    "FIRST.org EPSS batch failed (size=%d); "
                    "missing CVEs will fall back to floor",
                    len(batch),
                )
        return out

    # ---------- sync adapter for risk_engine.EPSSProvider Protocol ----------

    def get(self, cve: str) -> float:
        """Blocking single-CVE lookup. Prefer get_many in async contexts."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
        if loop.is_running():
            # Called from within an async context via a sync wrapper —
            # punt to L1 to avoid deadlock. Caller should have pre-warmed.
            return self._l1.get(cve.upper(), self._floor)
        return loop.run_until_complete(self.get_many([cve])).get(
            cve.upper(), self._floor
        )

    def get_many_sync(self, cves: Iterable[str]) -> dict[str, float]:
        return asyncio.run(self.get_many(cves))

    # ---------- lifecycle ----------

    async def warm(self, cves: Iterable[str]) -> None:
        """Pre-populate L1/L2 from API before a scan run. Call this in
        the orchestrator before risk enrichment to avoid per-CVE latency."""
        await self.get_many(cves)
        logger.info("EPSS warm complete; L1 size=%d", len(self._l1))

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()


# ---------- factory ----------

async def build_default_provider(
    redis_url: str | None = None,
    offline_csv_path: str | None = None,
) -> CachedEPSSProvider:
    redis = Redis.from_url(redis_url) if redis_url else None
    http = httpx.AsyncClient(
        headers={"User-Agent": "VulnSuite/0.1 (+security@vulnsuite.local)"}
    ) if not offline_csv_path else None
    return CachedEPSSProvider(
        redis=redis,
        http_client=http,
        offline_csv_path=offline_csv_path,
    )
