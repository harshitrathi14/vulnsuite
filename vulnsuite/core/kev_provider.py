"""VulnSuite - CISA KEV provider (Known Exploited Vulnerabilities).

CISA's KEV catalog is the authoritative public list of CVEs that are
*confirmed exploited in the wild*. Unlike EPSS (a probability), KEV is
a binary fact: if a CVE is on this list, real attackers have used it.
That makes it the strongest deterministic signal we have for forcing a
finding up the priority queue (see risk_engine escalation).

Sources, in order of preference:
  - Offline mirror JSON (air-gapped BFSI): set ``offline_json_path`` to
    a copy of known_exploited_vulnerabilities.json. No network.
  - Redis-cached set (shared across workers, daily TTL).
  - CISA public feed.

The catalog is small (~1,300 CVEs), so we hold the whole set in memory.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
REDIS_KEY = "vulnsuite:kev:set"
REDIS_TTL_SECONDS = 24 * 3600
REQUEST_TIMEOUT = 15.0


class KEVProvider:
    """Satisfies the KEVProvider Protocol in core/risk_engine.py."""

    def __init__(self, kev_ids: set[str] | None = None) -> None:
        self._kev: set[str] = {c.upper().strip() for c in (kev_ids or set())}

    def is_kev(self, cve: str) -> bool:
        if not cve:
            return False
        return cve.upper().strip() in self._kev

    def any_kev(self, cves: list[str]) -> bool:
        return any(self.is_kev(c) for c in cves)

    @property
    def size(self) -> int:
        return len(self._kev)


def _parse_catalog(payload: dict) -> set[str]:
    out: set[str] = set()
    for entry in payload.get("vulnerabilities", []) or []:
        cve = (entry.get("cveID") or "").upper().strip()
        if cve.startswith("CVE-"):
            out.add(cve)
    return out


def _load_offline(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"KEV catalog not found: {path}")
    with p.open("rt", encoding="utf-8") as fh:
        ids = _parse_catalog(json.load(fh))
    logger.info("loaded %d KEV CVEs from offline catalog", len(ids))
    return ids


async def build_kev_provider(
    redis_url: str | None = None,
    offline_json_path: str | None = None,
) -> KEVProvider:
    """Build a provider from the best available source. Always returns a
    usable provider — on total failure it returns an empty one (escalation
    simply no-ops rather than crashing the scan)."""
    if offline_json_path:
        try:
            return KEVProvider(_load_offline(offline_json_path))
        except Exception:  # noqa: BLE001
            logger.exception("offline KEV load failed; KEV escalation disabled this run")
            return KEVProvider()

    # Redis cache first
    redis = None
    if redis_url:
        try:
            from redis.asyncio import Redis

            redis = Redis.from_url(redis_url)
            cached = await redis.smembers(REDIS_KEY)
            if cached:
                ids = {c.decode() if isinstance(c, bytes) else c for c in cached}
                logger.info("KEV: %d CVEs from Redis cache", len(ids))
                return KEVProvider(ids)
        except Exception:  # noqa: BLE001
            logger.warning("KEV Redis read failed; falling through to CISA feed")

    # CISA feed
    try:
        import httpx

        async with httpx.AsyncClient(
            headers={"User-Agent": "VulnSuite/0.1 (+security@vulnsuite.local)"},
            timeout=REQUEST_TIMEOUT,
        ) as http:
            resp = await http.get(CISA_KEV_URL)
            resp.raise_for_status()
            ids = _parse_catalog(resp.json())
        logger.info("KEV: %d CVEs from CISA feed", len(ids))
        if redis is not None and ids:
            try:
                await redis.sadd(REDIS_KEY, *ids)
                await redis.expire(REDIS_KEY, REDIS_TTL_SECONDS)
            except Exception:  # noqa: BLE001
                logger.warning("KEV Redis write-through failed")
        return KEVProvider(ids)
    except Exception:  # noqa: BLE001
        logger.exception("CISA KEV fetch failed; KEV escalation disabled this run")
        return KEVProvider()
