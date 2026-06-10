"""VulnSuite - SIEM connectors (Splunk HEC, Microsoft Sentinel, Elastic).

Ships findings to downstream SIEM platforms over HTTP. Three adapters
behind a common `SIEMConnector` Protocol so the worker can dispatch to
whichever SIEM the tenant has configured without branching logic.

Common design:
  - Async httpx.AsyncClient for throughput (batches of 500)
  - Retries with exponential backoff (3 attempts)
  - Shared CEF-like normalized envelope so dashboards in any SIEM
    render VulnSuite findings consistently
  - Credentials come from settings.siem (env/Key Vault), never hardcoded
  - Failures are captured and surfaced — never crash the scan pipeline

Why each SIEM matters for BFSI:
  - Splunk: still the dominant enterprise SIEM in Indian BFSI.
  - Microsoft Sentinel: natural fit given our Azure-first posture.
  - Elastic: common in cost-sensitive and open-source-leaning shops.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Iterable, Protocol

import httpx

from ..core.schema import Finding

logger = logging.getLogger(__name__)

BATCH_SIZE = 500
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 2.0
REQUEST_TIMEOUT = 30.0


# ---------- common envelope ----------

def normalize_for_siem(f: Finding, tenant_name: str) -> dict:
    """Shared CEF-like envelope. Every SIEM gets the same fields."""
    ev = (f.evidence.raw or {}) if f.evidence else {}
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "vendor": "VulnSuite",
        "product": "VulnSuite",
        "version": "0.1",
        "event_type": "vulnerability_finding",
        "tenant": tenant_name,
        "tenant_id": str(f.tenant_id),
        "asset_id": str(f.asset_id),
        "finding_id": str(f.finding_id),
        "tool": f.tool,
        "module": f.module if isinstance(f.module, str) else f.module.value,
        "title": f.title,
        "severity": f.severity if isinstance(f.severity, str) else f.severity.value,
        "cvss_base": f.cvss_base,
        "epss": f.epss,
        "risk_score": f.risk_score,
        "risk_bucket": f.risk_bucket,
        "cve": f.cve,
        "cwe": f.cwe,
        "status": f.status if isinstance(f.status, str) else f.status.value,
        "first_seen": f.first_seen.isoformat(),
        "last_seen": f.last_seen.isoformat(),
        "file": f.evidence.file if f.evidence else None,
        "line": f.evidence.line if f.evidence else None,
        "host": ev.get("host"),
        "resource": ev.get("resource_name"),
        "rbi_control": ev.get("rbi_control"),
        "corroborated_by": [c.get("tool") for c in ev.get("corroborated_by", [])],
        # CEF-style severity for SIEM dashboards (0-10)
        "cef_severity": int(f.risk_score),
        # Signal for CERT-In reportability — Sentinel/Splunk alerts can key on this
        "certin_reportable": f.risk_bucket == "P0",
        # ---- AI enrichment signals (Claude Fable 5, Phase 3) ----
        # Flat scalars so SOC rules can key on them directly, e.g.
        # `ai_actively_exploited:true AND risk_bucket:P1` as an escalation rule.
        "ai_fp_likelihood": (ev.get("ai_triage") or {}).get("fp_likelihood"),
        "ai_exploitability": (ev.get("ai_triage") or {}).get("exploitability"),
        "ai_suggested_status": (ev.get("ai_triage") or {}).get("suggested_status"),
        "ai_actively_exploited": bool((ev.get("ai_threat_intel") or {}).get("actively_exploited")),
        "ai_kev_listed": bool((ev.get("ai_threat_intel") or {}).get("kev_listed")),
        "ai_attack_chain_count": len(ev.get("ai_attack_chains") or []),
        "ai_suggested_bucket": ev.get("ai_suggested_bucket"),
        # ---- lifecycle + deterministic escalation ----
        # ai_kev_listed also reflects scan-time KEV escalation, not just live intel.
        "ai_kev_listed": bool((ev.get("ai_threat_intel") or {}).get("kev_listed")) or bool(ev.get("kev_listed")),
        "risk_escalated": bool(ev.get("risk_escalated_by")),
        "risk_escalated_by": list(ev.get("risk_escalated_by") or []),
    }


# ---------- protocol ----------

class SIEMConnector(Protocol):
    name: str
    async def send(self, findings: Iterable[Finding], tenant_name: str) -> int: ...
    async def close(self) -> None: ...


# ---------- base ----------

class _BaseSIEM:
    name: str = "base"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "VulnSuite/0.1"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _post_with_retry(self, url: str, payload, headers: dict) -> bool:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = await self._client.post(url, content=payload, headers=headers)
                if 200 <= resp.status_code < 300:
                    return True
                logger.warning(
                    "%s returned %s on attempt %d: %s",
                    self.name, resp.status_code, attempt, resp.text[:200],
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("%s attempt %d failed: %s", self.name, attempt, e)
            await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)
        return False


# ---------- Splunk HEC ----------

class SplunkHECConnector(_BaseSIEM):
    """Splunk HTTP Event Collector. One event per finding, batched."""
    name = "splunk-hec"

    def __init__(
        self,
        hec_url: str,           # e.g. https://splunk.bank.local:8088/services/collector/event
        hec_token: str,
        index: str = "vulnsuite",
        source_type: str = "vulnsuite:finding",
        verify_tls: bool = True,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if client is None:
            client = httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT,
                verify=verify_tls,
                headers={"User-Agent": "VulnSuite/0.1"},
            )
        super().__init__(client)
        self.url = hec_url
        self.token = hec_token
        self.index = index
        self.source_type = source_type

    async def send(self, findings: Iterable[Finding], tenant_name: str) -> int:
        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json",
        }
        sent = 0
        batch: list[str] = []
        for f in findings:
            event = {
                "time": datetime.now(timezone.utc).timestamp(),
                "host": tenant_name,
                "source": "vulnsuite",
                "sourcetype": self.source_type,
                "index": self.index,
                "event": normalize_for_siem(f, tenant_name),
            }
            # HEC accepts concatenated JSON, not a JSON array
            batch.append(json.dumps(event))
            if len(batch) >= BATCH_SIZE:
                if await self._post_with_retry(self.url, "\n".join(batch), headers):
                    sent += len(batch)
                batch.clear()
        if batch:
            if await self._post_with_retry(self.url, "\n".join(batch), headers):
                sent += len(batch)
        logger.info("splunk: sent %d findings", sent)
        return sent


# ---------- Microsoft Sentinel ----------

class SentinelConnector(_BaseSIEM):
    """Azure Monitor / Sentinel via Log Analytics Data Collection Rule (DCR).

    Uses the DCR-based Logs Ingestion API (preferred over the legacy HTTP
    Data Collector API, which is being deprecated). Auth is via
    DefaultAzureCredential — in prod this is the worker's managed identity
    with `Monitoring Metrics Publisher` role on the DCR.
    """
    name = "sentinel"

    def __init__(
        self,
        dce_endpoint: str,      # Data Collection Endpoint URI
        dcr_immutable_id: str,  # DCR immutable ID
        stream_name: str,       # Custom-VulnSuiteFindings_CL
        credential=None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(client)
        self.dce = dce_endpoint.rstrip("/")
        self.dcr = dcr_immutable_id
        self.stream = stream_name
        self._credential = credential  # azure.identity.aio.DefaultAzureCredential
        self._token_cache: tuple[str, float] | None = None

    async def _bearer(self) -> str:
        if self._credential is None:
            raise RuntimeError("Sentinel credential not configured")
        now = datetime.now(timezone.utc).timestamp()
        if self._token_cache and self._token_cache[1] - now > 120:
            return self._token_cache[0]
        token = await self._credential.get_token(
            "https://monitor.azure.com/.default",
        )
        self._token_cache = (token.token, token.expires_on)
        return token.token

    async def send(self, findings: Iterable[Finding], tenant_name: str) -> int:
        bearer = await self._bearer()
        url = f"{self.dce}/dataCollectionRules/{self.dcr}/streams/{self.stream}?api-version=2023-01-01"
        headers = {
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
        }
        sent = 0
        batch: list[dict] = []
        for f in findings:
            batch.append(normalize_for_siem(f, tenant_name))
            if len(batch) >= BATCH_SIZE:
                if await self._post_with_retry(url, json.dumps(batch), headers):
                    sent += len(batch)
                batch.clear()
        if batch:
            if await self._post_with_retry(url, json.dumps(batch), headers):
                sent += len(batch)
        logger.info("sentinel: sent %d findings", sent)
        return sent


# ---------- Elastic ----------

class ElasticConnector(_BaseSIEM):
    """Elasticsearch _bulk API. Index pattern: vulnsuite-findings-YYYY.MM."""
    name = "elastic"

    def __init__(
        self,
        base_url: str,                   # e.g. https://elastic.bank.local:9200
        api_key: str | None = None,
        basic_auth: tuple[str, str] | None = None,
        index_prefix: str = "vulnsuite-findings",
        verify_tls: bool = True,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        headers = {"User-Agent": "VulnSuite/0.1"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
        if client is None:
            client = httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT,
                verify=verify_tls,
                headers=headers,
                auth=basic_auth,
            )
        super().__init__(client)
        self.base = base_url.rstrip("/")
        self.prefix = index_prefix

    def _index_name(self) -> str:
        now = datetime.now(timezone.utc)
        return f"{self.prefix}-{now:%Y.%m}"

    async def send(self, findings: Iterable[Finding], tenant_name: str) -> int:
        url = f"{self.base}/_bulk"
        headers = {"Content-Type": "application/x-ndjson"}
        index = self._index_name()
        sent = 0
        lines: list[str] = []
        count = 0
        for f in findings:
            action = {"index": {"_index": index, "_id": str(f.finding_id)}}
            doc = normalize_for_siem(f, tenant_name)
            lines.append(json.dumps(action))
            lines.append(json.dumps(doc))
            count += 1
            if count >= BATCH_SIZE:
                body = "\n".join(lines) + "\n"
                if await self._post_with_retry(url, body, headers):
                    sent += count
                lines.clear()
                count = 0
        if lines:
            body = "\n".join(lines) + "\n"
            if await self._post_with_retry(url, body, headers):
                sent += count
        logger.info("elastic: sent %d findings", sent)
        return sent


# ---------- factory ----------

def build_connector(kind: str, **kwargs) -> SIEMConnector:
    """Factory used by workers/tasks.py. Kind comes from tenant config."""
    kind = kind.lower()
    if kind in ("splunk", "splunk-hec"):
        return SplunkHECConnector(**kwargs)
    if kind in ("sentinel", "azure-sentinel"):
        return SentinelConnector(**kwargs)
    if kind in ("elastic", "elasticsearch"):
        return ElasticConnector(**kwargs)
    raise ValueError(f"unknown SIEM kind: {kind}")


async def fan_out(
    connectors: list[SIEMConnector],
    findings: list[Finding],
    tenant_name: str,
) -> dict[str, int]:
    """Ship the same findings to multiple SIEMs in parallel."""
    async def _one(c: SIEMConnector) -> tuple[str, int]:
        try:
            n = await c.send(findings, tenant_name)
            return (c.name, n)
        except Exception as e:  # noqa: BLE001
            logger.exception("%s fan-out failed: %s", c.name, e)
            return (c.name, 0)

    results = await asyncio.gather(*[_one(c) for c in connectors])
    return dict(results)
