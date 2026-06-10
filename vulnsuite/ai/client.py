"""VulnSuite AI - Claude Fable 5 client wrapper.

Single funnel for every model call in the suite. Centralizes:
- the activation gate (feature flag + air-gap + SDK presence)
- Fable 5 request shape (adaptive thinking, effort, no sampling params)
- tenant tagging via request metadata
- prompt-cache-friendly system blocks (frozen prefix, volatile suffix)
- JSON-schema sanitization for the Batches API path

Fable 5 API notes (do not "fix" these):
- thinking must be ``{"type": "adaptive"}``; an explicit disabled is a 400.
- temperature / top_p / top_k are removed parameters (400 if sent).
- structured outputs go through ``messages.parse`` (sync path) or
  ``output_config.format`` with a sanitized schema (batch path).
"""
from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any, TypeVar
from uuid import UUID

from pydantic import BaseModel

from ..core.config import get_settings

logger = logging.getLogger(__name__)

try:  # the suite must import (and air-gapped deploys must run) without the SDK
    import anthropic
except ImportError:  # pragma: no cover - exercised only in stripped envs
    anthropic = None  # type: ignore[assignment]

T = TypeVar("T", bound=BaseModel)

_VALID_EFFORT = {"low", "medium", "high", "xhigh", "max"}

# JSON-schema keywords the structured-outputs grammar rejects.
_UNSUPPORTED_SCHEMA_KEYS = {
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
    "minLength", "maxLength", "pattern", "minItems", "maxItems", "uniqueItems",
}


class AIEnrichmentError(RuntimeError):
    """Raised by call helpers; callers catch it and degrade to no-op."""


def ai_active() -> bool:
    """AI is opt-in, and hard-off when air-gapped or the SDK is absent."""
    settings = get_settings()
    if not settings.ai.enabled:
        return False
    if settings.scanning.offline_mode:
        return False
    return anthropic is not None


def _effort(value: str) -> str:
    return value if value in _VALID_EFFORT else "high"


@lru_cache(maxsize=1)
def get_sync_client() -> "anthropic.Anthropic":
    settings = get_settings()
    kwargs: dict[str, Any] = {"timeout": settings.ai.request_timeout_seconds, "max_retries": 3}
    if settings.ai.api_key is not None:
        kwargs["api_key"] = settings.ai.api_key.get_secret_value()
    return anthropic.Anthropic(**kwargs)


@lru_cache(maxsize=1)
def get_async_client() -> "anthropic.AsyncAnthropic":
    settings = get_settings()
    kwargs: dict[str, Any] = {"timeout": settings.ai.request_timeout_seconds, "max_retries": 3}
    if settings.ai.api_key is not None:
        kwargs["api_key"] = settings.ai.api_key.get_secret_value()
    return anthropic.AsyncAnthropic(**kwargs)


def _system_blocks(system: str) -> list[dict[str, Any]]:
    """Frozen system prompt as the cacheable prefix."""
    return [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]


def _metadata(tenant_id: UUID | str) -> dict[str, str]:
    return {"user_id": f"tenant:{tenant_id}"}


def parse_structured(
    *,
    system: str,
    user: str,
    output_model: type[T],
    effort: str,
    tenant_id: UUID | str,
    max_tokens: int = 16000,
) -> T:
    """One structured-output call. Raises AIEnrichmentError on any failure."""
    if not ai_active():
        raise AIEnrichmentError("AI layer disabled")
    settings = get_settings()
    try:
        response = get_sync_client().messages.parse(
            model=settings.ai.model,
            max_tokens=max_tokens,
            thinking={"type": "adaptive"},
            output_config={"effort": _effort(effort)},
            system=_system_blocks(system),
            metadata=_metadata(tenant_id),
            messages=[{"role": "user", "content": user}],
            output_format=output_model,
        )
        parsed = response.parsed_output
        if parsed is None:
            raise AIEnrichmentError("model returned no parseable output")
        return parsed
    except AIEnrichmentError:
        raise
    except Exception as exc:  # noqa: BLE001 - boundary: degrade, never crash the pipeline
        raise AIEnrichmentError(f"{type(exc).__name__}: {exc}") from exc


def generate_text(
    *,
    system: str,
    user: str,
    effort: str,
    tenant_id: UUID | str,
    max_tokens: int = 16000,
) -> str:
    """Free-text generation (narratives). Raises AIEnrichmentError on failure."""
    if not ai_active():
        raise AIEnrichmentError("AI layer disabled")
    settings = get_settings()
    try:
        response = get_sync_client().messages.create(
            model=settings.ai.model,
            max_tokens=max_tokens,
            thinking={"type": "adaptive"},
            output_config={"effort": _effort(effort)},
            system=_system_blocks(system),
            metadata=_metadata(tenant_id),
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(b.text for b in response.content if b.type == "text").strip()
        if not text:
            raise AIEnrichmentError("model returned empty text")
        return text
    except AIEnrichmentError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AIEnrichmentError(f"{type(exc).__name__}: {exc}") from exc


# ---------- Batches API path (bulk triage at 50% price) ----------

def clean_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Pydantic JSON schema -> structured-outputs-compatible schema.

    Strips constraint keywords the grammar rejects and forces
    ``additionalProperties: false`` on every object node.
    """

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            out = {k: _walk(v) for k, v in node.items() if k not in _UNSUPPORTED_SCHEMA_KEYS}
            if out.get("type") == "object":
                out["additionalProperties"] = False
            return out
        if isinstance(node, list):
            return [_walk(v) for v in node]
        return node

    return _walk(model.model_json_schema())


def build_batch_request(
    *,
    custom_id: str,
    system: str,
    user: str,
    output_model: type[BaseModel],
    effort: str,
    tenant_id: UUID | str,
    max_tokens: int = 16000,
) -> dict[str, Any]:
    settings = get_settings()
    return {
        "custom_id": custom_id,
        "params": {
            "model": settings.ai.model,
            "max_tokens": max_tokens,
            "thinking": {"type": "adaptive"},
            "output_config": {
                "effort": _effort(effort),
                "format": {"type": "json_schema", "schema": clean_schema(output_model)},
            },
            "system": _system_blocks(system),
            "metadata": _metadata(tenant_id),
            "messages": [{"role": "user", "content": user}],
        },
    }


def submit_batch(requests: list[dict[str, Any]]) -> str:
    if not ai_active():
        raise AIEnrichmentError("AI layer disabled")
    try:
        batch = get_sync_client().messages.batches.create(requests=requests)
        return batch.id
    except Exception as exc:  # noqa: BLE001
        raise AIEnrichmentError(f"batch submit failed: {type(exc).__name__}: {exc}") from exc


def batch_status(batch_id: str) -> str:
    try:
        return get_sync_client().messages.batches.retrieve(batch_id).processing_status
    except Exception as exc:  # noqa: BLE001
        raise AIEnrichmentError(f"batch poll failed: {type(exc).__name__}: {exc}") from exc


def collect_batch(batch_id: str, output_model: type[T]) -> dict[str, T]:
    """Map custom_id -> parsed model for every succeeded request in the batch."""
    out: dict[str, T] = {}
    try:
        for result in get_sync_client().messages.batches.results(batch_id):
            if result.result.type != "succeeded":
                logger.warning("batch item %s: %s", result.custom_id, result.result.type)
                continue
            message = result.result.message
            text = next((b.text for b in message.content if b.type == "text"), "")
            try:
                out[result.custom_id] = output_model.model_validate_json(text)
            except Exception:  # noqa: BLE001
                logger.warning("batch item %s: unparseable output", result.custom_id)
    except AIEnrichmentError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AIEnrichmentError(f"batch collect failed: {type(exc).__name__}: {exc}") from exc
    return out
