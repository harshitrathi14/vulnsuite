"""VulnSuite AI - Secret redaction boundary.

Nothing in a finding may reach the Claude API before passing through
``redact_finding``. Secrets-module findings carry *live credential
material* (gitleaks/trufflehog matches), and any module can embed
tokens in snippets or evidence. This module is the hard boundary:
pattern-based masking for all findings, plus aggressive field-level
masking for the SECRETS module where the evidence IS the secret.

BFSI note: redaction is not configurable. There is deliberately no
flag to turn it off.
"""
from __future__ import annotations

import re
from typing import Any

from ..core.schema import Evidence, Finding, Module

REDACTED = "[REDACTED]"

# Patterns are ordered: structural blocks first, generic key=value last.
_PATTERNS: list[re.Pattern[str]] = [
    # Private key blocks (PEM)
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"),
    # AWS access key IDs + adjacent secrets
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"),
    # GitHub tokens (classic + fine-grained)
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    # Slack tokens
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    # Google API keys
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
    # JWTs
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+\b"),
    # Bearer tokens
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]{16,}=*"),
    # Credentials embedded in URLs: scheme://user:pass@host
    re.compile(r"(?<=://)[^/\s:@]+:[^@\s]+(?=@)"),
    # Azure / cloud connection-string fragments
    re.compile(r"(?i)\b(accountkey|sharedaccesskey|sharedaccesssignature|sig)=[^;&\s]{8,}"),
    # Generic key:value / key=value assignments (key may be prefixed, e.g. db_password)
    re.compile(
        r"(?i)[\w\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|"
        r"auth(?:orization)?|client[_\-]?secret|access[_\-]?key)[\w\-]*"
        r"\s*[:=]\s*['\"]?[^\s'\"]{6,}"
    ),
]

# Evidence keys whose values are masked outright on SECRETS findings.
SECRET_EVIDENCE_KEYS = frozenset(
    {
        "secret",
        "secret_value",
        "match",
        "raw_secret",
        "value",
        "token",
        "password",
        "private_key",
        "connection_string",
        "entropy_string",
        "commit_secret",
        "line_content",
        "decoded",
    }
)


def redact_text(text: str | None) -> str | None:
    """Mask known secret shapes inside arbitrary text."""
    if not text:
        return text
    out = text
    for pattern in _PATTERNS:
        out = pattern.sub(REDACTED, out)
    return out


def _redact_value(value: Any, *, force: bool = False) -> Any:
    if isinstance(value, str):
        return REDACTED if force else redact_text(value)
    if isinstance(value, dict):
        return _redact_mapping(value, force_all=force)
    if isinstance(value, list):
        return [_redact_value(v, force=force) for v in value]
    return value


def _redact_mapping(data: dict[str, Any], *, force_all: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        force = force_all or key.lower() in SECRET_EVIDENCE_KEYS
        out[key] = _redact_value(value, force=force)
    return out


def redact_finding(finding: Finding) -> Finding:
    """Return a deep copy of the finding safe to send off-host.

    The original is never mutated — the redacted copy exists only for
    the duration of the API exchange; persisted evidence keeps full
    fidelity for analysts inside the boundary.
    """
    f = finding.model_copy(deep=True)
    module = f.module if isinstance(f.module, str) else f.module.value
    is_secrets = module == Module.SECRETS.value

    f.title = redact_text(f.title) or f.title
    f.description = redact_text(f.description) or ""
    f.remediation = redact_text(f.remediation) or ""

    evidence = f.evidence or Evidence()
    snippet = "[REDACTED - secret material]" if is_secrets else redact_text(evidence.snippet)
    raw = _redact_mapping(evidence.raw, force_all=False) if evidence.raw else evidence.raw
    f.evidence = evidence.model_copy(update={"snippet": snippet, "raw": raw})
    return f
