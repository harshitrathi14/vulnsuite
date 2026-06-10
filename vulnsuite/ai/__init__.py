"""VulnSuite - AI enrichment layer (Claude Fable 5).

Phase 3: every capability in this package is advisory and additive.
Deterministic pipeline outputs (risk_score, risk_bucket, dedup keys)
remain authoritative; AI verdicts ride inside ``evidence.raw`` under
``ai_*`` keys so analysts can always see — and override — what the
model concluded.

Hard rules enforced here:
- AI is OFF by default and force-disabled in offline (air-gap) mode.
- Secret material is redacted before any byte leaves the boundary.
- Every request is tenant-tagged; tenants are never mixed in a call.
- All failures degrade to no-op: findings flow through unenriched.
"""
from __future__ import annotations

__all__ = ["client", "schemas", "redaction"]
