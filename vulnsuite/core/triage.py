"""
VulnSuite - Analyst triage

Re-scans own `open` and `fixed`; analysts own `triaged`, `accepted` and
`false_positive` (core/db.py never auto-closes or reopens those). This
module holds the rules for moving between them so the API endpoint is a
thin wrapper and the rules are testable without a database:

- accepted / false_positive need a written justification
- accepted needs an expiry (max 365 days); an expired acceptance is
  reopened by the next scan instead of staying silently suppressed
- every change records who and when
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

TriageStatus = Literal["open", "triaged", "accepted", "false_positive"]

MAX_ACCEPTANCE_DAYS = 365
MIN_JUSTIFICATION_CHARS = 10


class TriageRequest(BaseModel):
    status: TriageStatus
    note: str = Field(default="", max_length=4000)
    owner: str | None = Field(default=None, max_length=256)
    accepted_until: datetime | None = None

    @model_validator(mode="after")
    def _rules(self) -> "TriageRequest":
        note = self.note.strip()
        if self.status in ("accepted", "false_positive") and len(note) < MIN_JUSTIFICATION_CHARS:
            raise ValueError(
                f"{self.status} requires a justification of at least "
                f"{MIN_JUSTIFICATION_CHARS} characters"
            )
        if self.status == "accepted":
            if self.accepted_until is None:
                raise ValueError("accepted requires accepted_until (risk acceptance must expire)")
            if self.accepted_until.tzinfo is None:
                raise ValueError("accepted_until must be timezone-aware")
            now = datetime.now(timezone.utc)
            if self.accepted_until <= now:
                raise ValueError("accepted_until must be in the future")
            if self.accepted_until > now + timedelta(days=MAX_ACCEPTANCE_DAYS):
                raise ValueError(f"risk acceptance cannot exceed {MAX_ACCEPTANCE_DAYS} days")
        elif self.accepted_until is not None:
            raise ValueError("accepted_until only applies to status=accepted")
        if self.owner is not None and not self.owner.strip():
            raise ValueError("owner must not be blank")
        return self


def acceptance_expired(status: str, accepted_until: datetime | None, now: datetime) -> bool:
    return status == "accepted" and accepted_until is not None and accepted_until <= now


def apply_triage(row: Any, req: TriageRequest, *, actor: str, now: datetime) -> dict[str, Any]:
    """Mutate a FindingRow-like object in place; return the audit delta."""
    before = row.status
    row.status = req.status
    row.triaged_by = actor
    row.triaged_at = now
    if req.note.strip():
        row.triage_note = req.note.strip()
    if req.owner is not None:
        row.owner = req.owner.strip()
    row.accepted_until = req.accepted_until if req.status == "accepted" else None
    if req.status == "open":
        row.fixed_at = None
    return {
        "from_status": before,
        "to_status": req.status,
        "owner": row.owner,
        "accepted_until": row.accepted_until.isoformat() if row.accepted_until else None,
    }
