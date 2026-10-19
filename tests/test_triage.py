"""Analyst triage rules (core/triage.py): justification for suppressions,
mandatory bounded expiry on risk acceptance, expiry reopens, audit delta."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from vulnsuite.core.triage import TriageRequest, acceptance_expired, apply_triage

NOW = datetime.now(timezone.utc)
NEXT_MONTH = NOW + timedelta(days=30)


def _row(**over):
    base = dict(status="open", owner=None, triage_note="", triaged_by=None, triaged_at=None,
                accepted_until=None, fixed_at=None)
    base.update(over)
    return SimpleNamespace(**base)


# ---------- request rules ----------

def test_open_and_triaged_need_no_justification() -> None:
    assert TriageRequest(status="open").status == "open"
    assert TriageRequest(status="triaged", owner="appsec").owner == "appsec"


@pytest.mark.parametrize("status", ["accepted", "false_positive"])
def test_suppressions_require_justification(status) -> None:
    kwargs = {"accepted_until": NEXT_MONTH} if status == "accepted" else {}
    with pytest.raises(ValidationError, match="justification"):
        TriageRequest(status=status, note="meh", **kwargs)


def test_accepted_requires_bounded_future_expiry() -> None:
    note = "Compensating control: WAF rule 1234 blocks the vector."
    with pytest.raises(ValidationError, match="requires accepted_until"):
        TriageRequest(status="accepted", note=note)
    with pytest.raises(ValidationError, match="in the future"):
        TriageRequest(status="accepted", note=note, accepted_until=NOW - timedelta(days=1))
    with pytest.raises(ValidationError, match="365 days"):
        TriageRequest(status="accepted", note=note, accepted_until=NOW + timedelta(days=400))
    with pytest.raises(ValidationError, match="timezone-aware"):
        TriageRequest(status="accepted", note=note, accepted_until=datetime(2099, 1, 1))
    assert TriageRequest(status="accepted", note=note, accepted_until=NEXT_MONTH).accepted_until == NEXT_MONTH


def test_expiry_only_applies_to_accepted() -> None:
    with pytest.raises(ValidationError, match="only applies"):
        TriageRequest(status="triaged", accepted_until=NEXT_MONTH)


def test_fixed_is_not_an_analyst_status() -> None:
    with pytest.raises(ValidationError):
        TriageRequest(status="fixed")


def test_blank_owner_rejected() -> None:
    with pytest.raises(ValidationError, match="owner"):
        TriageRequest(status="triaged", owner="   ")


# ---------- applying ----------

def test_apply_records_actor_time_and_returns_audit_delta() -> None:
    row = _row()
    req = TriageRequest(status="accepted", note="Accepted by CISO, ticket SEC-42 tracks removal.",
                        owner="platform-team", accepted_until=NEXT_MONTH)
    delta = apply_triage(row, req, actor="analyst@example.com", now=NOW)
    assert (row.status, row.owner, row.triaged_by, row.triaged_at) == ("accepted", "platform-team", "analyst@example.com", NOW)
    assert row.triage_note.startswith("Accepted by CISO")
    assert row.accepted_until == NEXT_MONTH
    assert delta == {"from_status": "open", "to_status": "accepted", "owner": "platform-team",
                     "accepted_until": NEXT_MONTH.isoformat()}


def test_reopening_clears_expiry_and_fixed_at_but_keeps_note_and_owner() -> None:
    row = _row(status="accepted", accepted_until=NEXT_MONTH, fixed_at=NOW, owner="x", triage_note="why")
    apply_triage(row, TriageRequest(status="open"), actor="a", now=NOW)
    assert row.status == "open" and row.accepted_until is None and row.fixed_at is None
    assert row.owner == "x" and row.triage_note == "why"


def test_acceptance_expiry() -> None:
    assert acceptance_expired("accepted", NOW - timedelta(seconds=1), NOW)
    assert not acceptance_expired("accepted", NOW + timedelta(days=1), NOW)
    assert not acceptance_expired("accepted", None, NOW)
    assert not acceptance_expired("false_positive", NOW - timedelta(days=1), NOW)
