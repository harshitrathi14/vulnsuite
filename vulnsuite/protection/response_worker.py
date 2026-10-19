"""Explicit worker for durable notifications and approved cloud WAF response.

Run against the protection control-plane DB; local containment is executed by the
enrolled host agent. Importing this module never sends traffic or applies response.
"""
from __future__ import annotations

import argparse
import json
import logging
import time

from .integrations import (IDENTITY_ACTIONS, CloudflareWAFConnector, EntraIDConnector,
                           IntegrationError, WebhookConnector)

LOG = logging.getLogger(__name__)
LEASE_SECONDS = 120
# Provider-executed actions; those in REVERSIBLE are rolled back at expiry.
REMOTE_ACTIONS = ("cloud_waf_block",) + IDENTITY_ACTIONS
REVERSIBLE = ("cloud_waf_block", "identity_disable_account")
_REMOTE_SQL = "(" + ",".join("?" * len(REMOTE_ACTIONS)) + ")"
_REVERSIBLE_SQL = "(" + ",".join("?" * len(REVERSIBLE)) + ")"


def _delay(attempts: int) -> int:
    return min(3600, 2 ** min(attempts, 10) * 5)


def _claim_delivery(store, now):
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM deliveries WHERE "
                         "(status IN ('pending','retry') AND next_attempt<=?) OR "
                         "(status='sending' AND lease_until<=?) ORDER BY created LIMIT 1",
                         (now, now)).fetchone()
        if not row:
            return None
        db.execute("UPDATE deliveries SET status='sending',attempts=attempts+1,lease_until=? WHERE id=?",
                   (now + LEASE_SECONDS, row['id']))
        return dict(row)


def deliver_pending(store, config: dict, *, limit=20, transport=None) -> dict:
    counts = {"delivered": 0, "retry": 0, "failed": 0}
    for _ in range(limit):
        now = time.time()
        row = _claim_delivery(store, now)
        if not row:
            break
        error = None
        try:
            connector = config.get("integrations", {}).get(row["connector"])
            if not connector or connector.get("enabled") is not True:
                raise IntegrationError("connector_disabled")
            if connector.get("type", "webhook") != "webhook":
                raise IntegrationError("connector_type_unsupported")
            WebhookConnector(connector, transport=transport).deliver(json.loads(row["payload"]), row["id"])
            status = "delivered"
        except IntegrationError as exc:
            status, error = ("retry" if exc.retryable else "failed"), exc.code
        except (ValueError, KeyError, TypeError):
            status, error = "failed", "invalid_connector_configuration"
        with store.connect() as db:
            # Lease ownership guards a late process from overwriting a reclaimed job.
            updated = db.execute("UPDATE deliveries SET status=?,last_error=?,next_attempt=?,lease_until=0 "
                                 "WHERE id=? AND status='sending' AND lease_until=?",
                                 (status, error, time.time() + _delay(row["attempts"] + 1),
                                  row["id"], now + LEASE_SECONDS)).rowcount
            if updated:
                store.audit(db, "integration_delivery", row["connector"],
                            json.dumps({"id": row["id"], "status": status, "error": error}))
                counts[status] += 1
    return counts


def _claim_response(store, now):
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        # Expired unexecuted plans cannot be applied. A timed-out POST may have
        # succeeded, so expired running/retried plans still require reconciliation.
        db.execute("UPDATE response_jobs SET status='expired' WHERE action IN " + _REMOTE_SQL +
                   " AND status IN ('requested','approved') AND attempts=0 AND expires<=?", (*REMOTE_ACTIONS, now))
        row = db.execute("SELECT * FROM response_jobs WHERE action IN " + _REMOTE_SQL + " AND ("
                         "(status='approved' AND next_attempt<=?) OR "
                         "(status='running' AND lease_until<=?) OR "
                         "(status='applied' AND expires<=? AND action IN " + _REVERSIBLE_SQL + ") OR "
                         "(status='rolling_back' AND lease_until<=?) OR "
                         "(status='rollback_failed' AND next_attempt<=?)) ORDER BY created LIMIT 1",
                         (*REMOTE_ACTIONS, now, now, now, *REVERSIBLE, now, now)).fetchone()
        if not row:
            return None
        result = dict(row)
        reversible = row["action"] in REVERSIBLE
        result["rollback"] = row["status"] in ("applied", "rolling_back", "rollback_failed") or (
            reversible and row["expires"] <= now)
        status = "rolling_back" if result["rollback"] else "running"
        db.execute("UPDATE response_jobs SET status=?,attempts=attempts+1,lease_until=? WHERE id=?",
                   (status, now + LEASE_SECONDS, row["id"]))
        result["claimed_status"] = status
        return result


def process_responses(store, config: dict, *, limit=20, transport=None) -> dict:
    counts = {"applied": 0, "approved": 0, "failed": 0, "rolled_back": 0, "rollback_failed": 0}
    for _ in range(limit):
        now = time.time()
        row = _claim_response(store, now)
        if not row:
            break
        try:
            identity = row["action"] in IDENTITY_ACTIONS
            settings = config.get("response", {}).get("identity" if identity else "cloud_waf", {})
            # Disabling new actions must not disable cleanup of previously applied
            # actions. Preserve credentials/scope until outstanding jobs are clean.
            if not row["rollback"] and settings.get("enabled") is not True:
                raise IntegrationError("connector_disabled")
            connector = (EntraIDConnector if identity else CloudflareWAFConnector)(settings, transport=transport)
            plan = json.loads(row["plan"])
            if row["rollback"] and row["action"] not in REVERSIBLE:
                # An expired or lease-lost one-shot action is never retried blindly.
                raise IntegrationError("not_reversible")
            result = connector.rollback(plan) if row["rollback"] else connector.apply(plan)
            status = result["status"]
        except IntegrationError as exc:
            status = "rollback_failed" if row["rollback"] else "approved" if exc.retryable else "failed"
            result = {"status": status, "error": exc.code}
        except (ValueError, KeyError, TypeError):
            status = "rollback_failed" if row["rollback"] else "failed"
            result = {"status": status, "error": "invalid_response_configuration"}
        with store.connect() as db:
            updated = db.execute("UPDATE response_jobs SET status=?,result=?,next_attempt=?,lease_until=0 "
                                 "WHERE id=? AND status=? AND lease_until=?",
                                 (status, json.dumps(result), time.time() + _delay(row["attempts"] + 1),
                                  row["id"], row["claimed_status"], now + LEASE_SECONDS)).rowcount
            if updated:
                store.audit(db, "identity_response" if row["action"] in IDENTITY_ACTIONS else "cloud_response",
                            row["id"], json.dumps(result))
                counts[status] += 1
    return counts


def run_once(store, config, **kwargs):
    return {"deliveries": deliver_pending(store, config, **kwargs),
            "responses": process_responses(store, config, **kwargs)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--database", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true")
    mode.add_argument("--watch", action="store_true")
    args = parser.parse_args()
    with open(args.config) as source:
        config = json.load(source)
    from .store import Store
    store = Store(args.database)
    while True:
        print(json.dumps(run_once(store, config)), flush=True)
        if args.once:
            return
        time.sleep(5)


if __name__ == "__main__":
    main()
