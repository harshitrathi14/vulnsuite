"""Control-plane authorization, lifecycle, and approval regression tests."""
import json
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from vulnsuite.protection.models import Event
from vulnsuite.protection.service import create_app
from vulnsuite.protection.store import Store


TOKENS = {name: char * 40 for name, char in (
    ("admin-one", "a"), ("admin-two", "b"), ("analyst", "c"),
    ("viewer", "d"), ("auditor", "e"), ("alpha", "f"), ("bravo", "g"))}


def headers(name):
    return {"Authorization": "Bearer " + TOKENS.get(name, name)}


@pytest.fixture
def operations(tmp_path):
    cfg = {
        "operators": {name: {"token": TOKENS[name], "roles": [
            "admin" if name.startswith("admin-") else name]}
            for name in ("admin-one", "admin-two", "analyst", "viewer", "auditor")},
        "hosts": {name: {"token": TOKENS[name], "addresses": [ip],
                         "allow_response": True, "protected_networks": ["10.0.0.0/24"],
                         "permitted_networks": ["10.0.0.0/8"]}
                  for name, ip in (("alpha", "10.1.0.1"), ("bravo", "10.1.0.2"))},
        "response": {"hosts": {"alpha": {"enabled": True,
            "allowed_actions": ["quarantine_file", "restore_file", "isolate_host", "release_host"],
            "isolation": {"management_networks": ["10.0.0.0/24"], "management_ports": [22, 443]}}}},
    }
    store = Store(str(tmp_path / "operations.sqlite"))
    client = TestClient(create_app(cfg, store))
    return client, store, cfg


def ingest(client, events, host="alpha"):
    return client.post("/v1/events", headers=headers(host),
                       json={"events": [e.model_dump(mode="json") for e in events]})


def malware(client, host="alpha"):
    response = ingest(client, [Event(kind="malware_detection", path="/srv/upload/sample",
                                    engine="sha256", signature="fixture", sha256="a" * 64)], host)
    assert response.status_code == 200, response.text
    return response.json()["alerts"][0]["id"]


def request_job(client, alert_id, actor="admin-one", **overrides):
    payload = {"action": "quarantine_file", "alert_id": alert_id,
               "duration_seconds": 300, "reason": "Investigated matching malware evidence"}
    payload.update(overrides)
    return client.post("/v1/playbooks", headers=headers(actor), json=payload)


@pytest.mark.parametrize("role", ["viewer", "auditor"])
def test_read_only_roles_cannot_modify_operations(operations, role):
    client, _, _ = operations
    assert client.get("/v1/overview", headers=headers(role)).status_code == 200
    assert client.get("/v1/me", headers=headers(role)).json()["roles"] == [role]
    for method, path, payload in (
        ("POST", "/v1/incidents", {"title": "Incident", "owner": "soc", "alert_ids": [1]}),
        ("POST", "/v1/blocks", {"alert_id": 1, "reason": "Investigated source address"}),
        ("POST", "/v1/playbooks", {"action": "quarantine_file", "alert_id": 1,
                                    "reason": "Investigated source evidence"}),
        ("POST", "/v1/enrollment-tokens", {"host": "new-host"}),
        ("POST", "/v1/agents/alpha/rotate", None),
        ("POST", "/v1/agents/alpha/revoke", None),
    ):
        assert client.request(method, path, headers=headers(role), json=payload).status_code == 403
    assert client.get("/v1/overview", headers=headers("alpha")).status_code == 403
    assert ingest(client, [Event(kind="heartbeat")], role).status_code == 401


def test_analyst_can_investigate_but_cannot_manage_agents_or_approve(operations):
    client, _, _ = operations
    alert_id = malware(client)
    response = client.post("/v1/incidents", headers=headers("analyst"),
                           json={"title": "Malware incident", "owner": "soc", "alert_ids": [alert_id]})
    assert response.status_code == 201
    job = request_job(client, alert_id, "analyst").json()
    assert client.post(f"/v1/playbooks/{job['id']}/approve", headers=headers("analyst")).status_code == 403
    assert client.post("/v1/enrollment-tokens", headers=headers("analyst"), json={"host": "new-host"}).status_code == 403
    assert client.put("/v1/agents/alpha/policy", headers=headers("analyst"), json={}).status_code == 403
    assert client.get("/v1/playbooks", headers=headers("analyst")).status_code == 200


def test_enrollment_is_single_use_hashed_and_rotation_revocation_persist(operations):
    client, store, cfg = operations
    issued = client.post("/v1/enrollment-tokens", headers=headers("admin-one"),
                         json={"host": "new-host", "policy": {"addresses": ["10.1.0.3"]}})
    assert issued.status_code == 201
    enrollment = issued.json()["enrollment_token"]
    assert client.get("/v1/agent/policy", headers=headers(enrollment)).status_code == 401
    enrolled = client.post("/v1/enroll", json={"token": enrollment})
    assert enrolled.status_code == 201
    credential = enrolled.json()["token"]
    assert client.post("/v1/enroll", json={"token": enrollment}).status_code == 401
    assert client.get("/v1/agent/policy", headers=headers(credential)).json()["host"] == "new-host"
    rotated = client.post("/v1/agents/new-host/rotate", headers=headers("admin-one")).json()["token"]
    assert client.get("/v1/agent/policy", headers=headers(credential)).status_code == 401
    assert client.get("/v1/agent/policy", headers=headers(rotated)).status_code == 200
    assert client.post("/v1/agents/new-host/revoke", headers=headers("admin-one")).status_code == 200
    assert client.get("/v1/agent/policy", headers=headers(rotated)).status_code == 401
    restarted = TestClient(create_app(cfg, Store(store.path)))
    assert restarted.get("/v1/agent/policy", headers=headers(rotated)).status_code == 401
    with store.connect() as db:
        dump = "\n".join(db.iterdump())
    assert enrollment not in dump and credential not in dump and rotated not in dump


def test_expired_enrollment_and_duplicate_addresses_are_rejected(operations):
    client, store, _ = operations
    assert client.post("/v1/enrollment-tokens", headers=headers("admin-one"),
                       json={"host": "duplicate", "policy": {"addresses": ["10.1.0.1"]}}).status_code == 409
    assert client.put("/v1/agents/bravo/policy", headers=headers("admin-one"),
                      json={"addresses": ["10.1.0.1"]}).status_code == 409
    issued = client.post("/v1/enrollment-tokens", headers=headers("admin-one"), json={"host": "expired"}).json()
    with store.connect() as db:
        db.execute("UPDATE enrollment_tokens SET expires=? WHERE host='expired'", (time.time() - 1,))
    assert client.post("/v1/enroll", json={"token": issued["enrollment_token"]}).status_code == 401


def test_revoked_seed_host_does_not_reactivate_on_restart(operations):
    client, store, cfg = operations
    assert client.post("/v1/agents/alpha/revoke", headers=headers("admin-one")).status_code == 200
    restarted = TestClient(create_app(cfg, Store(store.path)))
    assert restarted.get("/v1/agent/policy", headers=headers("alpha")).status_code == 401


def test_incident_version_prevents_lost_updates_and_preserves_timeline(operations):
    client, store, _ = operations
    alert_id = malware(client)
    response = client.post("/v1/incidents", headers=headers("analyst"),
                           json={"title": "Malware incident", "owner": "soc", "alert_ids": [alert_id, alert_id]})
    assert response.status_code == 201
    identifier = response.json()["id"]
    payload = {"version": 1, "status": "investigating", "owner": "responder", "note": "Reviewing malware evidence"}
    assert client.patch(f"/v1/incidents/{identifier}", headers=headers("analyst"), json=payload).json()["version"] == 2
    assert client.patch(f"/v1/incidents/{identifier}", headers=headers("admin-one"), json=payload).status_code == 409
    timeline = client.get(f"/v1/incidents/{identifier}/timeline", headers=headers("auditor")).json()
    assert len(timeline["notes"]) == 1 and len(timeline["alerts"]) == 1
    assert timeline["notes"][0]["actor"] == "analyst"
    with store.connect() as db:
        assert db.execute("SELECT owner FROM incidents WHERE id=?", (identifier,)).fetchone()[0] == "responder"


def test_incident_creation_rolls_back_if_any_alert_is_missing(operations):
    client, store, _ = operations
    alert_id = malware(client)
    response = client.post("/v1/incidents", headers=headers("analyst"),
                           json={"title": "Invalid incident", "owner": "soc", "alert_ids": [alert_id, 999999]})
    assert response.status_code == 404
    assert store.incident_list() == []


@pytest.mark.parametrize("changes", [
    {"duration_seconds": 59}, {"duration_seconds": 604801}, {"ip": "10.1.0.1; execute"},
    {"reason": "short"}, {"rule": ""},
])
def test_suppression_bounds(operations, changes):
    client, _, _ = operations
    payload = {"rule": "ssh_brute_force", "host": "alpha", "duration_seconds": 600,
               "reason": "Approved maintenance false positives"}
    payload.update(changes)
    assert client.post("/v1/suppressions", headers=headers("admin-one"), json=payload).status_code == 422


def test_suppression_is_host_ip_scoped_audited_and_revocable(operations):
    client, store, _ = operations
    store.connector_names = ["test-ticketing"]
    payload = {"rule": "ssh_brute_force", "host": "alpha", "ip": "10.8.0.9",
               "duration_seconds": 600, "reason": "Approved maintenance false positives"}
    assert client.post("/v1/suppressions", headers=headers("analyst"), json=payload).status_code == 403
    created = client.post("/v1/suppressions", headers=headers("admin-one"), json=payload)
    assert created.status_code == 201
    suppression_id = created.json()["id"]
    for host in ("alpha", "bravo"):
        assert ingest(client, [Event(kind="auth_failure", source_ip="10.8.0.9") for _ in range(5)], host).status_code == 200
    with store.connect() as db:
        suppressed = db.execute("SELECT a.host FROM alerts a JOIN suppressed_alerts s ON s.alert_id=a.id").fetchall()
        assert [row[0] for row in suppressed] == ["alpha"]
        assert db.execute("SELECT count(*) FROM deliveries").fetchone()[0] >= 1
        assert db.execute("SELECT subject FROM audit WHERE action='suppression_created'").fetchone()[0] == "admin-one"
    assert client.delete(f"/v1/suppressions/{suppression_id}", headers=headers("admin-one")).status_code == 200
    with store.connect() as db:
        assert db.execute("SELECT revoked FROM suppressions WHERE id=?", (suppression_id,)).fetchone()[0] == 1


def test_two_person_approval_and_host_scoped_idempotent_receipts(operations):
    client, _, _ = operations
    response = request_job(client, malware(client))
    assert response.status_code == 201
    identifier = response.json()["id"]
    receipt = {"status": "applied", "detail": "quarantined",
               "result": {"status": "applied", "detail": "quarantined", "request_id": identifier}}
    receipt_path = f"/v1/playbooks/{identifier}/receipt"
    assert client.post(receipt_path, headers=headers("alpha"), json=receipt).status_code == 409
    assert client.get("/v1/playbooks/commands", headers=headers("alpha")).json()["commands"] == []
    assert client.post(f"/v1/playbooks/{identifier}/approve", headers=headers("admin-one")).status_code == 403
    assert client.post(f"/v1/playbooks/{identifier}/approve", headers=headers("admin-two")).status_code == 200
    assert client.post(f"/v1/playbooks/{identifier}/approve", headers=headers("admin-two")).status_code == 409
    commands = client.get("/v1/playbooks/commands", headers=headers("alpha")).json()["commands"]
    assert [command["id"] for command in commands] == [identifier]
    assert client.get("/v1/playbooks/commands", headers=headers("bravo")).json()["commands"] == []
    assert client.post(receipt_path, headers=headers("bravo"), json=receipt).status_code == 404
    assert client.post(receipt_path, headers=headers("alpha"), json=receipt).status_code == 200
    assert client.post(receipt_path, headers=headers("alpha"), json=receipt).status_code == 200
    assert client.post(receipt_path, headers=headers("alpha"),
                       json={"status": "failed", "detail": "execution_failed", "result": {}}).status_code == 409
    assert client.get("/v1/playbooks/commands", headers=headers("alpha")).json()["commands"] == []


def test_expired_playbook_cannot_be_approved_or_delivered(operations):
    client, store, _ = operations
    identifier = request_job(client, malware(client)).json()["id"]
    with store.connect() as db:
        db.execute("UPDATE response_jobs SET expires=? WHERE id=?", (time.time() - 1, identifier))
    assert client.post(f"/v1/playbooks/{identifier}/approve", headers=headers("admin-two")).status_code == 409
    with store.connect() as db:
        db.execute("UPDATE response_jobs SET status='approved' WHERE id=?", (identifier,))
    assert client.get("/v1/playbooks/commands", headers=headers("alpha")).json()["commands"] == []


def test_reenrollment_cannot_inherit_old_approved_containment_jobs(operations):
    client, store, _ = operations
    identifier = request_job(client, malware(client)).json()["id"]
    assert client.post(f"/v1/playbooks/{identifier}/approve", headers=headers("admin-two")).status_code == 200
    assert client.post("/v1/agents/alpha/revoke", headers=headers("admin-one")).status_code == 200
    enrollment = client.post("/v1/enrollment-tokens", headers=headers("admin-one"), json={"host": "alpha"}).json()
    new_token = client.post("/v1/enroll", json={"token": enrollment["enrollment_token"]}).json()["token"]
    assert client.get("/v1/playbooks/commands", headers=headers(new_token)).json()["commands"] == []


def test_reenrollment_cancels_pending_blocks_and_clears_previous_health(operations):
    client, store, _ = operations
    ingest(client, [Event(kind="heartbeat", platform="linux", agent_version="old-agent")])
    with store.connect() as db:
        db.execute("UPDATE enrolled_hosts SET created=? WHERE host='alpha'", (time.time()-86400,))
        db.execute("INSERT INTO sensors VALUES('alpha','telemetry','ok','collected',?)", (time.time(),))
    response = ingest(client, [Event(kind="auth_failure", source_ip="10.8.0.9") for _ in range(5)])
    alert_id = response.json()["alerts"][0]["id"]
    block = client.post("/v1/blocks", headers=headers("analyst"),
                        json={"alert_id": alert_id, "reason": "Investigated brute force source"})
    assert block.status_code == 201
    assert client.post("/v1/agents/alpha/revoke", headers=headers("admin-one")).status_code == 200
    issued = client.post("/v1/enrollment-tokens", headers=headers("admin-one"), json={"host": "alpha"}).json()
    credential = client.post("/v1/enroll", json={"token": issued["enrollment_token"]}).json()["token"]
    assert client.get("/v1/commands", headers=headers(credential)).json()["commands"] == []
    host = next(h for h in client.get("/v1/hosts", headers=headers("viewer")).json()["hosts"] if h["host"] == "alpha")
    assert host["last_seen"] is None and host["metadata"] == {} and host["stale"]
    assert host['sensors'] == []
    with store.connect() as db:
        assert time.time()-db.execute("SELECT created FROM enrolled_hosts WHERE host='alpha'").fetchone()[0] < 60
    assert client.post(f"/v1/commands/{block.json()['command_id']}/receipt", headers=headers(credential),
                       json={"status": "applied", "detail": "blocked"}).status_code == 409


def test_playbook_receipt_status_must_match_action_and_detail(operations):
    client, store, _ = operations
    identifier = request_job(client, malware(client)).json()["id"]
    assert client.post(f"/v1/playbooks/{identifier}/approve", headers=headers("admin-two")).status_code == 200
    path = f"/v1/playbooks/{identifier}/receipt"
    for invalid in (
        {"status": "rolled_back", "detail": "restored", "result": {}},
        {"status": "applied", "detail": "policy_denied", "result": {}},
        {"status": "failed", "detail": "quarantined", "result": {}},
    ):
        assert client.post(path, headers=headers("alpha"), json=invalid).status_code == 422
    receipt = {"status": "applied", "detail": "quarantined", "result": {"request_id": identifier}}
    assert client.post(path, headers=headers("alpha"), json=receipt).status_code == 200
    with store.connect() as db:
        result = json.loads(db.execute("SELECT result FROM response_jobs WHERE id=?", (identifier,)).fetchone()[0])
    assert result["detail"] == "quarantined"


def test_expired_suppression_does_not_hide_or_discard_new_alert(operations):
    client, store, _ = operations
    response = client.post("/v1/suppressions", headers=headers("admin-one"), json={
        "rule": "ssh_brute_force", "host": "alpha", "duration_seconds": 600,
        "reason": "Maintenance interval is complete"})
    assert response.status_code == 201
    with store.connect() as db:
        db.execute("UPDATE suppressions SET expires=?", (time.time() - 1,))
    alert = ingest(client, [Event(kind="auth_failure", source_ip="10.8.0.9") for _ in range(5)]).json()["alerts"][0]
    with store.connect() as db:
        assert db.execute("SELECT 1 FROM suppressed_alerts WHERE alert_id=?", (alert["id"],)).fetchone() is None
        assert db.execute("SELECT id FROM alerts WHERE id=?", (alert["id"],)).fetchone() is not None


def test_policy_changes_are_versioned_without_exposing_credentials(operations):
    client, store, _ = operations
    policy = {"addresses": ["10.1.0.1"], "desired_version": "0.3.0"}
    response = client.put("/v1/agents/alpha/policy", headers=headers("admin-one"), json=policy)
    assert response.status_code == 200
    assert response.json()["version"] >= 1
    fetched = client.get("/v1/agent/policy", headers=headers("alpha")).json()
    assert fetched["policy"]["desired_version"] == "0.3.0" and "token" not in fetched["policy"]
    overview = client.get("/v1/overview", headers=headers("viewer"))
    assert overview.status_code == 200
    assert all(value not in overview.text for value in TOKENS.values())
    with store.connect() as db:
        row = db.execute("SELECT host,actor FROM policy_history WHERE id=?", (response.json()["version"],)).fetchone()
    assert tuple(row) == ("alpha", "admin-one")


def test_applied_containment_can_be_rolled_back_after_original_alert_ages(operations):
    client, store, _ = operations
    alert_id = malware(client)
    identifier = request_job(client, alert_id).json()["id"]
    with store.connect() as db:
        db.execute("UPDATE response_jobs SET status='applied' WHERE id=?", (identifier,))
        db.execute("UPDATE alerts SET created=? WHERE id=?", (time.time() - 7200, alert_id))
    response = request_job(client, alert_id, action="restore_file", previous_job_id=identifier)
    assert response.status_code == 201, response.text


def test_archived_events_do_not_trigger_fresh_detection_or_refresh_host_health(operations):
    client, store, _ = operations
    old = datetime.now(timezone.utc) - timedelta(hours=1)
    events = [Event(kind="auth_failure", source_ip="10.9.0.1", occurred_at=old) for _ in range(5)]
    events.append(Event(kind="heartbeat", occurred_at=old, platform="linux", agent_version="old"))
    response = ingest(client, events)
    assert response.status_code == 200
    assert response.json()["alerts"] == [] and response.json()["archived"] == 6
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 6
        assert db.execute("SELECT last_seen FROM enrolled_hosts WHERE host='alpha'").fetchone()[0] is None
    fresh = ingest(client, [Event(kind="auth_failure", source_ip="10.9.0.1")])
    assert fresh.json()["alerts"] == []


def test_legacy_event_schema_retries_are_normalized_without_new_detection(operations):
    client, store, _ = operations
    event = Event(kind="heartbeat")
    assert ingest(client, [event]).status_code == 200
    with store.connect() as db:
        row = db.execute("SELECT payload FROM events WHERE id=?", (str(event.event_id),)).fetchone()
        old_payload = json.loads(row[0])
        for field in ("agent_version", "platform", "hostname", "queue_depth", "queue_capacity", "collection_paused", "telemetry_source"):
            old_payload.pop(field)
        db.execute("UPDATE events SET payload=? WHERE id=?", (json.dumps(old_payload), str(event.event_id)))
    response = ingest(client, [event])
    assert response.status_code == 200 and response.json()["alerts"] == []
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 1


def test_sso_operator_tenant_role_and_no_bootstrap_fallback(tmp_path):
    pytest.importorskip("jose")
    from jose import jwk, jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = jwk.construct(private.public_key(), "RS256").to_dict()
    public["kid"] = "test-key"
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps({"keys": [public]}))
    tenant = str(uuid4())
    cfg = {"operator_token": "bootstrap-secret" * 4, "organisation_id": tenant, "hosts": {},
           "operator_auth": {"oidc_issuer": "https://identity.example.org", "jwks_path": str(path)}}
    client = TestClient(create_app(cfg, Store(str(tmp_path / "sso.sqlite"))))
    def credential(**overrides):
        now = int(time.time())
        claims = {"sub": "auditor-123", "roles": ["auditor"], "tenant_id": tenant,
                  "iss": "https://identity.example.org", "aud": "vulnsuite-api", "iat": now, "exp": now + 300}
        claims.update(overrides)
        return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "test-key"})
    assert client.get("/v1/me", headers=headers(credential())).json()["sub"] == "auditor-123"
    assert client.post("/v1/enrollment-tokens", headers=headers(credential()), json={"host": "host"}).status_code == 403
    assert client.get("/v1/me", headers=headers(credential(tenant_id=str(uuid4())))).status_code == 401
    assert client.get("/v1/me", headers=headers(cfg["operator_token"])).status_code == 401
    assert client.post("/v1/enrollment-tokens", headers=headers(credential(roles=["admin"])), json={"host": "host"}).status_code == 201


def test_console_csp_and_no_credential_persistence(operations):
    client, _, _ = operations
    response = client.get("/console")
    assert response.status_code == 200
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    script = client.get("/console.js").text
    assert "innerHTML" not in script and "localStorage" not in script and "sessionStorage" not in script
    assert ".textContent" in script
