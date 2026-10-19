import hashlib
import hmac
import json
import time
from uuid import uuid4

import httpx
import pytest

from vulnsuite.protection.integrations import CloudflareWAFConnector, IntegrationError, WebhookConnector
from vulnsuite.protection.response_worker import deliver_pending, process_responses
from vulnsuite.protection.store import Store


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.setenv('VS_WEBHOOK_TOKEN', 't' * 40)
    monkeypatch.setenv('VS_WEBHOOK_SIGNING', 's' * 40)
    monkeypatch.setenv('VS_CLOUDFLARE_TOKEN', 'c' * 40)
    return {'integrations': {'soc': {'enabled': True, 'type': 'webhook',
            'url': 'https://siem.example.test/ingest', 'token_env': 'VS_WEBHOOK_TOKEN',
            'signing_key_env': 'VS_WEBHOOK_SIGNING'}},
            'response': {'cloud_waf': {'enabled': True, 'zone_id': 'a' * 32,
            'ruleset_id': 'b' * 32, 'token_env': 'VS_CLOUDFLARE_TOKEN',
            'protected_networks': ['10.0.0.0/8'], 'permitted_networks': ['0.0.0.0/0', '::/0']}}}


def cloud_transport(settings):
    rules, calls = [], []
    def handle(request):
        calls.append(request)
        assert request.url.host == 'api.cloudflare.com'
        assert request.headers['Authorization'] == 'Bearer ' + 'c' * 40
        if request.method == 'POST':
            item = json.loads(request.content)
            rules.append({**item, 'id': 'd' * 32})
        elif request.method == 'DELETE':
            rules.clear()
        return httpx.Response(200, json={'success': True, 'result': {
            'id': 'b' * 32, 'kind': 'zone', 'phase': 'http_request_firewall_custom',
            'rules': rules}})
    return httpx.MockTransport(handle), rules, calls


def test_webhook_signed_idempotent_request(settings):
    seen = []
    def handle(request):
        seen.append(request)
        return httpx.Response(202)
    identifier = uuid4().hex
    connector = WebhookConnector(settings['integrations']['soc'], transport=httpx.MockTransport(handle))
    assert connector.deliver({'type': 'security.alert', 'id': 1}, identifier)['status'] == 'delivered'
    request = seen[0]
    signed = request.headers['X-VulnSuite-Timestamp'].encode() + b'.' + request.content
    assert request.headers['X-VulnSuite-Signature'] == 'v1=' + hmac.new(b's' * 40, signed, hashlib.sha256).hexdigest()
    assert request.headers['Idempotency-Key'] == identifier
    assert request.headers['Authorization'] == 'Bearer ' + 't' * 40


@pytest.mark.parametrize('url', ['http://siem.test/', 'https://user:pass@siem.test/',
                                 'https://siem.test/?token=x', 'https://siem.test/#fragment'])
def test_webhook_rejects_unsafe_url(settings, url):
    settings['integrations']['soc']['url'] = url
    with pytest.raises(ValueError):
        WebhookConnector(settings['integrations']['soc'])


def test_webhook_redirect_does_not_forward_secrets(settings):
    seen = []
    def handle(request):
        seen.append(request)
        return httpx.Response(307, headers={'Location': 'https://other.test/'})
    connector = WebhookConnector(settings['integrations']['soc'], transport=httpx.MockTransport(handle))
    with pytest.raises(IntegrationError, match='upstream_rejected'):
        connector.deliver({'id': 1}, uuid4().hex)
    assert len(seen) == 1


def test_cloud_rule_retry_expiry_and_rollback(settings):
    transport, rules, calls = cloud_transport(settings)
    connector = CloudflareWAFConnector(settings['response']['cloud_waf'], transport=transport)
    plan = connector.prepare_block('8.8.4.4', 60, uuid4().hex)
    first = connector.apply(plan)
    assert connector.apply(plan) == first
    assert sum(r.method == 'POST' for r in calls) == 1
    assert f'http.request.timestamp.sec lt {plan["expires_at"]}' in rules[0]['expression']
    assert connector.rollback(plan)['status'] == 'rolled_back'
    assert connector.rollback(plan)['status'] == 'rolled_back'
    assert not rules


def test_cloud_policy_scope_and_expired_plan(settings):
    connector = CloudflareWAFConnector(settings['response']['cloud_waf'])
    with pytest.raises(ValueError):
        connector.prepare_block('10.1.1.1', 60, uuid4().hex)
    with pytest.raises(ValueError):
        connector.prepare_block('8.8.8.8', 3601, uuid4().hex)
    plan = connector.prepare_block('8.8.8.8', 60, uuid4().hex, now=time.time() - 61)
    with pytest.raises(IntegrationError, match='plan_expired'):
        connector.apply(plan)
    plan['zone_id'] = 'e' * 32
    with pytest.raises(IntegrationError, match='scope_mismatch'):
        connector.rollback(plan)


def test_cloud_external_edit_is_never_overwritten(settings):
    transport, rules, _ = cloud_transport(settings)
    connector = CloudflareWAFConnector(settings['response']['cloud_waf'], transport=transport)
    plan = connector.prepare_block('8.8.8.8', 60, uuid4().hex)
    connector.apply(plan)
    rules[0]['expression'] = 'true'
    with pytest.raises(IntegrationError, match='rule_changed_externally'):
        connector.rollback(plan)
    assert rules


def test_durable_webhook_retry_survives_store_restart(settings, tmp_path):
    store = Store(str(tmp_path / 'state.db'))
    store.connector_names = ['soc']
    with store.connect() as db:
        store.queue_notifications(db, 'security.alert', {'id': 1})
    seen = []
    def unavailable(request):
        seen.append(request.headers['Idempotency-Key'])
        return httpx.Response(503, text='secret upstream failure')
    assert deliver_pending(store, settings, transport=httpx.MockTransport(unavailable))['retry'] == 1
    with store.connect() as db:
        row = db.execute('SELECT * FROM deliveries').fetchone()
        assert row['last_error'] == 'upstream_unavailable'
        db.execute('UPDATE deliveries SET next_attempt=0')
    def recovered(request):
        seen.append(request.headers['Idempotency-Key'])
        return httpx.Response(204)
    restarted = Store(store.path)
    assert deliver_pending(restarted, settings, transport=httpx.MockTransport(recovered))['delivered'] == 1
    assert seen[0] == seen[1]
    with store.connect() as db:
        assert db.execute('SELECT attempts FROM deliveries').fetchone()[0] == 2


def test_stale_delivery_lease_reclaimed(settings, tmp_path):
    store = Store(str(tmp_path / 'state.db'))
    store.connector_names = ['soc']
    with store.connect() as db:
        store.queue_notifications(db, 'security.alert', {'id': 1})
        db.execute("UPDATE deliveries SET status='sending',lease_until=?", (time.time() + 60,))
    transport = httpx.MockTransport(lambda request: httpx.Response(204))
    assert deliver_pending(store, settings, transport=transport)['delivered'] == 0
    with store.connect() as db:
        db.execute('UPDATE deliveries SET lease_until=0')
    assert deliver_pending(store, settings, transport=transport)['delivered'] == 1


def test_cloud_worker_expiration_cleanup_retries(settings, tmp_path, monkeypatch):
    store = Store(str(tmp_path / 'state.db'))
    transport, rules, _ = cloud_transport(settings)
    connector = CloudflareWAFConnector(settings['response']['cloud_waf'])
    start = int(time.time())
    identifier = uuid4().hex
    plan = connector.prepare_block('8.8.8.8', 60, identifier, now=start)
    with store.connect() as db:
        db.execute("INSERT INTO response_jobs(id,host,action,alert_id,plan,status,requested_by,approved_by,created,expires) "
                   "VALUES(?, 'server-a', 'cloud_waf_block', 1, ?, 'approved', 'alice', 'bob', ?, ?)",
                   (identifier, json.dumps(plan), start, plan['expires_at']))
    assert process_responses(store, settings, transport=transport)['applied'] == 1
    monkeypatch.setattr('vulnsuite.protection.response_worker.time.time', lambda: start + 61)
    outage = httpx.MockTransport(lambda request: httpx.Response(503))
    assert process_responses(store, settings, transport=outage)['rollback_failed'] == 1
    assert f'lt {start + 60}' in rules[0]['expression']  # Edge expiry survives cleanup outage.
    settings['response']['cloud_waf']['enabled'] = False
    with store.connect() as db:
        db.execute('UPDATE response_jobs SET next_attempt=0')
    assert process_responses(Store(store.path), settings, transport=transport)['rolled_back'] == 1
    assert not rules
