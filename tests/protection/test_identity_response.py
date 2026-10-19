"""Entra ID identity response: UPN policy, Graph calls, the approval workflow and the
durable worker. Graph and the token endpoint are mocked; nothing contacts Microsoft."""
import json
import time
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from vulnsuite.protection.integrations import EntraIDConnector, IntegrationError, normalise_upn
from vulnsuite.protection.models import Event
from vulnsuite.protection.response_worker import process_responses
from vulnsuite.protection.service import create_app
from vulnsuite.protection.store import Store

TENANT = '11111111-2222-3333-4444-555555555555'
CLIENT = '66666666-7777-8888-9999-aaaaaaaaaaaa'
OBJECT = 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff'
KEYS = {'requester': 'r' * 40, 'approver': 'a' * 40, 'host': 'h' * 40}


def config(**overrides):
    return {'enabled': True, 'provider': 'entra_id', 'tenant_id': TENANT, 'client_id': CLIENT,
            'client_secret_env': 'VS_TEST_ENTRA_SECRET', 'allowed_domains': ['corp.example'],
            'protected_users': ['breakglass@corp.example'], 'upn_domain': 'corp.example', **overrides}


class FakeGraph:
    """Minimal token endpoint plus /users behaviour with a mutable account state."""

    def __init__(self, enabled=True):
        self.enabled, self.requests = enabled, []

    def __call__(self, request):
        self.requests.append(request)
        if request.url.host == 'login.microsoftonline.com':
            assert b'client_credentials' in request.content and b'client_secret=' in request.content
            return httpx.Response(200, json={'access_token': 'tok', 'token_type': 'Bearer'})
        assert request.url.host == 'graph.microsoft.com'
        assert request.headers['Authorization'] == 'Bearer tok'
        if request.method == 'GET':
            return httpx.Response(200, json={'id': OBJECT, 'userPrincipalName': 'Alice@corp.example',
                                             'accountEnabled': self.enabled})
        if request.method == 'POST' and request.url.path.endswith('/revokeSignInSessions'):
            return httpx.Response(200, json={'value': True})
        if request.method == 'PATCH':
            self.enabled = json.loads(request.content)['accountEnabled']
            return httpx.Response(204)
        return httpx.Response(404, json={'error': 'unexpected'})


@pytest.fixture(autouse=True)
def secret(monkeypatch):
    monkeypatch.setenv('VS_TEST_ENTRA_SECRET', 's' * 40)


def test_user_principal_normalisation_and_policy():
    assert normalise_upn('CORP\\Alice', 'corp.example') == 'alice@corp.example'
    assert normalise_upn('alice@Corp.Example', None) == 'alice@corp.example'
    for bad in ('alice', 'a b@corp.example', '', 'x' * 400):
        with pytest.raises(ValueError):
            normalise_upn(bad, None)
    connector = EntraIDConnector(config())
    plan = connector.prepare('identity_disable_account', 'CORP\\alice', 600, uuid4().hex, now=1_700_000_000)
    assert plan['user'] == 'alice@corp.example' and plan['expires_at'] == 1_700_000_600
    assert plan['provider'] == 'entra_id' and plan['tenant_id'] == TENANT
    for user in ('breakglass@corp.example', 'bob@other.example'):
        with pytest.raises(ValueError):
            connector.prepare('identity_revoke_sessions', user, 600, uuid4().hex)
    with pytest.raises(ValueError):
        connector.prepare('identity_disable_account', 'alice', 30, uuid4().hex)
    with pytest.raises(ValueError):
        connector.prepare('delete_account', 'alice', 600, uuid4().hex)
    for broken in (config(tenant_id='nope'), config(allowed_domains=[]), config(client_secret_env='MISSING_ENV')):
        with pytest.raises(ValueError):
            EntraIDConnector(broken)


def test_disable_then_reenable_through_graph():
    graph = FakeGraph()
    connector = EntraIDConnector(config(), transport=httpx.MockTransport(graph))
    plan = connector.prepare('identity_disable_account', 'alice', 600, uuid4().hex)
    result = connector.apply(plan)
    assert result['status'] == 'applied' and result['detail'] == 'account_disabled'
    assert result['object_id'] == OBJECT and graph.enabled is False
    methods = [(r.method, r.url.path) for r in graph.requests]
    assert methods[0][0] == 'POST' and methods[0][1].endswith('/oauth2/v2.0/token')
    assert ('PATCH', f'/v1.0/users/{OBJECT}') in methods
    # Already disabled by someone else: do not claim ownership.
    with pytest.raises(IntegrationError) as refused:
        connector.apply(plan)
    assert refused.value.code == 'account_already_disabled'
    rolled = connector.rollback(plan)
    assert rolled['status'] == 'rolled_back' and rolled['detail'] == 'account_enabled' and graph.enabled is True
    # Rolling back an enabled account is idempotent and does not PATCH again.
    before = len(graph.requests)
    connector.rollback(plan)
    assert [r.method for r in graph.requests[before:]] == ['POST', 'GET']


def test_revoke_sessions_is_one_shot_and_scope_is_pinned():
    graph = FakeGraph()
    connector = EntraIDConnector(config(), transport=httpx.MockTransport(graph))
    plan = connector.prepare('identity_revoke_sessions', 'alice@corp.example', 300, uuid4().hex)
    assert connector.apply(plan)['detail'] == 'sessions_revoked'
    assert any(r.method == 'POST' and r.url.path.endswith('/revokeSignInSessions') for r in graph.requests)
    assert connector.rollback(plan)['detail'] == 'nothing_to_rollback'
    other = EntraIDConnector(config(tenant_id=CLIENT), transport=httpx.MockTransport(graph))
    with pytest.raises(IntegrationError) as mismatch:
        other.apply(plan)
    assert mismatch.value.code == 'scope_mismatch'
    with pytest.raises(IntegrationError):
        connector.apply({**plan, 'user': 'breakglass@corp.example'})
    with pytest.raises(IntegrationError):
        connector.apply({**plan, 'ref': 'vulnsuite_' + 'f' * 32})
    expired = connector.prepare('identity_revoke_sessions', 'alice', 60, uuid4().hex, now=time.time() - 120)
    with pytest.raises(IntegrationError) as late:
        connector.apply(expired)
    assert late.value.code == 'plan_expired'


def test_graph_errors_are_categorised_without_leaking_bodies():
    def failing(request):
        if request.url.host == 'login.microsoftonline.com':
            return httpx.Response(200, json={'access_token': 'tok'})
        return httpx.Response(503, json={'error': {'message': 'secret details'}})
    connector = EntraIDConnector(config(), transport=httpx.MockTransport(failing))
    plan = connector.prepare('identity_revoke_sessions', 'alice', 300, uuid4().hex)
    with pytest.raises(IntegrationError) as unavailable:
        connector.apply(plan)
    assert unavailable.value.code == 'upstream_unavailable' and unavailable.value.retryable

    def wrong_user(request):
        if request.url.host == 'login.microsoftonline.com':
            return httpx.Response(200, json={'access_token': 'tok'})
        return httpx.Response(200, json={'id': OBJECT, 'userPrincipalName': 'mallory@corp.example'})
    connector = EntraIDConnector(config(), transport=httpx.MockTransport(wrong_user))
    with pytest.raises(IntegrationError) as mismatch:
        connector.apply(plan)
    assert mismatch.value.code in ('scope_mismatch', 'invalid_upstream_response')


# ---------- API + worker ----------

def auth(actor):
    return {'Authorization': 'Bearer ' + KEYS[actor]}


@pytest.fixture
def system(tmp_path):
    cfg = {'operators': {actor: {'token': KEYS[actor], 'roles': ['admin']} for actor in ('requester', 'approver')},
           'hosts': {'dc-1': {'token': KEYS['host'], 'addresses': ['10.10.0.10']}},
           'response': {'identity': config()}}
    store = Store(str(tmp_path / 'control.sqlite'))
    client = TestClient(create_app(cfg, store), headers=auth('host'))
    return {'client': client, 'store': store, 'config': cfg}


_SOURCES = iter(range(1, 250))


def brute_force_alert(system, user='CORP\\alice'):
    # A fresh source address per call: same-IP alerts are deduplicated for five minutes.
    source = f'203.0.113.{next(_SOURCES)}'
    events = [Event(kind='auth_failure', source_ip=source, user=user, protocol='rdp',
                    telemetry_source='windows_security') for _ in range(5)]
    response = system['client'].post('/v1/events', json={'events': [e.model_dump(mode='json') for e in events]})
    assert response.status_code == 200, response.text
    alerts = response.json()['alerts']
    assert alerts and alerts[0]['rule'] == 'remote_auth_brute_force'
    return alerts[0]['id']


def request(system, alert_id, action, duration=600):
    return system['client'].post('/v1/playbooks', headers=auth('requester'), json={
        'alert_id': alert_id, 'action': action, 'duration_seconds': duration,
        'reason': 'Password spraying against this account from an unknown address'})


def job(system, identifier):
    with system['store'].connect() as db:
        return dict(db.execute('SELECT * FROM response_jobs WHERE id=?', (identifier,)).fetchone())


def test_disable_account_approved_applied_and_reenabled_at_expiry(system):
    alert_id = brute_force_alert(system)
    created = request(system, alert_id, 'identity_disable_account')
    assert created.status_code == 201, created.text
    plan = created.json()['plan']
    assert plan['user'] == 'alice@corp.example' and plan['action'] == 'identity_disable_account'
    assert 'platform' not in plan and created.json()['expires_at'] == plan['expires_at']
    graph = FakeGraph()
    transport = httpx.MockTransport(graph)
    # Nothing happens before approval; the host agent never sees identity jobs.
    assert process_responses(system['store'], system['config'], transport=transport)['applied'] == 0
    assert system['client'].get('/v1/playbooks/commands').json()['commands'] == []
    assert system['client'].post(f"/v1/playbooks/{created.json()['id']}/approve", headers=auth('requester')).status_code == 403
    assert system['client'].post(f"/v1/playbooks/{created.json()['id']}/approve", headers=auth('approver')).status_code == 200
    assert process_responses(system['store'], system['config'], transport=transport)['applied'] == 1
    row = job(system, created.json()['id'])
    assert row['status'] == 'applied' and json.loads(row['result'])['detail'] == 'account_disabled'
    assert graph.enabled is False
    # Still within the window: no rollback yet.
    assert process_responses(system['store'], system['config'], transport=transport)['rolled_back'] == 0
    with system['store'].connect() as db:
        db.execute('UPDATE response_jobs SET expires=? WHERE id=?', (time.time() - 1, row['id']))
    assert process_responses(system['store'], system['config'], transport=transport)['rolled_back'] == 1
    assert job(system, row['id'])['status'] == 'rolled_back' and graph.enabled is True
    with system['store'].connect() as db:
        actions = [r[0] for r in db.execute("SELECT action FROM audit WHERE action='identity_response'")]
    assert len(actions) == 2


def test_revoke_sessions_applies_once_and_never_rolls_back(system):
    created = request(system, brute_force_alert(system), 'identity_revoke_sessions').json()
    system['client'].post(f"/v1/playbooks/{created['id']}/approve", headers=auth('approver'))
    graph = FakeGraph()
    transport = httpx.MockTransport(graph)
    assert process_responses(system['store'], system['config'], transport=transport)['applied'] == 1
    with system['store'].connect() as db:
        db.execute('UPDATE response_jobs SET expires=? WHERE id=?', (time.time() - 1, created['id']))
    counts = process_responses(system['store'], system['config'], transport=transport)
    assert counts['rolled_back'] == 0 and counts['rollback_failed'] == 0
    assert job(system, created['id'])['status'] == 'applied'
    assert sum(r.method == 'POST' and 'revoke' in r.url.path for r in graph.requests) == 1


def test_policy_gates_on_request(system):
    # Protected and foreign-domain users are refused by server-side policy.
    assert request(system, brute_force_alert(system, 'CORP\\breakglass'), 'identity_disable_account').status_code == 403
    assert request(system, brute_force_alert(system, 'bob@other.example'), 'identity_revoke_sessions').status_code == 403
    # Alerts without user evidence cannot drive an identity action.
    response = system['client'].post('/v1/events', json={'events': [
        Event(kind='api_denied', source_ip='198.51.100.7').model_dump(mode='json') for _ in range(20)]})
    api_alert = response.json()['alerts'][0]['id']
    assert request(system, api_alert, 'identity_revoke_sessions').status_code == 409
    # Disabled connector refuses new plans; expired approvals are not sent to the provider.
    system['config']['response']['identity']['enabled'] = False
    assert request(system, brute_force_alert(system), 'identity_revoke_sessions').status_code == 403
    system['config']['response']['identity']['enabled'] = True
    created = request(system, brute_force_alert(system, 'CORP\\carol'), 'identity_revoke_sessions').json()
    system['client'].post(f"/v1/playbooks/{created['id']}/approve", headers=auth('approver'))
    with system['store'].connect() as db:
        db.execute('UPDATE response_jobs SET expires=? WHERE id=?', (time.time() - 1, created['id']))
    seen = []
    process_responses(system['store'], system['config'],
                      transport=httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(500)))
    assert not seen and job(system, created['id'])['status'] == 'expired'


def test_agent_revocation_expires_outstanding_identity_jobs(system):
    created = request(system, brute_force_alert(system), 'identity_disable_account').json()
    system['client'].post(f"/v1/playbooks/{created['id']}/approve", headers=auth('approver'))
    graph = FakeGraph()
    transport = httpx.MockTransport(graph)
    process_responses(system['store'], system['config'], transport=transport)
    assert graph.enabled is False
    assert system['client'].post('/v1/agents/dc-1/revoke', headers=auth('requester')).status_code == 200
    assert process_responses(system['store'], system['config'], transport=transport)['rolled_back'] == 1
    assert graph.enabled is True
