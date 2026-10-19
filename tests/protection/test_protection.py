import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from vulnsuite.protection.agent import collect, cycle, fingerprint, parse_line, respond
from vulnsuite.protection.models import Event
from vulnsuite.protection.response import allowed_ip, block_ip
from vulnsuite.protection.service import create_app
from vulnsuite.protection.store import Store


@pytest.fixture
def system(tmp_path):
    store = Store(str(tmp_path / 'events.db'))
    cfg = {'operator_token': 'o' * 40, 'hosts': {
        'a': {'token': 'a' * 40, 'allow_response': True, 'protected_networks': ['10.0.0.0/24'],
              'permitted_networks': ['10.0.0.0/8']}, 'b': {'token': 'b' * 40}}}
    return TestClient(create_app(cfg, store)), store


def auth(key):
    return {'Authorization': f'Bearer {key * 40}'}


def failures(ip='10.1.1.9'):
    return [Event(kind='auth_failure', source_ip=ip) for _ in range(5)]


def send(client, events, key='a'):
    return client.post('/v1/events', headers=auth(key),
                       json={'events': [e.model_dump(mode='json') for e in events]})


def test_correlation_retry_restart(system):
    client, store = system
    events = failures()
    assert send(client, events).status_code == 200
    assert send(client, events).json()['alerts'] == []
    assert len(Store(store.path).list_alerts()) == 1
    result = send(client, [Event(kind='auth_success', source_ip='10.1.1.9')])
    assert result.json()['alerts'][0]['rule'] == 'login_after_brute_force'


def test_out_of_order_host_isolation(system):
    client, store = system
    success = Event(kind='auth_success', source_ip='10.1.1.9')
    send(client, [success])
    earlier = [Event(kind='auth_failure', source_ip='10.1.1.9',
                     occurred_at=success.occurred_at - timedelta(seconds=2)) for _ in range(5)]
    send(client, earlier, 'b')
    assert all(a['rule'] != 'login_after_brute_force' for a in store.list_alerts())
    send(client, earlier)
    assert any(a['rule'] == 'login_after_brute_force' for a in store.list_alerts())


def test_authorization_response_lifecycle(system):
    client, store = system
    assert client.get('/v1/alerts').status_code == 401
    assert client.get('/v1/alerts', headers=auth('a')).status_code == 403
    assert send(client, failures(), 'o').status_code == 401
    send(client, failures())
    payload = {'alert_id': store.list_alerts()[0]['id'], 'duration_seconds': 60,
               'reason': 'Investigated brute force'}
    assert client.post('/v1/blocks', headers=auth('a'), json=payload).status_code == 403
    queued = client.post('/v1/blocks', headers=auth('o'), json=payload)
    assert queued.status_code == 201
    assert client.post('/v1/blocks', headers=auth('o'), json=payload).status_code == 409
    assert client.get('/v1/commands', headers=auth('b')).json()['commands'] == []
    url = f"/v1/commands/{queued.json()['command_id']}/receipt"
    receipt = {'status': 'applied', 'detail': 'blocked'}
    assert client.post(url, headers=auth('b'), json=receipt).status_code == 404
    assert client.post(url, headers=auth('a'), json=receipt).status_code == 200
    assert client.post(url, headers=auth('a'), json=receipt).status_code == 200
    assert client.get('/v1/commands', headers=auth('a')).json()['commands'] == []
    assert client.get('/v1/responses', headers=auth('o')).json()['responses'][0]['status'] == 'applied'


def test_response_denied(system):
    client, store = system
    send(client, failures('10.0.0.8'))
    payload = {'alert_id': store.list_alerts()[0]['id'], 'reason': 'Investigated source address'}
    assert client.post('/v1/blocks', headers=auth('o'), json=payload).status_code == 403
    send(client, failures(), 'b')
    payload['alert_id'] = store.list_alerts()[0]['id']
    assert client.post('/v1/blocks', headers=auth('o'), json=payload).status_code == 403


def test_validation_and_transaction_rollback(system):
    client, store = system
    valid = Event(kind='heartbeat')
    old = Event(kind='heartbeat', occurred_at=datetime.now(timezone.utc) - timedelta(days=8))
    assert send(client, [valid, old]).status_code == 422
    with store.connect() as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 0
    send(client, [valid])
    assert send(client, [valid.model_copy(update={'kind': 'auth_failure'})]).status_code == 422
    assert client.post('/v1/events', headers=auth('a'), content=b'x' * 262145).status_code == 413
    assert client.post('/v1/events', headers=auth('a'), json={'events': [{'kind': 'heartbeat', 'host': 'spoof'}]}).status_code == 422


def test_api_file_and_health(system):
    client, store = system
    send(client, [Event(kind='api_denied', source_ip='10.1.1.9') for _ in range(20)])
    send(client, [Event(kind='file_change', path='/etc/passwd', change='modified')])
    assert {a['rule'] for a in store.list_alerts()} == {'api_access_abuse', 'file_integrity_change'}
    hosts = client.get('/v1/hosts', headers=auth('o')).json()['hosts']
    assert not hosts[0]['stale'] and hosts[1]['stale']


def test_parser_and_file_monitor(tmp_path):
    assert parse_line('sshd: Failed password for invalid user bob from 10.1.2.3 port 22', 'ssh')['kind'] == 'auth_failure'
    assert parse_line('sshd: Accepted publickey for bob from 2001:4860::1 port 22', 'ssh')['kind'] == 'auth_success'
    assert parse_line('{"status":403,"remote_addr":"10.1.2.3","authorization":"secret"}', 'api') == {'kind': 'api_denied', 'source_ip': '10.1.2.3'}
    log, watched = tmp_path / 'auth.log', tmp_path / 'config'
    log.write_text('historical log\n')
    watched.write_text('original')
    cfg = {'logs': [{'path': str(log), 'kind': 'ssh'}], 'watch_files': [str(watched)]}
    state = {}
    collect(cfg, state)
    log.write_text(log.read_text() + 'sshd: Failed password for bob from 10.1.2.3 port 22\n')
    watched.write_text('changed')
    collect(cfg, state)
    assert {e['kind'] for e in state['outbox']} == {'heartbeat', 'auth_failure', 'file_change', 'sensor_status'}
    watched.unlink()
    collect(cfg, state)
    assert any(e.get('change') == 'deleted' for e in state['outbox'])
    watched.symlink_to(log)
    with pytest.raises(OSError):
        fingerprint(str(watched))


def test_firewall_policy():
    for ip in ('127.0.0.1', '169.254.1.1', '224.0.0.1', '10.0.0.7', '8.8.8.8', '10.2.3.4; reboot'):
        with pytest.raises(ValueError):
            allowed_ip(ip, ['10.0.0.0/24'], ['10.0.0.0/8'])
    with patch('vulnsuite.protection.response.subprocess.run') as run:
        block_ip('10.2.3.4', 60, ['10.0.0.0/24'], ['10.0.0.0/8'])
        assert run.call_args.args[0][-3:] == ['timeout', '60s', '}']
        assert 'shell' not in run.call_args.kwargs
    assert respond({'ip': '10.2.3.4', 'duration': 60, 'created': time.time()}, {})['detail'] == 'policy_denied'


def test_durable_delivery(tmp_path):
    path = tmp_path / 'state.json'
    calls = []
    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={'commands': [], 'accepted': len(json.loads(request.content)['events'])} if request.method == 'POST' else {'commands': []})
    with httpx.Client(base_url='https://protection.test', transport=httpx.MockTransport(handler)) as client:
        cycle({}, {}, path, client)
    assert json.loads(path.read_text())['outbox'] == []
    assert calls == ['/v1/events', '/v1/commands']


def test_credentials():
    with pytest.raises(ValueError):
        create_app({'operator_token': 'x' * 40, 'hosts': {'h': {'token': 'x' * 40}}})


def test_end_to_end_agent_response(system, tmp_path):
    client, store = system
    client.headers.update(auth('a'))
    state = {'outbox': [e.model_dump(mode='json') for e in failures()]}
    path = tmp_path / 'agent.json'
    cycle({}, state, path, client)
    alert_id = store.list_alerts()[0]['id']
    queued = client.post('/v1/blocks', headers=auth('o'), json={
        'alert_id': alert_id, 'reason': 'Confirmed suspicious source', 'duration_seconds': 60})
    assert queued.status_code == 201
    cfg = {'allow_response': True, 'protected_networks': ['10.0.0.0/24'],
           'permitted_networks': ['10.0.0.0/8']}
    with patch('vulnsuite.protection.agent.block_ip') as block:
        cycle(cfg, state, path, client)
        cycle(cfg, state, path, client)
        block.assert_called_once()
    assert client.get('/v1/responses', headers=auth('o')).json()['responses'][0]['status'] == 'applied'


def test_collection_partial_lines_and_rotation(tmp_path):
    log = tmp_path / 'auth.log'
    log.write_text('')
    cfg = {'logs': [{'path': str(log), 'kind': 'ssh'}]}
    state = {}
    collect(cfg, state)
    log.write_text('sshd: Failed password for bob from 10.1.2.3 port 22')
    collect(cfg, state)
    assert not any(e['kind'] == 'auth_failure' for e in state['outbox'])
    log.write_text(log.read_text() + '\n')
    collect(cfg, state)
    assert sum(e['kind'] == 'auth_failure' for e in state['outbox']) == 1
    log.rename(tmp_path / 'auth.log.1')
    log.write_text('sshd: Accepted publickey for bob from 10.1.2.3 port 22\n')
    collect(cfg, state)
    assert any(e['kind'] == 'auth_success' for e in state['outbox'])


def test_network_outage_retains_outbox(tmp_path):
    path = tmp_path / 'state.json'
    def broken(request):
        raise httpx.ConnectError('offline')
    with httpx.Client(base_url='https://protection.test', transport=httpx.MockTransport(broken)) as client:
        with pytest.raises(httpx.ConnectError):
            cycle({}, {}, path, client)
    assert json.loads(path.read_text())['outbox'][0]['kind'] == 'heartbeat'


def test_expired_and_missing_evidence(system):
    client, store = system
    assert client.post('/v1/events', headers=auth('a'), json={
        'events': [{'kind': 'file_change'}]}).status_code == 422
    send(client, failures())
    alert_id = store.list_alerts()[0]['id']
    client.post('/v1/blocks', headers=auth('o'), json={
        'alert_id': alert_id, 'reason': 'Confirmed suspicious source'})
    with store.connect() as db:
        db.execute('UPDATE commands SET created=?', (time.time() - 301,))
    assert client.get('/v1/commands', headers=auth('a')).json()['commands'] == []
