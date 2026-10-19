"""Approved response across real API, durable store, agent and provider boundaries.

Only inert temporary files are moved. HTTP provider requests and nft execution are
mocked; the tests never change a live firewall or contact an external service.
"""
import hashlib
import json
import subprocess
import time
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from vulnsuite.protection.models import Event
from vulnsuite.protection.response_agent import poll_playbooks
from vulnsuite.protection.response_worker import process_responses
from vulnsuite.protection.service import create_app
from vulnsuite.protection.store import Store


KEYS = {'requester': 'r' * 40, 'approver': 'a' * 40, 'host': 'h' * 40}


def auth(actor):
    return {'Authorization': 'Bearer ' + KEYS[actor]}


@pytest.fixture
def response_system(tmp_path, monkeypatch):
    monkeypatch.setenv('VS_TEST_CLOUDFLARE_TOKEN', 'c' * 40)
    sample = tmp_path / 'inert-sample'
    sample.write_bytes(b'This is a harmless response workflow test fixture.\n')
    sample.chmod(0o750)
    vault = tmp_path / 'vault'
    vault.mkdir(mode=0o700)
    isolation = {'management_networks': ['10.10.0.5/32'], 'management_ports': [22, 443]}
    policy = {'enabled': True,
              'allowed_actions': ['quarantine_file', 'restore_file', 'isolate_host', 'release_host'],
              'quarantine': {'quarantine_dir': str(vault), 'allowed_paths': [str(sample)]},
              'isolation': isolation}
    config = {
        'operators': {actor: {'token': KEYS[actor], 'roles': ['admin']}
                      for actor in ('requester', 'approver')},
        'hosts': {'server-a': {'token': KEYS['host'], 'addresses': ['10.10.0.10']}},
        'response': {'hosts': {'server-a': policy}, 'cloud_waf': {
            'enabled': True, 'zone_id': 'a' * 32, 'ruleset_id': 'b' * 32,
            'token_env': 'VS_TEST_CLOUDFLARE_TOKEN', 'protected_networks': ['10.0.0.0/8'],
            'permitted_networks': ['0.0.0.0/0', '::/0']}},
    }
    store = Store(str(tmp_path / 'control.sqlite'))
    client = TestClient(create_app(config, store), headers=auth('host'))
    return {'client': client, 'store': store, 'config': config,
            'agent_config': {'response_policy': policy}, 'sample': sample,
            'state_path': tmp_path / 'agent-state.json'}


def malware_alert(system):
    sample = system['sample']
    event = Event(kind='malware_detection', path=str(sample),
                  sha256=hashlib.sha256(sample.read_bytes()).hexdigest(),
                  engine='sha256', signature='inert-workflow-fixture')
    response = system['client'].post('/v1/events', json={'events': [event.model_dump(mode='json')]})
    assert response.status_code == 200, response.text
    return response.json()['alerts'][0]['id']


def access_alert(system):
    events = [Event(kind='auth_failure', source_ip='8.8.4.4') for _ in range(5)]
    response = system['client'].post('/v1/events', json={'events': [e.model_dump(mode='json') for e in events]})
    assert response.status_code == 200, response.text
    return response.json()['alerts'][0]['id']


def request_job(system, alert_id, action, **extra):
    response = system['client'].post('/v1/playbooks', headers=auth('requester'), json={
        'alert_id': alert_id, 'action': action, 'duration_seconds': 120,
        'reason': 'Reviewed inert workflow evidence and planned rollback', **extra})
    assert response.status_code == 201, response.text
    return response.json()


def approve(system, identifier):
    client = system['client']
    assert client.post(f'/v1/playbooks/{identifier}/approve', headers=auth('requester')).status_code == 403
    response = client.post(f'/v1/playbooks/{identifier}/approve', headers=auth('approver'))
    assert response.status_code == 200, response.text


def row(system, identifier):
    with system['store'].connect() as db:
        return dict(db.execute('SELECT * FROM response_jobs WHERE id=?', (identifier,)).fetchone())


def poll(system, state):
    poll_playbooks(system['agent_config'], state, system['state_path'], system['client'])


def test_api_approval_agent_quarantine_restore_and_durable_receipt(response_system):
    system, state = response_system, {}
    sample = system['sample']
    original = sample.read_bytes()
    alert_id = malware_alert(system)
    job = request_job(system, alert_id, 'quarantine_file')
    assert job['plan']['expires_at'] == job['expires_at']
    poll(system, state)
    assert sample.exists() and row(system, job['id'])['status'] == 'requested'
    approve(system, job['id'])
    poll(system, state)
    applied = row(system, job['id'])
    result = json.loads(applied['result'])
    assert not sample.exists() and applied['status'] == 'applied'
    assert result['detail'] == 'quarantined' and result['sha256'] == hashlib.sha256(original).hexdigest()
    restored_state = json.loads(system['state_path'].read_text())
    assert restored_state['playbook_receipts'][job['id']]['acknowledged']
    # Rollback must remain possible when the original alert is no longer recent.
    with system['store'].connect() as db:
        db.execute('UPDATE alerts SET created=? WHERE id=?', (time.time() - 7200, alert_id))
    restore = request_job(system, alert_id, 'restore_file', previous_job_id=job['id'])
    approve(system, restore['id'])
    poll(system, restored_state)
    assert row(system, restore['id'])['status'] == 'rolled_back'
    assert sample.read_bytes() == original and sample.stat().st_mode & 0o777 == 0o750
    with system['store'].connect() as db:
        actors = {r[0] for r in db.execute("SELECT subject FROM audit WHERE action='playbook_approved'")}
        assert actors == {'approver'}
    # A restarted agent sends no second action once the API accepted its receipt.
    with patch('vulnsuite.protection.response_agent.execute_playbook') as execute:
        poll(system, json.loads(system['state_path'].read_text()))
        execute.assert_not_called()


def test_approved_quarantine_still_obeys_host_local_allowlist(response_system):
    system = response_system
    job = request_job(system, malware_alert(system), 'quarantine_file')
    approve(system, job['id'])
    # Local configuration is independent of the server-side approved policy.
    system['agent_config'] = {'response_policy': {
        **system['agent_config']['response_policy'], 'allowed_actions': ['isolate_host']}}
    poll(system, {})
    result = row(system, job['id'])
    assert result['status'] == 'failed' and json.loads(result['result'])['detail'] == 'policy_denied'
    assert system['sample'].exists()


def test_api_isolation_plan_matches_local_policy_and_release_receipt(response_system):
    system, state, tables, scripts = response_system, {}, set(), []
    job = request_job(system, malware_alert(system), 'isolate_host')
    assert job['plan']['management_networks'] == ['10.10.0.5/32']
    assert job['plan']['management_ports'] == [22, 443]
    approve(system, job['id'])
    def nft(command, **kwargs):
        assert command[0] == '/usr/sbin/nft'
        if command[1:] == ['--json', 'list', 'tables']:
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({'nftables': [
                {'table': {'family': 'inet', 'name': name}} for name in tables]}))
        if command[1:] == ['-f', '-']:
            scripts.append(kwargs['input'])
            tables.add('vsi_' + job['id'])
        if command[1:4] == ['delete', 'table', 'inet']:
            tables.remove(command[-1])
        return subprocess.CompletedProcess(command, 0, stdout='')
    with patch('vulnsuite.protection.playbooks.subprocess.run', side_effect=nft):
        poll(system, state)
        assert row(system, job['id'])['status'] == 'applied'
        assert len(scripts) == 1 and '10.10.0.5/32 tcp dport { 22, 443 } accept' in scripts[0]
        release = request_job(system, row(system, job['id'])['alert_id'], 'release_host', previous_job_id=job['id'])
        approve(system, release['id'])
        poll(system, state)
    assert row(system, release['id'])['status'] == 'rolled_back' and not tables


def test_cloud_approved_worker_and_cleanup_after_agent_revocation(response_system):
    system, rules, requests = response_system, [], []
    job = request_job(system, access_alert(system), 'cloud_waf_block')
    def provider(request):
        requests.append(request)
        assert request.url.host == 'api.cloudflare.com'
        if request.method == 'POST':
            rules.append({**json.loads(request.content), 'id': 'c' * 32})
        elif request.method == 'DELETE':
            rules.clear()
        return httpx.Response(200, json={'success': True, 'result': {
            'id': 'b' * 32, 'kind': 'zone', 'phase': 'http_request_firewall_custom', 'rules': rules}})
    transport = httpx.MockTransport(provider)
    assert process_responses(system['store'], system['config'], transport=transport)['applied'] == 0
    assert not requests
    approve(system, job['id'])
    assert system['client'].get('/v1/playbooks/commands').json()['commands'] == []
    assert process_responses(system['store'], system['config'], transport=transport)['applied'] == 1
    assert row(system, job['id'])['status'] == 'applied'
    assert f'http.request.timestamp.sec lt {job["plan"]["expires_at"]}' in rules[0]['expression']
    # Revocation must remove future agent access without orphaning provider cleanup.
    response = system['client'].post('/v1/agents/server-a/revoke', headers=auth('requester'))
    assert response.status_code == 200
    assert system['client'].get('/v1/playbooks/commands').status_code == 401
    assert process_responses(system['store'], system['config'], transport=transport)['rolled_back'] == 1
    assert row(system, job['id'])['status'] == 'rolled_back' and not rules
    assert sum(r.method == 'POST' for r in requests) == 1
    assert sum(r.method == 'DELETE' for r in requests) == 1


def test_revoked_unexecuted_cloud_job_never_calls_provider(response_system):
    system = response_system
    job = request_job(system, access_alert(system), 'cloud_waf_block')
    approve(system, job['id'])
    assert system['client'].post('/v1/agents/server-a/revoke', headers=auth('requester')).status_code == 200
    seen = []
    transport = httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(500))
    process_responses(system['store'], system['config'], transport=transport)
    assert not seen and row(system, job['id'])['status'] == 'cancelled'
