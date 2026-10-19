"""Real API/approval/agent dispatch/receipt flow with mocked Windows OS adapters.

These tests run on Linux and never change Windows files, ACLs, tasks or firewall.
"""
import json
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from vulnsuite.protection import response_agent
from vulnsuite.protection.models import Event
from vulnsuite.protection.service import create_app
from vulnsuite.protection.store import Store
from vulnsuite.protection.telemetry import SYSMON, parse_windows_event, windows_hash_detection

DIGEST = 'c' * 64
IMAGE = r'C:\ProgramData\Uploads\suspicious.exe'


def authorization(character):
    return {'Authorization': 'Bearer ' + character * 40}


@pytest.fixture
def windows_system(tmp_path, monkeypatch):
    from vulnsuite.protection import windows_isolation, windows_quarantine

    isolation_policy = {'platform': 'windows', 'management_networks': ['10.0.0.5/32'],
                        'management_ports': [443, 3389],
                        'state_dir': r'C:\ProgramData\VulnSuite\Isolation',
                        'helper_sha256': 'd' * 64}
    policy = {'enabled': True, 'platform': 'windows',
              'allowed_actions': ['quarantine_file', 'restore_file', 'isolate_host', 'release_host'],
              'quarantine': {'allowed_paths': [IMAGE], 'quarantine_dir': r'C:\ProgramData\VulnSuite\Quarantine'},
              'isolation': isolation_policy}
    cfg = {'operators': {
        'requester': {'token': 'a' * 40, 'roles': ['admin']},
        'approver': {'token': 'b' * 40, 'roles': ['admin']}},
        'hosts': {'windows-server': {'token': 'w' * 40}, 'other-server': {'token': 'o' * 40}},
        'response': {'hosts': {'windows-server': policy}}}
    store = Store(str(tmp_path / 'windows.sqlite'))
    app = create_app(cfg, store)
    operator = TestClient(app)
    agent = TestClient(app, headers=authorization('w'))
    other = TestClient(app, headers=authorization('o'))
    calls = {'quarantine': [], 'restore': [], 'isolate': [], 'release': [], 'cleanup': []}

    class FakeWindowsQuarantine:
        def __init__(self, settings):
            assert settings == policy['quarantine']

        def quarantine(self, path, digest, identifier):
            calls['quarantine'].append((path, digest, identifier))
            return {'status': 'applied', 'detail': 'quarantined', 'path': path,
                    'sha256': digest, 'request_id': identifier}

        def restore(self, identifier):
            calls['restore'].append(identifier)
            return {'status': 'rolled_back', 'detail': 'restored', 'path': IMAGE,
                    'sha256': DIGEST, 'request_id': identifier}

    def isolate(settings, plan):
        assert settings == isolation_policy
        calls['isolate'].append(plan.copy())
        return {'status': 'applied', 'detail': 'isolated', 'request_id': plan['request_id'],
                'expires_at': plan['expires_at'], 'platform': 'windows'}

    def release(settings, identifier):
        assert settings == isolation_policy
        calls['release'].append(identifier)
        return {'status': 'rolled_back', 'detail': 'isolation_released',
                'request_id': identifier, 'platform': 'windows'}

    monkeypatch.setattr(response_agent, 'native_platform', lambda: 'windows')
    monkeypatch.setattr(windows_quarantine, 'WindowsQuarantine', FakeWindowsQuarantine)
    monkeypatch.setattr(windows_isolation, 'apply_windows_isolation', isolate)
    monkeypatch.setattr(windows_isolation, 'release_windows_isolation', release)
    monkeypatch.setattr(windows_isolation, 'cleanup_expired', lambda settings: calls['cleanup'].append(settings))
    assert agent.post('/v1/events', json={'events': [Event(kind='heartbeat', platform='windows',
        agent_version='windows-test-version', hostname='windows-server').model_dump(mode='json')]}).status_code == 200
    event = parse_windows_event({'Provider': SYSMON, 'EventId': 1, 'RecordId': '9001',
        'TimeCreated': datetime.now(timezone.utc).isoformat(),
        'EventData': {'Image': IMAGE, 'ParentImage': r'C:\Windows\System32\services.exe',
                      'ProcessId': '4321', 'ParentProcessId': '210', 'User': r'EXAMPLE\service',
                      'Hashes': 'SHA256=' + DIGEST}})
    detected = windows_hash_detection(event, {DIGEST: 'Reviewed IOC'})
    response = agent.post('/v1/events', json={'events': [Event(**detected).model_dump(mode='json')]})
    assert response.status_code == 200, response.text
    health = operator.get('/v1/hosts', headers=authorization('a')).json()['hosts']
    assert next(h for h in health if h['host'] == 'windows-server')['metadata']['agent_version'] == 'windows-test-version'
    alert_id = response.json()['alerts'][0]['id']
    return {'operator': operator, 'agent': agent, 'other': other, 'store': store,
            'config': {'response_policy': policy}, 'alert_id': alert_id,
            'state_path': tmp_path / 'agent-state.json', 'calls': calls}


def request(system, action='quarantine_file', **extra):
    response = system['operator'].post('/v1/playbooks', headers=authorization('a'), json={
        'action': action, 'alert_id': system['alert_id'], 'duration_seconds': 300,
        'reason': 'Analyst verified exact known-bad image evidence', **extra})
    assert response.status_code == 201, response.text
    plan = response.json()
    assert plan['plan']['platform'] == 'windows'
    return plan


def approve(system, identifier):
    response = system['operator'].post(f'/v1/playbooks/{identifier}/approve', headers=authorization('b'))
    assert response.status_code == 200, response.text


def job(system, identifier):
    with system['store'].connect() as db:
        return dict(db.execute('SELECT * FROM response_jobs WHERE id=?', (identifier,)).fetchone())


def test_windows_quarantine_then_restore_uses_reviewed_evidence_and_original_job(windows_system):
    system = windows_system
    command = request(system)
    identifier = command['id']
    assert command['plan']['path'] == IMAGE and command['plan']['sha256'] == DIGEST
    assert system['operator'].post(f'/v1/playbooks/{identifier}/approve', headers=authorization('a')).status_code == 403
    state = {}
    response_agent.poll_playbooks(system['config'], state, system['state_path'], system['agent'])
    assert system['calls']['quarantine'] == []
    approve(system, identifier)
    assert system['other'].get('/v1/playbooks/commands').json()['commands'] == []
    response_agent.poll_playbooks(system['config'], state, system['state_path'], system['agent'])
    assert system['calls']['quarantine'] == [(IMAGE, DIGEST, identifier)]
    applied = job(system, identifier)
    assert applied['status'] == 'applied' and applied['requested_by'] == 'requester' and applied['approved_by'] == 'approver'
    assert json.loads(applied['result'])['platform'] == 'windows'
    response_agent.poll_playbooks(system['config'], state, system['state_path'], system['agent'])
    assert len(system['calls']['quarantine']) == 1
    rollback = request(system, 'restore_file', previous_job_id=identifier)
    assert rollback['plan']['request_id'] == identifier
    approve(system, rollback['id'])
    response_agent.poll_playbooks(system['config'], state, system['state_path'], system['agent'])
    assert system['calls']['restore'] == [identifier]
    assert job(system, rollback['id'])['status'] == 'rolled_back'


def test_windows_isolation_then_release_round_trips_real_prepare_policy(windows_system):
    system = windows_system
    command = request(system, 'isolate_host')
    identifier = command['id']
    assert command['plan']['management_networks'] == ['10.0.0.5/32']
    approve(system, identifier)
    state = {}
    response_agent.poll_playbooks(system['config'], state, system['state_path'], system['agent'])
    assert len(system['calls']['isolate']) == 1
    assert job(system, identifier)['status'] == 'applied'
    rollback = request(system, 'release_host', previous_job_id=identifier)
    approve(system, rollback['id'])
    response_agent.poll_playbooks(system['config'], state, system['state_path'], system['agent'])
    assert system['calls']['release'] == [identifier]
    assert job(system, rollback['id'])['status'] == 'rolled_back'


def test_lost_acknowledgment_retries_receipt_without_repeating_windows_action(windows_system):
    system = windows_system
    identifier = request(system)['id']
    approve(system, identifier)

    class LostReceiptAcknowledgment:
        def get(self, *args, **kwargs):
            return system['agent'].get(*args, **kwargs)

        def post(self, *args, **kwargs):
            response = system['agent'].post(*args, **kwargs)
            assert response.status_code == 200
            raise httpx.ReadError('simulated acknowledgment loss', request=response.request)

    with pytest.raises(httpx.ReadError):
        response_agent.poll_playbooks(system['config'], {}, system['state_path'], LostReceiptAcknowledgment())
    saved = json.loads(system['state_path'].read_text())
    assert saved['playbook_receipts'][identifier]['acknowledged'] is False
    assert job(system, identifier)['status'] == 'applied'
    response_agent.poll_playbooks(system['config'], saved, system['state_path'], system['agent'])
    assert len(system['calls']['quarantine']) == 1
    assert saved['playbook_receipts'][identifier]['acknowledged'] is True


def test_independent_local_windows_action_policy_denies_approved_server_request(windows_system):
    system = windows_system
    identifier = request(system)['id']
    approve(system, identifier)
    policy = {**system['config']['response_policy'], 'allowed_actions': ['restore_file']}
    response_agent.poll_playbooks({'response_policy': policy}, {}, system['state_path'], system['agent'])
    assert system['calls']['quarantine'] == []
    denied = job(system, identifier)
    assert denied['status'] == 'failed' and json.loads(denied['result'])['detail'] == 'policy_denied'


def test_crash_after_windows_mutation_requires_reviewed_restore_without_reexecution(windows_system, monkeypatch):
    from vulnsuite.protection import windows_quarantine

    system = windows_system
    identifier = request(system)['id']
    approve(system, identifier)
    original = windows_quarantine.WindowsQuarantine.quarantine

    def crash_after_mutation(self, path, digest, request_id):
        original(self, path, digest, request_id)
        raise SystemExit('simulated agent process termination after native mutation')

    monkeypatch.setattr(windows_quarantine.WindowsQuarantine, 'quarantine', crash_after_mutation)
    with pytest.raises(SystemExit):
        response_agent.poll_playbooks(system['config'], {}, system['state_path'], system['agent'])
    restored_state = json.loads(system['state_path'].read_text())
    assert restored_state['playbook_receipts'][identifier]['uncertain'] is True
    assert len(system['calls']['quarantine']) == 1
    # The restarted agent acknowledges its uncertainty and never repeats mutation.
    response_agent.poll_playbooks(system['config'], restored_state, system['state_path'], system['agent'])
    assert len(system['calls']['quarantine']) == 1
    uncertain = job(system, identifier)
    assert uncertain['status'] == 'failed'
    assert json.loads(uncertain['result'])['execution_uncertain'] is True
    rollback = request(system, 'restore_file', previous_job_id=identifier)
    response_agent.poll_playbooks(system['config'], restored_state, system['state_path'], system['agent'])
    assert system['calls']['restore'] == []
    approve(system, rollback['id'])
    response_agent.poll_playbooks(system['config'], restored_state, system['state_path'], system['agent'])
    assert system['calls']['restore'] == [identifier]
    assert job(system, rollback['id'])['status'] == 'rolled_back'
