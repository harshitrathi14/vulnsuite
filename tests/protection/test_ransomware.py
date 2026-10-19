"""Ransomware early warning: canary, mass-change and entropy signals from inert
temporary files; critical alerts; pre-approved isolation gated on both sides."""
import json
import os
import subprocess
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from vulnsuite.protection import response_agent
from vulnsuite.protection.agent import collect
from vulnsuite.protection.models import Event
from vulnsuite.protection.ransomware import entropy, ransomware_events, validate_config
from vulnsuite.protection.response_agent import execute_playbook, poll_playbooks
from vulnsuite.protection.service import create_app
from vulnsuite.protection.store import Store


def test_config_validation():
    with pytest.raises(ValueError):
        validate_config({})
    with pytest.raises(ValueError):
        validate_config({'canary_files': ['relative.txt']})
    with pytest.raises(ValueError):
        validate_config({'watch_dirs': ['/srv'], 'change_threshold': 2})
    settings = validate_config({'watch_dirs': ['/srv'], 'canary_files': [r'C:\Users\Public\canary.docx']})
    assert settings['threshold'] == 50 and settings['entropy'] is True


def test_canary_change_and_disappearance(tmp_path):
    canary = tmp_path / 'Q3-board-pack.xlsx'
    canary.write_bytes(b'inert canary content ' * 10)
    config = {'enabled': True, 'canary_files': [str(canary)]}
    state = {}
    events, status, detail = ransomware_events(config, state)
    assert events == [] and (status, detail) == ('ok', 'collected')  # baseline
    assert ransomware_events(config, state)[0] == []
    canary.write_bytes(b'\x00encrypted\xff' * 20)
    events, _, _ = ransomware_events(config, state)
    assert [(e['signal'], e['path']) for e in events] == [('canary_modified', str(canary))]
    assert ransomware_events(config, state)[0] == []  # reported once per change
    canary.unlink()
    events, _, _ = ransomware_events(config, state)
    assert [e['signal'] for e in events] == ['canary_deleted']
    events, status, detail = ransomware_events(config, state)
    assert events == [] and (status, detail) == ('partial', 'input_error')  # missing canary = coverage gap
    for item in ([{'kind': 'ransomware_signal', 'signal': 'canary_deleted', 'path': str(canary)}]):
        Event(**item)


def test_mass_rename_with_new_extension_and_entropy(tmp_path):
    share = tmp_path / 'share'
    share.mkdir()
    for n in range(40):
        (share / f'invoice-{n:03d}.pdf').write_bytes(b'%PDF-1.4 inert text content ' * 200)
    config = {'enabled': True, 'watch_dirs': [str(share)], 'change_threshold': 30}
    state = {}
    assert ransomware_events(config, state)[0] == []  # baseline
    # Ordinary activity below the threshold: nothing.
    (share / 'invoice-000.pdf').write_bytes(b'%PDF-1.4 updated ' * 200)
    assert ransomware_events(config, state)[0] == []
    # Encryption-style sweep: rewrite with random bytes and rename to a new extension.
    for n in range(40):
        target = share / f'invoice-{n:03d}.pdf'
        target.write_bytes(os.urandom(8192))
        target.rename(share / f'invoice-{n:03d}.pdf.locked')
    events, status, _ = ransomware_events(config, state)
    signals = {e['signal']: e for e in events}
    assert status == 'ok' and set(signals) == {'mass_change', 'high_entropy_rewrite'}
    assert signals['mass_change']['change_count'] >= 40 and signals['mass_change']['sample_extensions'] == ['.locked']
    assert signals['high_entropy_rewrite']['entropy_samples'] >= 3
    for item in events:
        Event(**item)
    assert entropy(b'a' * 1000) == 0.0 and entropy(os.urandom(65536)) > 7.9


def test_plain_rewrites_do_not_trigger_entropy(tmp_path):
    docs = tmp_path / 'docs'
    docs.mkdir()
    for n in range(10):
        (docs / f'note-{n}.txt').write_text('plain text ' * 1000)
    config = {'enabled': True, 'watch_dirs': [str(docs)], 'change_threshold': 100}
    state = {}
    ransomware_events(config, state)
    for n in range(10):
        (docs / f'note-{n}.txt').write_text('edited plain text ' * 1000)
    assert ransomware_events(config, state)[0] == []


def test_agent_wires_the_sensor_and_reports_health(tmp_path):
    canary = tmp_path / 'canary.docx'
    canary.write_bytes(b'inert')
    cfg = {'ransomware': {'enabled': True, 'canary_files': [str(canary)]}}
    state = {}
    collect(cfg, state)
    sensors = [e for e in state['outbox'] if e['kind'] == 'sensor_status']
    assert [(s['sensor'], s['sensor_status']) for s in sensors] == [('ransomware', 'ok')]


# ---------- server ----------

KEYS = {'requester': 'r' * 40, 'approver': 'a' * 40, 'host': 'h' * 40}


def auth(actor):
    return {'Authorization': 'Bearer ' + KEYS[actor]}


def build(tmp_path, automatic=None):
    policy = {'enabled': True, 'allowed_actions': ['isolate_host', 'release_host'],
              'isolation': {'management_networks': ['10.10.0.5/32'], 'management_ports': [22, 443]}}
    if automatic:
        policy['automatic'] = automatic
    cfg = {'operators': {actor: {'token': KEYS[actor], 'roles': ['admin']} for actor in ('requester', 'approver')},
           'hosts': {'file-1': {'token': KEYS['host'], 'addresses': ['10.10.0.10']}},
           'response': {'hosts': {'file-1': policy}},
           'integrations': {'siem': {'enabled': True, 'type': 'webhook', 'url': 'https://siem.example/x',
                                     'token_env': 'T', 'signing_key_env': 'S'}}}
    store = Store(str(tmp_path / 'control.sqlite'))
    client = TestClient(create_app(cfg, store), headers=auth('host'))
    return {'client': client, 'store': store, 'policy': policy, 'state_path': tmp_path / 'state.json'}


def signal(system, **fields):
    event = Event(**{'kind': 'ransomware_signal', 'signal': 'mass_change', 'path': '/srv/share',
                     'change_count': 120, 'sample_extensions': ['.locked'], **fields})
    response = system['client'].post('/v1/events', json={'events': [event.model_dump(mode='json')]})
    assert response.status_code == 200, response.text
    return response.json()['alerts']


def jobs(system):
    with system['store'].connect() as db:
        return [dict(r) for r in db.execute('SELECT * FROM response_jobs ORDER BY created')]


def test_signal_raises_critical_alert_without_automatic_response(tmp_path):
    system = build(tmp_path)
    alerts = signal(system)
    assert [(a['rule'], a['severity']) for a in alerts] == [('ransomware_activity', 'critical')]
    assert json.loads(alerts[0]['detail'])['sample_extensions'] == ['.locked']
    assert jobs(system) == []
    # Analysts can still request isolation manually from the alert.
    created = system['client'].post('/v1/playbooks', headers=auth('requester'), json={
        'alert_id': alerts[0]['id'], 'action': 'isolate_host', 'duration_seconds': 600,
        'reason': 'Mass encryption signal on the file share; isolate pending review'})
    assert created.status_code == 201 and created.json()['status'] == 'requested'


def test_pre_approved_isolation_is_created_once_and_needs_host_opt_in(tmp_path):
    system = build(tmp_path, automatic={'rules': ['ransomware_activity'], 'approved_by': 'ciso-delegate',
                                        'isolate_seconds': 600})
    alerts = signal(system)
    created = jobs(system)
    assert len(created) == 1
    job = created[0]
    assert job['status'] == 'approved' and job['requested_by'] == 'policy:automatic' and job['approved_by'] == 'ciso-delegate'
    plan = json.loads(job['plan'])
    assert plan['automatic'] is True and plan['expires_at'] == job['expires'] and plan['management_networks'] == ['10.10.0.5/32']
    with system['store'].connect() as db:
        audited = [r[0] for r in db.execute("SELECT action FROM audit WHERE action='playbook_auto_approved'")]
        queued = [json.loads(r[0])['type'] for r in db.execute('SELECT payload FROM deliveries')]
    assert audited == ['playbook_auto_approved'] and 'response.automatic' in queued
    # A second signal while isolation is outstanding does not stack another timer.
    signal(system, path='/srv/other')
    assert len(jobs(system)) == 1
    # The host receives the command but refuses it unless it opted in to automatic plans.
    commands = system['client'].get('/v1/playbooks/commands').json()['commands']
    assert [c['id'] for c in commands] == [job['id']]
    local = {'response_policy': {**system['policy'], 'platform': 'linux'}}
    with patch.object(response_agent, 'native_platform', return_value='linux'):
        denied = execute_playbook(local, commands[0])
        assert denied['detail'] == 'policy_denied'
        local['response_policy']['allow_automatic'] = True
        tables = set()

        def nft(command, **kwargs):
            if command[1:] == ['--json', 'list', 'tables']:
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps({'nftables': [
                    {'table': {'family': 'inet', 'name': name}} for name in tables]}))
            if command[1:] == ['-f', '-']:
                tables.add('vsi_' + job['id'])
            return subprocess.CompletedProcess(command, 0, stdout='')
        with patch('vulnsuite.protection.playbooks.subprocess.run', side_effect=nft):
            poll_playbooks(local, {}, system['state_path'], system['client'])
    assert jobs(system)[0]['status'] == 'applied' and tables == {'vsi_' + job['id']}


def test_automatic_policy_requires_approver_rule_and_enabled_isolation(tmp_path):
    for automatic in ({'rules': ['ransomware_activity']},                       # no approver
                      {'rules': ['web_server_shell'], 'approved_by': 'x'},      # rule not eligible
                      {'rules': ['ransomware_activity'], 'approved_by': 'x', 'isolate_seconds': 10}):
        system = build(tmp_path / str(len(automatic)) / str(id(automatic)), automatic=automatic)
        signal(system)
        assert jobs(system) == []
    system = build(tmp_path / 'disabled', automatic={'rules': ['ransomware_activity'], 'approved_by': 'x'})
    system['policy']['allowed_actions'].remove('isolate_host')
    signal(system)
    assert jobs(system) == []
