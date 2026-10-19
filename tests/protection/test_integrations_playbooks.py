import hashlib
import json
import os
from pathlib import Path
import time
from unittest.mock import patch
from uuid import uuid4

import httpx
import pytest

from vulnsuite.protection.playbooks import Quarantine, apply_isolation, isolation_script, prepare_isolation
from vulnsuite.protection.response_agent import execute_playbook, poll_playbooks


@pytest.fixture
def vault(tmp_path):
    # WSL /mnt/c does not guarantee POSIX permissions; pytest tmp_path is on /tmp.
    target = tmp_path / 'payload.bin'
    target.write_bytes(b'inert fixture: never executed')
    target.chmod(0o750)
    directory = tmp_path / 'vault'
    directory.mkdir(mode=0o700)
    config = {'quarantine_dir': str(directory), 'allowed_paths': [str(target)]}
    return Quarantine(config), target, hashlib.sha256(target.read_bytes()).hexdigest(), config


def test_quarantine_restore_keeps_bytes_and_mode(vault):
    quarantine, target, digest, _ = vault
    identifier = uuid4().hex
    result = quarantine.quarantine(str(target), digest, identifier)
    assert result['status'] == 'applied' and not target.exists()
    payload = Path(quarantine.directory) / result['request_id'] / 'payload'
    assert payload.read_bytes() == b'inert fixture: never executed'
    assert payload.stat().st_mode & 0o777 == 0o400
    assert quarantine.quarantine(str(target), digest, identifier) == result
    assert quarantine.restore(identifier)['status'] == 'rolled_back'
    assert target.read_bytes() == b'inert fixture: never executed'
    assert target.stat().st_mode & 0o777 == 0o750
    assert quarantine.restore(identifier)['status'] == 'rolled_back'


def test_quarantine_wrong_hash_symlink_hardlink_refused(vault, tmp_path):
    quarantine, target, digest, _ = vault
    with pytest.raises(ValueError):
        quarantine.quarantine(str(target), 'f' * 64, uuid4().hex)
    other = tmp_path / 'other'
    target.rename(other)
    target.symlink_to(other)
    with pytest.raises(OSError):
        quarantine.quarantine(str(target), digest, uuid4().hex)
    target.unlink()
    os.link(other, target)
    with pytest.raises(ValueError):
        quarantine.quarantine(str(target), digest, uuid4().hex)
    assert other.read_bytes() == target.read_bytes()


def test_quarantine_rejects_symlink_ancestor(tmp_path):
    real = tmp_path / 'real'
    real.mkdir()
    target = real / 'fixture'
    target.write_bytes(b'fixture')
    alias = tmp_path / 'alias'
    alias.symlink_to(real, target_is_directory=True)
    directory = tmp_path / 'vault'
    directory.mkdir(mode=0o700)
    quarantine = Quarantine({'quarantine_dir': str(directory), 'allowed_paths': [str(alias / 'fixture')]})
    with pytest.raises(OSError):
        quarantine.quarantine(str(alias / 'fixture'), hashlib.sha256(b'fixture').hexdigest(), uuid4().hex)
    assert target.exists()


def test_restore_refuses_overwrite_or_modified_evidence(vault):
    quarantine, target, digest, _ = vault
    identifier = str(uuid4())
    quarantine.quarantine(str(target), digest, identifier)
    target.write_bytes(b'new legitimate file')
    with pytest.raises(FileExistsError):
        quarantine.restore(identifier)
    assert target.read_bytes() == b'new legitimate file'
    target.unlink()
    payload = Path(quarantine.directory) / identifier / 'payload'
    payload.chmod(0o600)
    payload.write_bytes(b'changed')
    with pytest.raises(ValueError, match='hash mismatch'):
        quarantine.restore(identifier)
    assert payload.exists()


def test_restore_recovers_crash_after_move(vault):
    quarantine, target, digest, _ = vault
    identifier = str(uuid4())
    quarantine.quarantine(str(target), digest, identifier)
    payload = Path(quarantine.directory) / identifier / 'payload'
    payload.chmod(0o750)
    payload.rename(target)
    assert quarantine.restore(identifier)['status'] == 'rolled_back'


def test_isolation_bounded_ipv4_ipv6_management_and_scope():
    policy = {'management_networks': ['10.10.0.5/32', 'fd00::5/128'], 'management_ports': [443, 22]}
    plan = prepare_isolation(policy, 120, uuid4().hex, now=1000)
    script = isolation_script(policy, plan, now=1010)
    assert '0.0.0.0/0 timeout 110s' in script and '::/0 timeout 110s' in script
    assert '10.10.0.5/32 tcp dport { 22, 443 } accept' in script
    assert 'chain forward' in script
    assert 'flush ruleset' not in script
    with pytest.raises(ValueError):
        isolation_script(policy, plan, now=1121)
    with pytest.raises(ValueError):
        isolation_script({'management_networks': ['10.20.0.5/32']}, plan, now=1010)
    with pytest.raises(ValueError):
        prepare_isolation({'management_networks': ['0.0.0.0/0']}, 120, uuid4().hex)


def test_isolation_retry_does_not_refresh_kernel_timeout():
    policy = {'management_networks': ['10.0.0.5/32']}
    plan = prepare_isolation(policy, 120, uuid4().hex)
    existing = {'nftables': [{'table': {'family': 'inet', 'name': 'vsi_' + plan['request_id'].replace('-', '')}}]}
    with patch('vulnsuite.protection.playbooks.subprocess.run') as run:
        run.return_value.stdout = json.dumps(existing)
        assert apply_isolation(policy, plan)['status'] == 'applied'
        assert run.call_count == 1


def test_agent_independent_policy_denies_action(vault):
    _, target, digest, policy = vault
    identifier = uuid4().hex
    command = {'id': identifier, 'action': 'quarantine_file',
               'plan': {'path': str(target), 'sha256': digest, 'request_id': identifier,
                        'expires_at': time.time() + 300}}
    assert execute_playbook({}, command)['detail'] == 'policy_denied'
    config = {'response_policy': {'enabled': True, 'allowed_actions': ['isolate_host'], 'quarantine': policy}}
    assert execute_playbook(config, command)['detail'] == 'policy_denied'
    assert target.exists()


def test_agent_rejects_delayed_expired_approved_plan(vault):
    _, target, digest, policy = vault
    identifier = uuid4().hex
    command = {'id': identifier, 'action': 'quarantine_file',
               'plan': {'path': str(target), 'sha256': digest, 'request_id': identifier,
                        'expires_at': time.time() - 1}}
    config = {'response_policy': {'enabled': True, 'allowed_actions': ['quarantine_file'],
                                  'quarantine': policy}}
    assert execute_playbook(config, command)['detail'] == 'policy_denied'
    assert target.exists()


def test_agent_durable_receipt_after_network_failure(vault, tmp_path):
    _, target, digest, policy = vault
    identifier = uuid4().hex
    command = {'id': identifier, 'action': 'quarantine_file',
               'plan': {'path': str(target), 'sha256': digest, 'request_id': identifier,
                        'expires_at': time.time() + 300}}
    config = {'response_policy': {'enabled': True, 'allowed_actions': ['quarantine_file'], 'quarantine': policy}}
    path = tmp_path / 'agent.json'
    state = {}
    calls = []
    def fail_ack(request):
        calls.append(request.url.path)
        if request.method == 'GET':
            return httpx.Response(200, json={'commands': [command]})
        return httpx.Response(503)
    with httpx.Client(base_url='https://control.test', transport=httpx.MockTransport(fail_ack)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            poll_playbooks(config, state, path, client)
    assert not target.exists()
    restored = json.loads(path.read_text())
    assert restored['playbook_receipts'][identifier]['receipt']['status'] == 'applied'
    def recovered(request):
        calls.append(request.url.path)
        if request.method == 'GET':
            return httpx.Response(200, json={'commands': []})
        return httpx.Response(200, json={'status': 'applied'})
    with httpx.Client(base_url='https://control.test', transport=httpx.MockTransport(recovered)) as client:
        with patch('vulnsuite.protection.response_agent.execute_playbook') as execute:
            poll_playbooks(config, restored, path, client)
            execute.assert_not_called()
    assert restored['playbook_receipts'][identifier]['acknowledged']
    assert f'/v1/playbooks/{identifier}/receipt' in calls
