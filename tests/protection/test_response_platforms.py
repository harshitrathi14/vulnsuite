"""The server cannot turn a plan into a different host's native response."""
import time
import json
from unittest.mock import patch
from uuid import uuid4

import httpx
import pytest

from vulnsuite.protection.agent import collect, cycle, respond
from vulnsuite.protection.models import Event
from vulnsuite.protection.response_agent import cleanup_playbooks, execute_playbook, poll_playbooks


def command(platform=None):
    identifier = uuid4().hex
    plan = {'request_id': identifier, 'expires_at': time.time()+120,
            'path': r'C:\Uploads\fixture.bin', 'sha256': 'a'*64}
    if platform:
        plan['platform'] = platform
    return {'id': identifier, 'action': 'quarantine_file', 'plan': plan}


@pytest.mark.parametrize('native, configured, planned', [
    ('linux', 'linux', 'windows'), ('windows', 'windows', 'linux'),
    ('windows', 'windows', None), ('windows', None, 'windows'),
    ('linux', 'windows', 'windows'), (None, 'linux', 'linux')])
def test_platform_mismatch_never_reaches_native_executor(native, configured, planned):
    policy = {'enabled': True, 'allowed_actions': ['quarantine_file']}
    if configured:
        policy['platform'] = configured
    with patch('vulnsuite.protection.response_agent.native_platform', return_value=native), \
         patch('vulnsuite.protection.response_agent.Quarantine') as quarantine:
        result = execute_playbook({'response_policy': policy}, command(planned))
    assert result['status'] == 'failed' and result['detail'] == 'policy_denied'
    quarantine.assert_not_called()


@pytest.mark.parametrize('value', [{}, {'action': 'release_host'}, {'action': 'quarantine_file', 'plan': None}])
def test_malformed_local_job_fails_without_executing(value):
    assert execute_playbook({'response_policy': {'enabled': True}}, value)['status'] == 'failed'


def test_local_recovery_runs_before_collection_or_network_even_when_new_response_disabled(tmp_path):
    config = {'response_policy': {'enabled': False, 'platform': 'windows'}}
    order = []
    with patch('vulnsuite.protection.response_agent.cleanup_playbooks', side_effect=lambda *args: order.append('cleanup')), \
         patch('vulnsuite.protection.agent.collect', side_effect=httpx.ConnectError('offline')):
        with pytest.raises(httpx.ConnectError):
            cycle(config, {}, tmp_path/'state.json', object())
    assert order == ['cleanup']


def test_legacy_nft_block_is_denied_on_windows():
    with patch('vulnsuite.protection.agent.os.name', 'nt'), patch('vulnsuite.protection.agent.block_ip') as block:
        assert respond({}, {'allow_response': True})['detail'] == 'policy_denied'
    block.assert_not_called()


def test_disabling_response_still_acknowledges_earlier_attempt_without_fetching_jobs(tmp_path):
    identifier = uuid4().hex
    state = {'playbook_receipts': {identifier: {'receipt': {'status':'failed',
        'detail':'execution_failed', 'result':{'execution_uncertain':True}}, 'acknowledged':False}}}
    requests = []
    def handle(request):
        requests.append((request.method, request.url.path))
        return httpx.Response(200, json={'status':'failed'})
    with httpx.Client(base_url='https://fixture.example', transport=httpx.MockTransport(handle)) as client:
        poll_playbooks({'response_policy':{'enabled':False}}, state, tmp_path/'state.json', client)
    assert requests == [('POST', f'/v1/playbooks/{identifier}/receipt')]
    assert state['playbook_receipts'][identifier]['acknowledged']


def test_windows_cleanup_failure_and_recovery_emit_sensor_health(tmp_path):
    config = {'response_policy':{'enabled':False, 'platform':'windows', 'isolation':{}},
              'process_monitor':{'enabled':False}, 'malware':{'enabled':False}}
    # An existing isolation policy and prior attempt retain local recovery after
    # an administrator disables new responses.
    config['response_policy']['isolation'] = {'state_dir':r'C:\\VulnSuite\\Isolation'}
    state = {'windows_cleanup_required':True}
    with patch('vulnsuite.protection.response_agent.native_platform', return_value='windows'), \
         patch('vulnsuite.protection.windows_isolation.cleanup_expired', side_effect=[OSError('unavailable'), {'status':'cleaned','released':1}]):
        cleanup_playbooks(config, state, tmp_path/'state.json')
        collect(config, state)
        cleanup_playbooks(config, state, tmp_path/'state.json')
        collect(config, state)
    response_health = [entry for entry in state['outbox'] if entry.get('sensor')=='response']
    assert [(entry['sensor_status'],entry['sensor_detail']) for entry in response_health] == [
        ('error','execution_error'), ('ok','collected')]
    assert 'windows_cleanup_error' not in state


def test_crash_during_native_mutation_preserves_uncertainty_and_never_reexecutes(tmp_path):
    job = command('linux')
    config = {'response_policy': {'enabled': True, 'platform':'linux', 'allowed_actions':['quarantine_file']}}
    path = tmp_path/'state.json'
    received = []
    def handle(request):
        if request.method == 'POST':
            received.append(json.loads(request.content))
            return httpx.Response(200, json={'status':'failed'})
        return httpx.Response(200, json={'commands':[job]})
    with httpx.Client(base_url='https://fixture.example', transport=httpx.MockTransport(handle)) as client:
        with patch('vulnsuite.protection.response_agent.execute_playbook', side_effect=KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                poll_playbooks(config, {}, path, client)
        state = json.loads(path.read_text())
        assert state['playbook_receipts'][job['id']]['uncertain']
        assert not received
        with patch('vulnsuite.protection.response_agent.execute_playbook') as execute:
            poll_playbooks(config, state, path, client)
            execute.assert_not_called()
    assert received and all(r['status']=='failed' and r['result']['execution_uncertain'] for r in received)


@pytest.mark.parametrize('path', [r'\\server\share\payload.exe', r'\\?\C:\file',
                                r'C:\Uploads\file:stream', r'C:\Uploads\..\Windows\file', 'C:relative',
                                '/etc/file', '//server/share/payload.exe'])
def test_malware_contract_rejects_unsafe_windows_path_forms(path):
    with pytest.raises(ValueError):
        Event(kind='malware_detection', platform='windows', path=path,
              engine='sha256', sha256='a'*64, signature='fixture')
