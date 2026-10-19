"""Approved process termination: plan policy, host identity re-check, pidfd signalling,
Windows handle flow and the full API/approval/agent/receipt chain. No real process is
signalled; the native adapters are replaced by fakes."""
import json
import os
import signal
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from vulnsuite.protection import process_response, response_agent, windows_process
from vulnsuite.protection.models import Event
from vulnsuite.protection.process_response import (LinuxProcessNative, prepare_termination,
                                                    terminate_process)
from vulnsuite.protection.response_agent import execute_playbook, poll_playbooks
from vulnsuite.protection.service import create_app
from vulnsuite.protection.store import Store
from vulnsuite.protection.windows_process import (prepare_windows_termination,
                                                   terminate_windows_process)

REQUEST = '0f3c7d2e9a4b4c5d8e6f7a8b9c0d1e2f'
EVIDENCE = {'pid': 4242, 'executable': '/bin/bash', 'start_ticks': 5555, 'observed_at': 1_700_000_000}
IMAGE = r'C:\inetpub\wwwroot\uploads\shell.exe'


class FakeNative:
    """Records signals; the process 'exits' only on the configured signal."""

    def __init__(self, identity, exits_on=signal.SIGTERM, absent=False, open_error=None):
        self.identity_data, self.exits_on, self.absent = identity, exits_on, absent
        self.open_error, self.signals, self.dead, self.closed = open_error, [], False, False

    def open(self, pid):
        if self.absent:
            raise ProcessLookupError(pid)
        if self.open_error:
            raise self.open_error
        return 7

    def identity(self, pid):
        if isinstance(self.identity_data, Exception):
            raise self.identity_data
        return dict(self.identity_data)

    def send(self, fd, sig):
        assert fd == 7
        self.signals.append(sig)
        if sig == self.exits_on:
            self.dead = True

    def wait(self, fd, timeout):
        return self.dead

    def close(self, fd):
        self.closed = True


def identity(**overrides):
    base = {'start_ticks': 5555, 'executable': '/bin/bash', 'deleted': False, 'uid': 33,
            'started_at': 1_699_999_990.0}
    return {**base, **overrides}


# ---------- plan policy ----------

def test_plan_is_built_from_evidence_and_refuses_protected_targets():
    plan = prepare_termination({'grace_seconds': 3}, EVIDENCE, REQUEST, now=1_700_000_100)
    assert plan == {'platform': 'linux', 'request_id': '0f3c7d2e-9a4b-4c5d-8e6f-7a8b9c0d1e2f',
                    'pid': 4242, 'executable': '/bin/bash', 'start_ticks': 5555,
                    'observed_at': 1_700_000_000, 'grace_seconds': 3, 'created_at': 1_700_000_100}
    for bad in ({**EVIDENCE, 'pid': 1}, {**EVIDENCE, 'executable': '/usr/sbin/sshd'},
                {**EVIDENCE, 'executable': 'bash'}, {**EVIDENCE, 'executable': '/tmp/../bin/sh'},
                {**EVIDENCE, 'observed_at': None}, {**EVIDENCE, 'start_ticks': -1}):
        with pytest.raises(ValueError):
            prepare_termination({}, bad, REQUEST)
    with pytest.raises(ValueError):
        prepare_termination({'protected_executables': ['/usr/bin/python3']},
                            {**EVIDENCE, 'executable': '/usr/bin/python3'}, REQUEST)
    with pytest.raises(ValueError):
        prepare_termination({'grace_seconds': 11}, EVIDENCE, REQUEST)


def test_host_rejects_plan_that_differs_from_local_policy():
    plan = prepare_termination({'grace_seconds': 2}, EVIDENCE, REQUEST, now=1_700_000_100)
    native = FakeNative(identity())
    with pytest.raises(ValueError):
        terminate_process({'grace_seconds': 5}, plan, native=native, now=1_700_000_101)
    with pytest.raises(ValueError):  # local protected list applies even to an approved plan
        terminate_process({'protected_executables': ['/bin/bash']}, plan, native=native, now=1_700_000_101)
    with pytest.raises(ValueError):  # future plan
        terminate_process({}, plan, native=native, now=1_699_999_000)
    assert native.signals == []


# ---------- host execution ----------

def test_sigterm_then_confirmed_exit_is_applied():
    plan = prepare_termination({}, EVIDENCE, REQUEST, now=1_700_000_100)
    native = FakeNative(identity())
    result = terminate_process({}, plan, native=native, now=1_700_000_101)
    assert result['status'] == 'applied' and result['detail'] == 'process_terminated'
    assert result['signal'] == 'SIGTERM' and result['pid'] == 4242 and result['uid'] == 33
    assert native.signals == [signal.SIGTERM] and native.closed


def test_escalates_to_sigkill_when_grace_expires():
    plan = prepare_termination({}, EVIDENCE, REQUEST, now=1_700_000_100)
    native = FakeNative(identity(), exits_on=signal.SIGKILL)
    result = terminate_process({}, plan, native=native, now=1_700_000_101)
    assert result['signal'] == 'SIGKILL' and native.signals == [signal.SIGTERM, signal.SIGKILL]
    stubborn = FakeNative(identity(), exits_on=None)
    with pytest.raises(OSError):
        terminate_process({}, plan, native=stubborn, now=1_700_000_101)
    assert stubborn.closed


def test_recycled_or_missing_pid_is_reported_absent_not_killed():
    plan = prepare_termination({}, EVIDENCE, REQUEST, now=1_700_000_100)
    recycled = FakeNative(identity(start_ticks=9999))
    assert terminate_process({}, plan, native=recycled, now=1_700_000_101)['detail'] == 'process_absent'
    assert recycled.signals == [] and recycled.closed
    gone = FakeNative(identity(), absent=True)
    assert terminate_process({}, plan, native=gone, now=1_700_000_101)['detail'] == 'process_absent'
    raced = FakeNative(FileNotFoundError('/proc/4242/stat'))
    assert terminate_process({}, plan, native=raced, now=1_700_000_101)['detail'] == 'process_absent'


def test_alert_time_bounds_identity_when_start_ticks_are_unknown():
    plan = prepare_termination({}, {**EVIDENCE, 'start_ticks': None}, REQUEST, now=1_700_000_100)
    later = FakeNative(identity(started_at=1_700_000_000 + 31))
    assert terminate_process({}, plan, native=later, now=1_700_000_101)['detail'] == 'process_absent'
    earlier = FakeNative(identity(started_at=1_699_999_000))
    assert terminate_process({}, plan, native=earlier, now=1_700_000_101)['status'] == 'applied'


def test_identity_mismatch_and_privileged_processes_are_policy_denied():
    plan = prepare_termination({}, EVIDENCE, REQUEST, now=1_700_000_100)
    with pytest.raises(ValueError):
        terminate_process({}, plan, native=FakeNative(identity(executable='/usr/bin/sshd')), now=1_700_000_101)
    root = FakeNative(identity(uid=0))
    with pytest.raises(ValueError):
        terminate_process({}, plan, native=root, now=1_700_000_101)
    assert root.signals == []
    allowed = FakeNative(identity(uid=0))
    assert terminate_process({'allow_privileged': True}, plan, native=allowed, now=1_700_000_101)['status'] == 'applied'
    with pytest.raises(ValueError):
        terminate_process({}, {**plan, 'pid': os.getpid()}, native=FakeNative(identity()), now=1_700_000_101)


def test_linux_native_reads_identity_through_procfs(tmp_path):
    proc = tmp_path / 'proc'
    (proc / '4242').mkdir(parents=True)
    # fields after ')': state(3) ppid(4) ... starttime is field 22, i.e. index 19.
    (proc / '4242' / 'stat').write_text('4242 (ba sh) S 100 ' + ' '.join(['0'] * 17) + ' 5555 0 0\n')
    (proc / '4242' / 'status').write_text('Name:\tbash\nUid:\t33\t33\t33\t33\n')
    (proc / '4242' / 'exe').symlink_to('/bin/bash (deleted)')
    (proc / 'stat').write_text('cpu  1 2 3\nbtime 1700000000\n')
    native = LinuxProcessNative(str(proc))
    native.clock_ticks = 100
    found = native.identity(4242)
    assert found['start_ticks'] == 5555 and found['executable'] == '/bin/bash'
    assert found['deleted'] is True and found['uid'] == 33
    assert found['started_at'] == 1_700_000_000 + 55.55


# ---------- Windows ----------

class FakeWindowsNative:
    def __init__(self, image=IMAGE, started_at=1_699_999_990.0, absent=False, exits=True):
        self.image, self.started_at, self.absent, self.exits = image, started_at, absent, exits
        self.terminated, self.closed, self.waits = False, False, []

    def open(self, pid):
        if self.absent:
            raise ProcessLookupError(pid)
        return 99

    def identity(self, handle):
        return {'executable': self.image, 'started_at': self.started_at}

    def terminate(self, handle):
        self.terminated = True

    def wait(self, handle, timeout):
        self.waits.append(timeout)
        return self.terminated and self.exits

    def close(self, handle):
        self.closed = True


def test_windows_plan_and_handle_flow():
    evidence = {'pid': 6100, 'executable': IMAGE, 'observed_at': 1_700_000_000}
    plan = prepare_windows_termination({}, evidence, REQUEST, now=1_700_000_100)
    assert plan['platform'] == 'windows' and plan['executable'] == IMAGE
    native = FakeWindowsNative()
    result = terminate_windows_process({}, plan, native=native, now=1_700_000_101)
    assert result['status'] == 'applied' and result['detail'] == 'process_terminated'
    assert native.terminated and native.closed and native.waits[0] == 0
    for bad in ({'pid': 4, 'executable': IMAGE, 'observed_at': 1_700_000_000},
                {'pid': 6100, 'executable': r'C:\Windows\System32\lsass.exe', 'observed_at': 1_700_000_000},
                {'pid': 6100, 'executable': '/bin/bash', 'observed_at': 1_700_000_000}):
        with pytest.raises(ValueError):
            prepare_windows_termination({}, bad, REQUEST)


def test_windows_refuses_recycled_pid_and_other_images():
    plan = prepare_windows_termination({}, {'pid': 6100, 'executable': IMAGE, 'observed_at': 1_700_000_000},
                                       REQUEST, now=1_700_000_100)
    recycled = FakeWindowsNative(started_at=1_700_000_100.0)
    assert terminate_windows_process({}, plan, native=recycled, now=1_700_000_101)['detail'] == 'process_absent'
    assert not recycled.terminated and recycled.closed
    other = FakeWindowsNative(image=r'C:\Windows\System32\notepad.exe')
    with pytest.raises(ValueError):
        terminate_windows_process({}, plan, native=other, now=1_700_000_101)
    assert not other.terminated
    assert terminate_windows_process({}, plan, native=FakeWindowsNative(absent=True), now=1_700_000_101)['detail'] == 'process_absent'
    stuck = FakeWindowsNative(exits=False)
    with pytest.raises(OSError):
        terminate_windows_process({}, plan, native=stuck, now=1_700_000_101)


def test_windows_native_adapter_is_never_built_off_windows():
    plan = prepare_windows_termination({}, {'pid': 6100, 'executable': IMAGE, 'observed_at': 1_700_000_000},
                                       REQUEST, now=1_700_000_100)
    if os.name != 'nt':
        with pytest.raises(ValueError):
            terminate_windows_process({}, plan, now=1_700_000_101)


# ---------- agent policy gate ----------

def test_agent_requires_local_enablement_and_matching_job_id():
    plan = prepare_termination({}, EVIDENCE, REQUEST, now=None)
    plan['expires_at'] = plan['created_at'] + 120
    command = {'id': REQUEST, 'action': 'terminate_process', 'plan': plan}
    with patch.object(response_agent, 'native_platform', return_value='linux'):
        denied = execute_playbook({'response_policy': {'enabled': True, 'allowed_actions': ['isolate_host']}}, command)
        assert denied == {'status': 'failed', 'detail': 'policy_denied', 'result': {}}
        policy = {'enabled': True, 'allowed_actions': ['terminate_process'], 'termination': {}}
        mismatch = execute_playbook({'response_policy': policy}, {**command, 'id': 'a' * 32})
        assert mismatch['detail'] == 'policy_denied'
        with patch.object(process_response, 'LinuxProcessNative', lambda: FakeNative(identity())):
            applied = execute_playbook({'response_policy': policy}, command)
    assert applied['status'] == 'applied' and applied['detail'] == 'process_terminated'
    assert applied['result']['platform'] == 'linux' and applied['result']['signal'] == 'SIGTERM'


# ---------- end to end ----------

KEYS = {'requester': 'r' * 40, 'approver': 'a' * 40, 'host': 'h' * 40}


def auth(actor):
    return {'Authorization': 'Bearer ' + KEYS[actor]}


@pytest.fixture
def system(tmp_path):
    policy = {'enabled': True, 'allowed_actions': ['terminate_process', 'quarantine_file'],
              'termination': {'grace_seconds': 1},
              'quarantine': {'quarantine_dir': str(tmp_path), 'allowed_paths': ['/srv/x']}}
    config = {'operators': {actor: {'token': KEYS[actor], 'roles': ['admin']} for actor in ('requester', 'approver')},
              'hosts': {'web-1': {'token': KEYS['host'], 'addresses': ['10.10.0.10']}},
              'response': {'hosts': {'web-1': policy}}}
    store = Store(str(tmp_path / 'control.sqlite'))
    client = TestClient(create_app(config, store), headers=auth('host'))
    return {'client': client, 'store': store, 'policy': policy, 'state_path': tmp_path / 'state.json'}


def alert_for(system, event):
    response = system['client'].post('/v1/events', json={'events': [event.model_dump(mode='json')]})
    assert response.status_code == 200, response.text
    return response.json()['alerts'][0]


def shell_alert(system):
    return alert_for(system, Event(kind='process_alert', pid=4242, ppid=100, start_ticks=5555,
                                   executable='/bin/bash', parent_executable='/usr/sbin/nginx',
                                   process_rule='web_server_shell'))


def request(system, alert_id, **extra):
    return system['client'].post('/v1/playbooks', headers=auth('requester'), json={
        'alert_id': alert_id, 'action': 'terminate_process', 'duration_seconds': 120,
        'reason': 'Web shell confirmed from nginx worker; terminate before isolation', **extra})


def job_row(system, identifier):
    with system['store'].connect() as db:
        return dict(db.execute('SELECT * FROM response_jobs WHERE id=?', (identifier,)).fetchone())


def test_request_approve_execute_and_receipt(system):
    alert = shell_alert(system)
    assert alert['rule'] == 'web_server_shell'
    created = request(system, alert['id'])
    assert created.status_code == 201, created.text
    job = created.json()
    assert job['plan']['pid'] == 4242 and job['plan']['start_ticks'] == 5555
    assert job['plan']['executable'] == '/bin/bash' and job['plan']['platform'] == 'linux'
    assert job['plan']['observed_at'] == int(alert['created']) and job['plan']['grace_seconds'] == 1
    assert job['expires_at'] <= job['plan']['created_at'] + 300
    # Same operator cannot approve; nothing dispatches before approval.
    assert system['client'].post(f"/v1/playbooks/{job['id']}/approve", headers=auth('requester')).status_code == 403
    assert system['client'].get('/v1/playbooks/commands').json()['commands'] == []
    assert system['client'].post(f"/v1/playbooks/{job['id']}/approve", headers=auth('approver')).status_code == 200
    native = FakeNative(identity())
    state = {}
    with patch.object(response_agent, 'native_platform', return_value='linux'), \
         patch.object(process_response, 'LinuxProcessNative', lambda: native):
        poll_playbooks({'response_policy': system['policy']}, state, system['state_path'], system['client'])
    row = job_row(system, job['id'])
    assert row['status'] == 'applied' and row['approved_by'] == 'approver'
    result = json.loads(row['result'])
    assert result['detail'] == 'process_terminated' and result['signal'] == 'SIGTERM' and result['pid'] == 4242
    assert native.signals == [signal.SIGTERM]
    with system['store'].connect() as db:
        actions = [r[0] for r in db.execute('SELECT action FROM audit ORDER BY id')]
    assert actions[-3:] == ['playbook_requested', 'playbook_approved', 'playbook_receipt']
    # A restarted agent never signals twice for the same approved job.
    with patch.object(response_agent, 'execute_playbook') as execute:
        poll_playbooks({'response_policy': system['policy']}, json.loads(system['state_path'].read_text()),
                       system['state_path'], system['client'])
        execute.assert_not_called()


def test_absent_process_receipt_is_accepted_and_recorded_as_failed(system):
    job = request(system, shell_alert(system)['id']).json()
    system['client'].post(f"/v1/playbooks/{job['id']}/approve", headers=auth('approver'))
    with patch.object(response_agent, 'native_platform', return_value='linux'), \
         patch.object(process_response, 'LinuxProcessNative', lambda: FakeNative(identity(start_ticks=1))):
        poll_playbooks({'response_policy': system['policy']}, {}, system['state_path'], system['client'])
    row = job_row(system, job['id'])
    assert row['status'] == 'failed' and json.loads(row['result'])['detail'] == 'process_absent'


def test_process_absent_is_only_a_valid_receipt_for_termination(system):
    malware = alert_for(system, Event(kind='malware_detection', path='/srv/x', sha256='a' * 64,
                                      engine='sha256', signature='inert'))
    quarantine = system['client'].post('/v1/playbooks', headers=auth('requester'), json={
        'alert_id': malware['id'], 'action': 'quarantine_file', 'duration_seconds': 120,
        'reason': 'Inert fixture quarantine for receipt validation'}).json()
    system['client'].post(f"/v1/playbooks/{quarantine['id']}/approve", headers=auth('approver'))
    receipt = system['client'].post(f"/v1/playbooks/{quarantine['id']}/receipt",
                                    json={'status': 'failed', 'detail': 'process_absent', 'result': {}})
    assert receipt.status_code == 422


def test_evidence_and_policy_gates_on_request(system):
    # File-based malware alert carries no PID: not a termination target.
    file_alert = alert_for(system, Event(kind='malware_detection', path='/srv/x', sha256='b' * 64,
                                         engine='clamav', signature='Eicar-Test'))
    assert request(system, file_alert['id']).status_code == 409
    # Process-scan malware alert carries pid and start ticks: accepted.
    proc_alert = alert_for(system, Event(kind='malware_detection', path='/tmp/miner', sha256='c' * 64,
                                         engine='sha256', signature='xmrig', pid=777, start_ticks=42))
    accepted = request(system, proc_alert['id'])
    assert accepted.status_code == 201 and accepted.json()['plan']['start_ticks'] == 42
    # Protected executable in the evidence is refused by server-side policy.
    sshd = alert_for(system, Event(kind='process_alert', pid=900, ppid=1, start_ticks=10,
                                   executable='/usr/sbin/sshd', process_rule='deleted_executable'))
    assert request(system, sshd['id']).status_code == 403
    # Action not enabled for the host.
    system['policy']['allowed_actions'].remove('terminate_process')
    assert request(system, shell_alert(system)['id']).status_code == 403
