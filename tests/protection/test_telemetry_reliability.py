import json
import subprocess
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx
import pytest

from vulnsuite.protection.agent import collect, cycle, event, parse_line
from vulnsuite.protection.telemetry import parse_linux_audit, parse_windows_event, SECURITY, SYSMON
from vulnsuite.protection.windows_agent import collect_windows


def windows(code=4624, provider=SECURITY, **fields):
    data = {'IpAddress': '::ffff:10.2.3.4', 'LogonType': '10', 'TargetUserName': 'alice',
            'TargetDomainName': 'EXAMPLE', 'CommandLine': 'password=secret', **fields}
    return {'Provider': provider, 'EventId': code, 'RecordId': '1001',
            'TimeCreated': '2026-10-19T09:30:00Z', 'Keywords': '0x8020000000000000',
            'EventData': data, 'Message': 'password=secret'}


def audit_line(stamp='1792402200.123', **fields):
    data = {'arch': 'c000003e', 'syscall': '59', 'success': 'yes', 'pid': '891', 'ppid': '10',
            'exe': '"/tmp/transient"', 'key': '"vulnsuite_exec"', 'a0': 'secret', **fields}
    return f'type=SYSCALL msg=audit({stamp}:1234): ' + ' '.join(f'{k}={v}' for k, v in data.items())


def test_linux_exec_original_time_and_redaction():
    parsed = parse_linux_audit(audit_line())
    assert parsed['kind'] == 'process_start'
    assert parsed['executable'] == '/tmp/transient' and parsed['pid'] == 891
    assert parsed['record_id'] == '1792402200.123:1234'
    assert parsed['occurred_at'] == datetime.fromtimestamp(1792402200.123, timezone.utc).isoformat()
    assert parse_linux_audit(audit_line())['event_id'] == parsed['event_id']
    assert 'secret' not in json.dumps(event(parsed))
    assert parse_linux_audit(audit_line(success='no')) is None
    assert parse_linux_audit(audit_line(syscall='0')) is None
    assert parse_linux_audit(audit_line(arch='unknown')) is None
    assert parse_linux_audit('type=EXECVE msg=audit(1792402200.123:1234): argc=1 a0="secret"') is None
    assert parse_linux_audit(audit_line(exe='/tmp/transient'.encode().hex()))['executable'] == '/tmp/transient'


def test_windows_remote_auth_protocol_requires_evidence():
    parsed = parse_windows_event(windows())
    assert parsed['protocol'] == 'rdp' and parsed['kind'] == 'auth_success'
    assert parsed['source_ip'] == '10.2.3.4' and parsed['user'] == 'EXAMPLE\\alice'
    assert parsed['event_code'] == 4624 and parsed['logon_type'] == 10
    assert 'secret' not in json.dumps(event(parsed))
    failed = parse_windows_event(windows(4625, LogonType='3'))
    assert failed['kind'] == 'auth_failure' and failed['protocol'] == 'network'
    assert parse_windows_event(windows(LogonType='2', IpAddress='-')) is None
    assert parse_windows_event(windows(IpAddress='127.0.0.1')) is None
    with pytest.raises(ValueError):
        parse_windows_event(windows(IpAddress='-'))
    smb = windows(5140, SubjectUserName='alice', SubjectDomainName='EXAMPLE')
    assert parse_windows_event(smb)['protocol'] == 'smb'
    smb['Keywords'] = '0x8010000000000000'
    assert parse_windows_event(smb)['kind'] == 'auth_failure'
    smb['Keywords'] = '0'
    with pytest.raises(ValueError):
        parse_windows_event(smb)


def test_sysmon_process_metadata_omits_arguments():
    row = windows(1, SYSMON, Image=r'C:\Windows\System32\cmd.exe',
                  ParentImage=r'C:\Windows\System32\wsmprovhost.exe', User=r'EXAMPLE\alice',
                  ProcessId='44', ParentProcessId='20', Hashes='SHA256=' + 'a' * 64,
                  ParentCommandLine='credentials=secret', Environment='secret')
    parsed = event(parse_windows_event(row))
    assert parsed['kind'] == 'process_start' and parsed['protocol'] == 'winrm'
    assert parsed['sha256'] == 'a' * 64 and parsed['pid'] == 44
    assert not parsed['source_ip']
    assert 'secret' not in json.dumps(parsed)
    assert parse_line(json.dumps(row), 'windows_event')['event_id'] == parsed['event_id']


@pytest.mark.parametrize('reply', [{}, {'accepted': True}, {'accepted': 0}, {'accepted': 2}, []])
def test_incomplete_ack_keeps_batch_durable(tmp_path, reply):
    state, path = {}, tmp_path / 'agent.json'
    with httpx.Client(base_url='https://protection.test', transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=reply))) as client:
        with pytest.raises(ValueError):
            cycle({}, state, path, client)
    saved = json.loads(path.read_text())
    assert len(saved['outbox']) == 1
    assert saved['delivery']['status'] == 'error'
    assert saved['delivery']['detail'] == 'ack_error'


def test_422_never_discards_old_evidence(tmp_path):
    old = event({'kind': 'auth_failure', 'source_ip': '10.2.3.4',
                 'occurred_at': datetime.now(timezone.utc) - timedelta(days=8)})
    state, path = {'outbox': [old]}, tmp_path / 'agent.json'
    with httpx.Client(base_url='https://protection.test', transport=httpx.MockTransport(
            lambda request: httpx.Response(422, json={'detail': 'outside archive retention'}))) as client:
        for _ in range(2):
            with pytest.raises(httpx.HTTPStatusError):
                cycle({}, state, path, client)
    saved = json.loads(path.read_text())
    assert saved['outbox'][0]['event_id'] == old['event_id']
    assert saved['delivery']['failures'] == 2
    assert saved['health_outbox'][1]['sensor_detail'] == 'delivery_error'


def test_full_queue_pauses_offsets_reports_health_and_recovers(tmp_path):
    logfile = tmp_path / 'audit.log'
    logfile.write_text(audit_line() + '\n')
    cfg = {'queue_capacity': 100, 'logs': [{'path': str(logfile), 'kind': 'linux_audit', 'read_from_start': True}]}
    state = {'outbox': [event({'kind': 'auth_failure', 'source_ip': '10.2.3.4'}) for _ in range(90)]}
    before = [item['event_id'] for item in state['outbox']]
    collect(cfg, state)
    assert state['collection_paused'] and not state.get('offsets')
    batches = []
    def server(request):
        if request.method == 'GET':
            return httpx.Response(200, json={'commands': []})
        batch = json.loads(request.content)['events']
        batches.append(batch)
        return httpx.Response(200, json={'accepted': len(batch)})
    with httpx.Client(base_url='https://protection.test', transport=httpx.MockTransport(server)) as client:
        cycle(cfg, state, tmp_path / 'state.json', client)
    assert batches[0][0]['collection_paused'] is True
    assert batches[0][1]['sensor_detail'] == 'backpressure'
    assert [e['event_id'] for batch in batches[1:] for e in batch if e['kind'] == 'auth_failure'] == before
    assert batches[-1][0]['collection_paused'] is False
    assert batches[-1][1]['sensor_status'] == 'ok'
    collect(cfg, state)
    assert state['collection_paused'] is False
    assert any(e['kind'] == 'process_start' for e in state['outbox'])
    heartbeat = state['outbox'][-1]
    assert heartbeat['agent_version'] and heartbeat['platform'] == 'linux'
    assert heartbeat['queue_capacity'] == 100 and heartbeat['hostname']


def test_windows_cursors_only_advance_with_valid_export_envelope(tmp_path):
    script = tmp_path / 'export.ps1'
    cfg = {'export_script': str(script)}
    state = {'windows_cursors': {'Security': 1000}}
    row = windows()
    good = subprocess.CompletedProcess([], 0, stdout=json.dumps({
        'records': [row], 'cursors': {'Security': 1001}, 'errors': []}), stderr='')
    with patch('vulnsuite.protection.windows_agent.subprocess.run', return_value=good) as run:
        items, status, detail = collect_windows(cfg, state, 10)
    assert status == 'ok' and detail == 'collected'
    assert state['windows_cursors']['Security'] == 1001
    assert items[0]['protocol'] == 'rdp' and 'secret' not in json.dumps(items)
    assert '-NoProfile' in run.call_args.args[0] and 'shell' not in run.call_args.kwargs
    invalid = subprocess.CompletedProcess([], 0, stdout=json.dumps({
        'records': [row] * 11, 'cursors': {'Security': 2000}}), stderr='')
    with patch('vulnsuite.protection.windows_agent.subprocess.run', return_value=invalid):
        assert collect_windows(cfg, state, 10)[1] == 'error'
    assert state['windows_cursors']['Security'] == 1001
