import hashlib
import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from vulnsuite.protection.agent import collect, parse_line
from vulnsuite.protection.models import Event
from vulnsuite.protection.sensors import digest_file, malware_events, parse_modsecurity, process_events
from vulnsuite.protection.service import create_app
from vulnsuite.protection.store import Store


def make_process(root, pid, executable, ppid=1, start=100):
    directory = root / str(pid)
    directory.mkdir(exist_ok=True)
    # Fields after comm begin at state(3); starttime is field 22.
    fields = ['S', str(ppid)] + ['0'] * 17 + [str(start)]
    (directory / 'stat').write_text(f'{pid} (name with ) spaces) ' + ' '.join(fields))
    link = directory / 'exe'
    if link.is_symlink():
        link.unlink()
    link.symlink_to(executable)


def test_process_patterns_retry_and_pid_reuse(tmp_path):
    make_process(tmp_path, 1, '/usr/sbin/nginx')
    make_process(tmp_path, 2, '/bin/bash', ppid=1)
    make_process(tmp_path, 3, '/tmp/tool (deleted)', ppid=1)
    state = {}
    events, status, _ = process_events({}, state, tmp_path)
    assert status == 'ok'
    assert {e['process_rule'] for e in events} == {'web_server_shell', 'deleted_executable', 'writable_directory_execution'}
    assert process_events({}, state, tmp_path)[0] == []
    make_process(tmp_path, 2, '/bin/bash', ppid=1, start=101)
    assert process_events({}, state, tmp_path)[0][0]['process_rule'] == 'web_server_shell'
    assert all('cmdline' not in e and 'environment' not in e for e in events)


def test_allowlist_does_not_suppress_malware(tmp_path):
    binary = tmp_path / 'binary'
    binary.write_bytes(b'harmless test indicator')
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    proc = tmp_path / 'proc'
    proc.mkdir()
    make_process(proc, 1, str(binary))
    events, _, _ = process_events({'allowed_executables': [str(binary)],
                                 'known_bad_sha256': {digest: 'test-indicator'}}, {}, proc)
    assert len(events) == 1 and events[0]['kind'] == 'malware_detection'
    assert events[0]['sha256'] == digest


def test_process_outbox_budget_does_not_suppress_unsent_events(tmp_path):
    make_process(tmp_path, 1, '/tmp/test (deleted)')
    state = {}
    first, status, _ = process_events({}, state, tmp_path, max_events=1)
    assert len(first) == 1 and status == 'partial'
    second = process_events({}, state, tmp_path, max_events=1)[0]
    assert len(second) == 1 and first[0]['process_rule'] != second[0]['process_rule']


def test_digest_rejects_symlinks_and_large_files(tmp_path):
    binary = tmp_path / 'file'
    binary.write_bytes(b'test')
    link = tmp_path / 'link'
    link.symlink_to(binary)
    with pytest.raises(OSError):
        digest_file(link)
    with binary.open('wb') as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(ValueError):
        digest_file(binary)


def test_clamav_signature_scan_and_limits(tmp_path):
    binary = tmp_path / 'sample'
    binary.write_text('harmless sample')
    cfg = {'scan_files': [str(binary)], 'clamav': True}
    result = subprocess.CompletedProcess([], 1, stdout=f'{binary}: Test.Signature FOUND\n')
    with patch('vulnsuite.protection.sensors.subprocess.run', return_value=result) as run:
        events, status, _ = malware_events(cfg, {})
        assert events[0]['engine'] == 'clamav' and status == 'ok'
        args = run.call_args.args[0]
        assert '--remove' not in args and '--move' not in args
        assert '--follow-file-symlinks=0' in args and '--fail-if-cvd-older-than=7' in args
    result.stdout = f'{binary}: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n'
    with patch('vulnsuite.protection.sensors.subprocess.run', return_value=result):
        events, status, detail = malware_events(cfg, {})
        assert not events and status == 'partial' and detail == 'scan_limit'


def test_scanner_errors_are_not_clean_results(tmp_path):
    binary = tmp_path / 'file'
    binary.write_text('test')
    with patch('vulnsuite.protection.sensors.subprocess.run', side_effect=FileNotFoundError):
        events, status, detail = malware_events({'scan_files': [str(binary)], 'clamav': True}, {})
        assert not events and status == 'partial' and detail == 'scanner_error'
    assert malware_events({'scan_files': ['/missing']}, {})[1] == 'partial'
    state = {'malware_last_scan': time.time()}
    assert malware_events({}, state) == ([], None, None)


def waf_record(interrupted=False):
    return json.dumps({'transaction': {'client_ip': '10.1.2.3', 'is_interrupted': interrupted,
                       'request': {'body': 'secret', 'headers': {'Authorization': 'secret'}},
                       'messages': [{'message': 'private payload', 'details': {'ruleId': '942100',
                                     'data': 'private payload'}}]}})


def test_waf_parser_does_not_export_secrets_or_assume_blocking():
    detected = parse_modsecurity(waf_record())
    assert detected == {'kind': 'waf_match', 'source_ip': '10.1.2.3', 'rule_ids': [942100], 'waf_action': 'detected'}
    assert parse_line(waf_record(True), 'modsecurity')['waf_action'] == 'interrupted'
    record = json.loads(waf_record())
    del record['transaction']['is_interrupted']
    assert parse_modsecurity(json.dumps(record))['waf_action'] == 'unknown'
    assert 'secret' not in json.dumps(detected)
    assert parse_modsecurity('{"transaction":{"messages":[]}}') is None
    with pytest.raises(ValueError):
        parse_modsecurity('{"transaction":{"messages":[null]}}')


def test_bad_waf_and_inaccessible_files_do_not_stop_agent(tmp_path):
    log = tmp_path / 'waf.log'
    log.write_text('')
    state = {}
    cfg = {'logs': [{'kind': 'modsecurity', 'path': str(log)}, {'kind': 'ssh', 'path': '/missing'}]}
    collect(cfg, state)
    log.write_text('not JSON\n' + waf_record() + '\n')
    collect(cfg, state)
    assert any(e['kind'] == 'waf_match' for e in state['outbox'])
    assert any(e['kind'] == 'sensor_status' and e['sensor'] == 'logs' and e['sensor_status'] == 'error'
               for e in state['outbox'])
    assert state['sensor_states']['waf']['status'] == 'partial'


def test_cross_host_spray_and_fanout(tmp_path):
    store = Store(str(tmp_path / 'db'))
    now = time.time()
    for host in ('a', 'b', 'c'):
        store.ingest(host, [Event(kind='auth_failure', source_ip='10.1.2.3') for _ in range(4)], now)
        store.ingest(host, [Event(kind='auth_success', source_ip='10.1.2.3', user='alice')], now)
    rules = {a['rule'] for a in store.list_alerts()}
    assert {'cross_host_password_spray', 'remote_login_fanout'} <= rules
    # Unrelated users must not combine to manufacture fanout.
    other = Store(str(tmp_path / 'other'))
    for host in ('a', 'b', 'c'):
        other.ingest(host, [Event(kind='auth_success', source_ip='10.1.2.3', user=host)], now)
    assert not other.list_alerts()


@pytest.mark.parametrize('reverse', [False, True])
def test_pivot_detection_out_of_order_and_restart(tmp_path, reverse):
    path = str(tmp_path / 'db')
    mapping = {'10.0.1.1': 'source'}
    store = Store(path, mapping)
    now = datetime.now(timezone.utc)
    signal = Event(kind='malware_detection', path='/tmp/sample', engine='sha256',
                   sha256='a' * 64, signature='test', occurred_at=now - timedelta(seconds=1))
    login = Event(kind='auth_success', source_ip='10.0.1.1', user='alice', occurred_at=now)
    sequence = [('source', signal), ('target', login)]
    if reverse:
        sequence.reverse()
    for host, e in sequence:
        store.ingest(host, [e], now.timestamp())
        store = Store(path, mapping)
    alert = next(a for a in store.list_alerts() if a['rule'] == 'suspected_lateral_movement')
    assert alert['host'] == 'target' and alert['ip'] == '10.0.1.1'
    assert json.loads(alert['detail'])['source_host'] == 'source'
    # A source address not mapped by the administrator must not be attributed to a host.
    assert not Store(str(tmp_path / 'unmapped')).host_addresses


def test_sensor_health_and_api_validation(tmp_path):
    cfg = {'operator_token': 'o' * 40, 'hosts': {'a': {'token': 'a' * 40, 'addresses': ['10.0.1.1']}}}
    store = Store(str(tmp_path / 'db'))
    client = TestClient(create_app(cfg, store))
    e = Event(kind='sensor_status', sensor='malware', sensor_status='partial', sensor_detail='scanner_error')
    response = client.post('/v1/events', headers={'Authorization': 'Bearer ' + 'a' * 40},
                           json={'events': [e.model_dump(mode='json')]})
    assert response.status_code == 200
    assert response.json()['alerts'][0]['rule'] == 'sensor_degraded'
    hosts = client.get('/v1/hosts', headers={'Authorization': 'Bearer ' + 'o' * 40}).json()['hosts']
    assert hosts[0]['sensors'][0]['status'] == 'partial'
    for fields in ({'kind': 'process_alert'}, {'kind': 'malware_detection'},
                   {'kind': 'waf_match', 'source_ip': '10.0.0.1'}, {'kind': 'sensor_status'}):
        with pytest.raises(ValidationError):
            Event(**fields)
    cfg['hosts']['b'] = {'token': 'b' * 40, 'addresses': ['10.0.1.1']}
    with pytest.raises(ValueError):
        create_app(cfg, store)


def test_clean_scan_input_changed_is_partial(tmp_path):
    binary = tmp_path / 'file'
    binary.write_text('before')
    def changed(*args, **kwargs):
        binary.write_text('after')
        return subprocess.CompletedProcess([], 0, stdout='')
    with patch('vulnsuite.protection.sensors.subprocess.run', side_effect=changed):
        events, status, detail = malware_events({'scan_files': [str(binary)], 'clamav': True}, {})
        assert not events and status == 'partial' and detail == 'input_error'


def test_empty_detection_engine_is_not_healthy(tmp_path):
    binary = tmp_path / 'file'
    binary.write_text('test')
    assert malware_events({'scan_files': [str(binary)]}, {})[1] == 'partial'


def test_unmapped_ip_and_reversed_time_do_not_create_pivot(tmp_path):
    now = datetime.now(timezone.utc)
    store = Store(str(tmp_path / 'db'), {'10.0.1.1': 'source'})
    signal = Event(kind='process_alert', pid=1, start_ticks=10, executable='/tmp/test',
                   process_rule='writable_directory_execution', occurred_at=now)
    store.ingest('source', [signal], now.timestamp())
    store.ingest('target', [Event(kind='auth_success', source_ip='10.0.1.99', user='alice')], now.timestamp())
    store.ingest('target', [Event(kind='auth_success', source_ip='10.0.1.1', user='alice',
                                occurred_at=now - timedelta(seconds=2))], now.timestamp())
    assert all(a['rule'] != 'suspected_lateral_movement' for a in store.list_alerts())


def test_legacy_event_retry_is_normalised_after_upgrade(tmp_path):
    store = Store(str(tmp_path / 'db'))
    e = Event(kind='heartbeat')
    now = time.time()
    store.ingest('host', [e], now)
    legacy = {key: value for key, value in e.model_dump(mode='json').items()
              if key in ('event_id', 'kind', 'occurred_at', 'source_ip', 'user', 'path', 'change')}
    with store.connect() as db:
        db.execute('UPDATE events SET payload=?', (json.dumps(legacy),))
    assert store.ingest('host', [e], now) == []
