"""Log tamper detection and telemetry integrity: agent-side truncation/deletion
signals, auditd watch correlation, Windows log-cleared events, per-agent sequence
numbers, the per-host hash chain, external checkpoints and chain verification."""
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from vulnsuite.protection import agent as agent_module
from vulnsuite.protection.agent import assign_sequence, collect, collect_log, cycle, event
from vulnsuite.protection.maintenance import verify_chain
from vulnsuite.protection.models import Event
from vulnsuite.protection.service import create_app
from vulnsuite.protection.store import Store
from vulnsuite.protection.telemetry import EVENTLOG, SECURITY, LinuxAuditCorrelator, parse_windows_event


# ---------- agent: file-level signals ----------

def test_truncation_of_the_same_inode_is_reported_but_rotation_is_not(tmp_path):
    log = tmp_path / 'auth.log'
    log.write_text('Oct 19 sshd[1]: Accepted password for alice from 10.1.1.5 port 1 ssh2\n')
    offsets = {}
    source = {'path': str(log), 'kind': 'ssh', 'read_from_start': True}
    events, status, _ = collect_log(source, offsets, 100)
    assert status == 'ok' and [e['kind'] for e in events] == ['auth_success']
    log.write_text('')  # same inode shrinks: evidence was removed
    events, _, _ = collect_log(source, offsets, 100)
    assert [(e['kind'], e['tamper'], e['path']) for e in events] == [('log_tamper', 'truncated', str(log))]
    assert offsets[str(log)]['position'] == 0
    # logrotate-style rename creates a new inode: normal, no alert.
    log.rename(tmp_path / 'auth.log.1')
    log.write_text('Oct 19 sshd[1]: Failed password for bob from 10.1.1.6 port 1 ssh2\n')
    events, _, _ = collect_log(source, offsets, 100)
    assert [e['kind'] for e in events] == ['auth_failure']


def test_copytruncate_sources_do_not_alert_and_rotation_none_reports_replacement(tmp_path):
    log = tmp_path / 'app.log'
    log.write_text('{"status": 401, "remote_addr": "10.1.1.7"}\n')
    offsets = {}
    copy = {'path': str(log), 'kind': 'api', 'read_from_start': True, 'rotation': 'copytruncate'}
    collect_log(copy, offsets, 100)
    log.write_text('')
    events, _, _ = collect_log(copy, offsets, 100)
    assert events == []
    pinned = {'path': str(log), 'kind': 'api', 'rotation': 'none'}
    offsets = {}
    collect_log(pinned, offsets, 100)
    log.rename(tmp_path / 'app.log.moved')  # keeps the old inode alive so the new file differs
    log.write_text('')
    events, _, _ = collect_log(pinned, offsets, 100)
    assert [e['tamper'] for e in events] == ['replaced']


def test_missing_log_is_reported_once_and_recovers(tmp_path):
    log = tmp_path / 'secure'
    log.write_text('')
    offsets = {}
    source = {'path': str(log), 'kind': 'ssh'}
    collect_log(source, offsets, 100)
    log.unlink()
    events, status, detail = collect_log(source, offsets, 100)
    assert [e['tamper'] for e in events] == ['deleted'] and (status, detail) == ('error', 'input_error')
    with pytest.raises(FileNotFoundError):  # second cycle: ordinary access error, no duplicate alert
        collect_log(source, offsets, 100)
    log.write_text('Oct 19 sshd[1]: Failed password for bob from 10.1.1.6 port 1 ssh2\n')
    events, status, _ = collect_log(source, offsets, 100)
    assert status == 'ok' and [e['kind'] for e in events] == ['auth_failure']  # recreated file read from start
    assert not offsets[str(log)].get('missing')
    # A brand-new source that never existed is not tampering.
    with pytest.raises(FileNotFoundError):
        collect_log({'path': str(tmp_path / 'never'), 'kind': 'ssh'}, {}, 100)


# ---------- agent: auditd watch correlation ----------

def syscall(serial, key='vulnsuite_log_tamper', exe='"/usr/bin/truncate"', success='yes'):
    return (f'type=SYSCALL msg=audit(1792402200.100:{serial}): arch=c000003e syscall=76 success={success} '
            f'exit=0 pid=4242 ppid=1 auid=1000 uid=0 exe={exe} key="{key}"')


def path_record(serial, name='"/var/log/auth.log"', nametype='NORMAL'):
    return f'type=PATH msg=audit(1792402200.100:{serial}): item=0 name={name} inode=1 nametype={nametype}'


def test_syscall_and_path_records_become_one_tamper_event():
    correlator = LinuxAuditCorrelator()
    assert correlator.feed(syscall(7)) == []
    assert correlator.feed('type=CWD msg=audit(1792402200.100:7): cwd="/root"') == []
    assert correlator.feed(path_record(7, nametype='DELETE')) == []
    events = correlator.feed('type=PROCTITLE msg=audit(1792402200.100:8): proctitle=secret')
    assert len(events) == 1
    tamper = events[0]
    assert tamper['kind'] == 'log_tamper' and tamper['tamper'] == 'deleted'
    assert tamper['path'] == '/var/log/auth.log' and tamper['executable'] == '/usr/bin/truncate'
    assert tamper['pid'] == 4242 and tamper['user'] == '1000' and tamper['occurred_at'].startswith('2026-10-19')
    Event(**tamper)
    assert correlator.flush() == []


def test_hex_encoded_path_boundary_flush_ignore_list_and_exec_passthrough():
    correlator = LinuxAuditCorrelator(ignore_executables=['/usr/sbin/logrotate'])
    correlator.feed(syscall(9))
    correlator.feed(path_record(9, name='2F7661722F6C6F672F617574682E6C6F67', nametype='NORMAL'))
    flushed = correlator.flush()
    assert flushed[0]['path'] == '/var/log/auth.log' and flushed[0]['tamper'] == 'written'
    # Unfinished event at a read boundary is still reported, without the path.
    correlator.feed(syscall(10))
    assert correlator.flush()[0].get('path') is None
    # Known writers are dropped on the host; failed syscalls are not evidence.
    assert correlator.feed(syscall(11, exe='"/usr/sbin/logrotate"')) == [] and correlator.flush() == []
    assert correlator.feed(syscall(12, success='no')) == [] and correlator.flush() == []
    exec_line = ('type=SYSCALL msg=audit(1792402200.123:13): arch=c000003e syscall=59 success=yes pid=891 '
                 'ppid=10 exe="/tmp/transient" key="vulnsuite_exec"')
    assert [e['kind'] for e in correlator.feed(exec_line)] == ['process_start']


def test_agent_reads_audit_watch_records_through_collect(tmp_path):
    log = tmp_path / 'audit.log'
    log.write_text(syscall(21) + '\n' + path_record(21, nametype='DELETE') + '\n')
    cfg = {'logs': [{'path': str(log), 'kind': 'linux_audit', 'read_from_start': True}]}
    state = {}
    collect(cfg, state)
    kinds = [e['kind'] for e in state['outbox']]
    assert 'log_tamper' in kinds and kinds[-1] == 'heartbeat'
    agent_module._AUDIT_CORRELATORS.pop(str(log), None)


# ---------- Windows ----------

def test_windows_log_cleared_and_policy_change_events():
    base = {'RecordId': '77', 'TimeCreated': '2026-10-19T09:30:00Z', 'Keywords': '0x8020000000000000'}
    cleared = parse_windows_event({**base, 'Provider': EVENTLOG, 'EventId': 1102,
                                   'EventData': {'SubjectUserName': 'mallory', 'SubjectDomainName': 'CORP'}})
    assert cleared['kind'] == 'log_tamper' and cleared['tamper'] == 'cleared'
    assert cleared['user'] == 'CORP\\mallory' and cleared['telemetry_source'] == 'windows_security'
    Event(**cleared)
    policy = parse_windows_event({**base, 'Provider': SECURITY, 'EventId': 4719, 'EventData': {'SubjectUserName': '-'}})
    assert policy['tamper'] == 'audit_policy_changed' and 'user' not in policy
    stopped = parse_windows_event({**base, 'Provider': EVENTLOG, 'EventId': 1100, 'EventData': {}})
    assert stopped['tamper'] == 'audit_stopped'
    assert parse_windows_event({**base, 'Provider': SECURITY, 'EventId': 1102, 'EventData': {}}) is None


# ---------- model ----------

def test_tamper_event_requires_evidence_and_sequence_bounds():
    with pytest.raises(ValueError):
        Event(kind='log_tamper')
    with pytest.raises(ValueError):
        Event(kind='heartbeat', sequence=0)
    assert Event(kind='heartbeat', sequence=1).sequence == 1


# ---------- agent: sequence numbers ----------

def test_sequence_is_assigned_once_persisted_and_monotonic(tmp_path):
    state = {}
    first = [event({'kind': 'heartbeat'}), event({'kind': 'heartbeat'})]
    assign_sequence(state, first)
    assert [e['sequence'] for e in first] == [1, 2] and state['sequence'] == 2
    assign_sequence(state, first)  # idempotent
    assert [e['sequence'] for e in first] == [1, 2]
    delivered = []

    def server(request):
        if request.method == 'GET':
            return httpx.Response(200, json={'commands': []})
        batch = json.loads(request.content)['events']
        delivered.extend(batch)
        return httpx.Response(200, json={'accepted': len(batch)})

    path = tmp_path / 'state.json'
    with httpx.Client(base_url='https://protection.test', transport=httpx.MockTransport(server)) as client:
        cycle({}, {}, path, client)
        cycle({}, json.loads(path.read_text()), path, client)
    assert [e['sequence'] for e in delivered] == [1, 2]
    assert json.loads(path.read_text())['sequence'] == 2


# ---------- server: alerts, chain, checkpoints, verification ----------

@pytest.fixture
def system(tmp_path):
    config = {'operators': {'op': {'token': 'o' * 40, 'roles': ['admin']}},
              'hosts': {'web-1': {'token': 'h' * 40}},
              'integrations': {'siem': {'enabled': True, 'type': 'webhook', 'url': 'https://siem.example/x',
                                        'token_env': 'T', 'signing_key_env': 'S'}}}
    store = Store(str(tmp_path / 'control.sqlite'))
    client = TestClient(create_app(config, store), headers={'Authorization': 'Bearer ' + 'h' * 40})
    return {'client': client, 'store': store, 'database': tmp_path / 'control.sqlite',
            'operator': {'Authorization': 'Bearer ' + 'o' * 40}}


def send(system, events):
    response = system['client'].post('/v1/events', json={'events': [e.model_dump(mode='json') for e in events]})
    assert response.status_code == 200, response.text
    return response.json()['alerts']


def test_tamper_events_raise_critical_or_high_alerts(system):
    alerts = send(system, [Event(kind='log_tamper', tamper='truncated', path='/var/log/auth.log', sequence=1),
                           Event(kind='log_tamper', tamper='written', path='/etc/rsyslog.conf',
                                 executable='/usr/bin/vim', pid=55, user='1000', sequence=2)])
    assert [(a['rule'], a['severity']) for a in alerts] == [('log_tampering', 'critical'), ('log_tampering', 'high')]
    assert json.loads(alerts[1]['detail'])['executable'] == '/usr/bin/vim'


def test_sequence_gap_and_reset_alerts(system):
    assert send(system, [Event(kind='heartbeat', sequence=1), Event(kind='heartbeat', sequence=2)]) == []
    gap = send(system, [Event(kind='heartbeat', sequence=6)])
    assert [a['rule'] for a in gap] == ['telemetry_gap'] and json.loads(gap[0]['detail'])['missing'] == 3
    assert send(system, [Event(kind='heartbeat', sequence=7)]) == []
    reset = send(system, [Event(kind='heartbeat', sequence=1)])
    assert [(a['rule'], a['severity']) for a in reset] == [('telemetry_sequence_reset', 'high')]
    # Replayed (archived) telemetry still participates in the sequence check but not in detections.
    from datetime import datetime, timedelta, timezone
    old = datetime.now(timezone.utc) - timedelta(hours=2)
    replay = send(system, [Event(kind='auth_failure', source_ip='10.9.9.9', occurred_at=old, sequence=2)])
    assert [a['rule'] for a in replay] == ['telemetry_gap'] or replay == []  # dedup window may absorb it
    assert system['store'].chain_status('web-1')['last_sequence'] == 2


def test_chain_head_checkpoint_and_verification(system, monkeypatch):
    events = [Event(kind='heartbeat', sequence=i) for i in range(1, 4)]
    send(system, events)
    status = system['client'].get('/v1/hosts/web-1/telemetry-chain', headers=system['operator']).json()
    assert status['count'] == 3 and len(status['head']) == 64 and status['last_sequence'] == 3
    assert system['client'].get('/v1/hosts/nobody/telemetry-chain', headers=system['operator']).status_code == 404
    # Recompute by hand: each link hashes the previous link and the stored payload.
    with system['store'].connect() as db:
        rows = [dict(r) for r in db.execute("SELECT payload,chain FROM events WHERE host='web-1' ORDER BY rowid")]
        queued = [json.loads(r[0]) for r in db.execute("SELECT payload FROM deliveries WHERE connector='siem'")]
    link = ''
    for row in rows:
        link = Store.chain_link(link, row['payload'])
        assert row['chain'] == link
    assert link == status['head']
    checkpoints = [q for q in queued if q['type'] == 'telemetry.checkpoint']
    assert len(checkpoints) == 1 and checkpoints[0]['data']['head'] == status['head']
    # Another batch within the hour does not checkpoint again; after an hour it does.
    send(system, [Event(kind='heartbeat', sequence=4)])
    with system['store'].connect() as db:
        db.execute("UPDATE telemetry_chain SET checkpoint_at=checkpoint_at-7200")
    send(system, [Event(kind='heartbeat', sequence=5)])
    with system['store'].connect() as db:
        count = db.execute("SELECT count(*) FROM deliveries WHERE payload LIKE '%telemetry.checkpoint%'").fetchone()[0]
    assert count == 2
    verified = verify_chain(system['database'], 'web-1')['web-1']
    assert verified['verified'] and verified['events_verified'] == 5 and verified['broken_at_rowid'] is None
    # Editing one stored event breaks the chain at that row; deleting the tail breaks the head.
    with system['store'].connect() as db:
        db.execute("UPDATE events SET payload=replace(payload,'heartbeat','heartbeat ') WHERE rowid=2")
    tampered = verify_chain(system['database'], 'web-1')['web-1']
    assert not tampered['verified'] and tampered['broken_at_rowid'] == 2
    with system['store'].connect() as db:
        db.execute("UPDATE events SET payload=replace(payload,'heartbeat ','heartbeat') WHERE rowid=2")
        db.execute("DELETE FROM events WHERE rowid=5")
    truncated = verify_chain(system['database'])['web-1']
    assert truncated['broken_at_rowid'] is None and not truncated['head_matches'] and not truncated['verified']
    # Retention removing the oldest events keeps the chain verifiable from the anchor.
    with system['store'].connect() as db:
        db.execute("DELETE FROM events WHERE rowid=1")
    assert verify_chain(system['database'])['web-1']['head_matches'] is False  # tail still missing
    with system['store'].connect() as db:
        actions = [r[0] for r in db.execute("SELECT action FROM audit WHERE action='telemetry_chain_verified'")]
    assert len(actions) == 4
