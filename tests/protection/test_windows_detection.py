"""Synthetic Sysmon fixtures: exact indicator matching, bounded durable delivery."""
import json
import subprocess
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from vulnsuite.protection.models import Event
from vulnsuite.protection.store import Store
from vulnsuite.protection.telemetry import SYSMON, parse_windows_event, windows_hash_detection
from vulnsuite.protection.windows_agent import collect_windows

DIGEST = 'a' * 64
IMAGE = r'C:\ProgramData\Uploads\sample.exe'


def sysmon(hashes='SHA256=' + DIGEST, **overrides):
    row = {'Provider': SYSMON, 'EventId': 1, 'RecordId': '1234',
           'TimeCreated': datetime.now(timezone.utc).isoformat(),
           'EventData': {'Image': IMAGE, 'ParentImage': r'C:\Windows\System32\services.exe',
                         'User': r'EXAMPLE\service', 'ProcessId': '4321', 'ParentProcessId': '210',
                         'Hashes': hashes, 'CommandLine': 'secret-command-line',
                         'ParentCommandLine': 'secret-parent-arguments'},
           'Message': 'secret raw event message'}
    row.update(overrides)
    return row


def exported(records, cursor=1234):
    return subprocess.CompletedProcess([], 0, stdout=json.dumps({
        'records': records, 'cursors': {'Microsoft-Windows-Sysmon/Operational': cursor},
        'errors': []}), stderr='')


def config(tmp_path, **overrides):
    return {'export_script': str(tmp_path / 'export.ps1'),
            'known_bad_sha256': {DIGEST: 'Reviewed sample IOC'}, **overrides}


def test_exact_sysmon_hash_match_produces_distinct_supported_malware_evidence(tmp_path):
    row = sysmon()
    process = parse_windows_event(row)
    detection = windows_hash_detection(process, {DIGEST: 'Reviewed sample IOC'})
    parsed = Event(**detection)
    assert parsed.kind == 'malware_detection'
    assert parsed.platform == 'windows' and parsed.telemetry_source == 'windows_sysmon'
    assert parsed.path == IMAGE and parsed.sha256 == DIGEST and parsed.engine == 'sha256'
    assert str(parsed.event_id) != process['event_id']
    assert parsed.occurred_at.isoformat() == process['occurred_at']
    assert windows_hash_detection(process, {DIGEST: 'Reviewed sample IOC'}) == detection
    assert 'secret' not in json.dumps(detection)
    store = Store(str(tmp_path / 'events.sqlite'))
    alerts = store.ingest('windows-server', [Event(**process), parsed], datetime.now(timezone.utc).timestamp())
    assert [alert['rule'] for alert in alerts] == ['malware_detected']
    assert json.loads(alerts[0]['detail'])['sha256'] == DIGEST
    assert store.ingest('windows-server', [Event(**process), parsed], datetime.now(timezone.utc).timestamp()) == []
    with store.connect() as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 2


@pytest.mark.parametrize('hashes', [
    '', 'SHA1=' + 'a' * 40, 'SHA256=' + 'b' * 64, 'SHA256=not-a-digest',
    'SHA256=' + DIGEST + ',SHA256=' + 'b' * 64, None,
])
def test_unknown_missing_or_ambiguous_hash_never_becomes_malware(hashes):
    process = parse_windows_event(sysmon(hashes))
    assert process['kind'] == 'process_start'
    assert windows_hash_detection(process, {DIGEST: 'Reviewed sample IOC'}) is None


def test_hash_parser_accepts_sysmon_whitespace_and_hex_case():
    process = parse_windows_event(sysmon('SHA1=' + 'b' * 40 + ', SHA256=' + 'A' * 64 + ',IMPHASH=abcd'))
    assert process['sha256'] == DIGEST


def test_only_sysmon_process_creation_can_generate_hash_detection():
    process = parse_windows_event(sysmon())
    for changed in ({'telemetry_source': 'linux_audit'}, {'event_code': 3}, {'kind': 'heartbeat'}):
        assert windows_hash_detection({**process, **changed}, {DIGEST: 'Reviewed sample IOC'}) is None


def test_collection_reserves_capacity_for_both_events_before_advancing_cursor(tmp_path):
    row, state = sysmon(), {'windows_cursors': {'Microsoft-Windows-Sysmon/Operational': 1200}}
    with patch('vulnsuite.protection.windows_agent.subprocess.run', return_value=exported([row])) as run:
        items, status, detail = collect_windows(config(tmp_path), state, 2)
    assert len(items) == 2 and status == 'ok' and detail == 'collected'
    assert [item['kind'] for item in items] == ['process_start', 'malware_detection']
    assert run.call_args.args[0][-1] == '1'
    assert state['windows_cursors']['Microsoft-Windows-Sysmon/Operational'] == 1234
    assert 'secret' not in json.dumps(items)


def test_insufficient_capacity_leaves_cursor_and_export_untouched(tmp_path):
    state = {'windows_cursors': {'Microsoft-Windows-Sysmon/Operational': 1200}}
    with patch('vulnsuite.protection.windows_agent.subprocess.run') as run:
        assert collect_windows(config(tmp_path), state, 1) == ([], 'partial', 'backpressure')
    run.assert_not_called()
    assert state['windows_cursors']['Microsoft-Windows-Sysmon/Operational'] == 1200


def test_export_exceeding_reserved_capacity_does_not_advance_cursor(tmp_path):
    state = {'windows_cursors': {'Microsoft-Windows-Sysmon/Operational': 1200}}
    with patch('vulnsuite.protection.windows_agent.subprocess.run', return_value=exported([sysmon(), sysmon()])):
        assert collect_windows(config(tmp_path), state, 2) == ([], 'error', 'input_error')
    assert state['windows_cursors']['Microsoft-Windows-Sysmon/Operational'] == 1200


@pytest.mark.parametrize('indicators', [[], None, {'invalid': 'Bad hash'}, {DIGEST: ''}, {DIGEST: 'line\nbreak'}])
def test_invalid_reviewed_indicator_configuration_never_runs_export(tmp_path, indicators):
    state = {}
    with patch('vulnsuite.protection.windows_agent.subprocess.run') as run:
        assert collect_windows(config(tmp_path, known_bad_sha256=indicators), state, 20) == ([], 'error', 'input_error')
    run.assert_not_called()
    assert 'windows_cursors' not in state


def test_missing_sha256_reports_partial_coverage_while_preserving_process_event(tmp_path):
    with patch('vulnsuite.protection.windows_agent.subprocess.run', return_value=exported([sysmon('SHA1=' + 'a' * 40)])):
        items, status, detail = collect_windows(config(tmp_path), {}, 10)
    assert [item['kind'] for item in items] == ['process_start']
    assert (status, detail) == ('partial', 'input_error')


def test_indicator_matching_is_opt_in(tmp_path):
    with patch('vulnsuite.protection.windows_agent.subprocess.run', return_value=exported([sysmon()])):
        items, status, detail = collect_windows(config(tmp_path, known_bad_sha256={}), {}, 1)
    assert [item['kind'] for item in items] == ['process_start']
    assert (status, detail) == ('ok', 'collected')


def test_unsupported_remote_image_keeps_process_telemetry_and_reports_partial(tmp_path):
    row = sysmon()
    row['EventData']['Image'] = r'\\server\share\sample.exe'
    with patch('vulnsuite.protection.windows_agent.subprocess.run', return_value=exported([row])):
        items, status, detail = collect_windows(config(tmp_path), {}, 10)
    assert [item['kind'] for item in items] == ['process_start']
    assert (status, detail) == ('partial', 'input_error')
