"""Offline synthetic detection evaluation; never scans hosts or enforces a response."""
import argparse
import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .models import Event
from .store import Store


def evaluate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    now = time.time()
    timestamp = datetime.fromtimestamp(now, timezone.utc)
    def auth(kind='auth_failure', protocol='ssh'):
        return Event(kind=kind, source_ip='10.50.0.10', user='test-user', protocol=protocol, occurred_at=timestamp)
    cases = [
        ('ordinary_login', 'benign', [('a', auth('auth_success'))], set()),
        ('routine_process', 'benign', [('a', Event(kind='process_start', pid=20, executable='/usr/bin/bash',
          parent_executable='/usr/lib/systemd/systemd', telemetry_source='linux_audit', occurred_at=timestamp))], set()),
        # Intentional known limitation: a legitimate user repeatedly mistyping a
        # password is indistinguishable from brute force on these signals alone.
        ('legitimate_password_mistakes', 'benign', [('a', auth()) for _ in range(5)], {'ssh_brute_force'}),
        ('brute_force', 'malicious', [('a', auth()) for _ in range(5)], {'ssh_brute_force'}),
        ('transient_tmp_execution', 'malicious', [('a', Event(kind='process_start', pid=77,
          executable='/tmp/synthetic-payload', telemetry_source='linux_audit', occurred_at=timestamp))], {'writable_directory_execution'}),
        ('windows_web_shell', 'malicious', [('a', Event(kind='process_start', pid=90,
          executable=r'C:\Windows\System32\cmd.exe', parent_executable=r'C:\Windows\System32\inetsrv\w3wp.exe',
          telemetry_source='windows_sysmon', occurred_at=timestamp))], {'web_server_shell'}),
        ('rdp_login_fanout', 'malicious', [(h, auth('auth_success', 'rdp')) for h in ('a', 'b', 'c')], {'remote_login_fanout'}),
        ('smb_login_fanout', 'malicious', [(h, auth('auth_success', 'smb')) for h in ('a', 'b', 'c')], {'remote_login_fanout'}),
    ]
    results, metrics = [], {'true_positive': 0, 'false_positive': 0, 'true_negative': 0, 'false_negative': 0}
    for name, label, events, expected in cases:
        database = directory / f'{name}.db'
        if database.exists():
            raise FileExistsError('evaluation requires a fresh output directory')
        store = Store(str(database))
        for host, item in events:
            store.ingest(host, [item], now)
        observed = {a['rule'] for a in store.list_alerts()}
        matched = expected <= observed if expected else not observed
        if not matched:
            raise AssertionError(f'{name}: expected {sorted(expected)}, observed {sorted(observed)}')
        predicted = bool(observed)
        bucket = ('true_positive' if predicted else 'false_negative') if label == 'malicious' else ('false_positive' if predicted else 'true_negative')
        metrics[bucket] += 1
        results.append({'case': name, 'label': label, 'alerts': sorted(observed), 'expected_rules_passed': matched})
    benign = metrics['false_positive'] + metrics['true_negative']
    malicious = metrics['true_positive'] + metrics['false_negative']
    return {'scope': 'offline synthetic case fixtures; not a production accuracy estimate or live enforcement validation',
            'unit': 'scenario, not event', 'cases': results, 'counts': metrics,
            'synthetic_case_false_positive_rate': metrics['false_positive'] / benign if benign else None,
            'synthetic_case_detection_rate': metrics['true_positive'] / malicious if malicious else None,
            'next_validation': 'Label representative organisation staging traffic, record volume and false positives, then tune narrow reviewed suppressions.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', help='Write JSON report to a new file; fixture databases stay temporary')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='vulnsuite-evaluation-') as folder:
        result = evaluate(folder)
    data = json.dumps(result, indent=2) + '\n'
    if args.output:
        with open(args.output, 'x') as stream:
            stream.write(data)
    print(data, end='')


if __name__ == '__main__':
    main()
