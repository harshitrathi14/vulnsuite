"""Windows Event Log collector used by the cross-platform durable agent.

Run with python -m vulnsuite.protection.windows_agent --config <agent.json>.
The PowerShell adapter exposes an allowlist of fields and durable record cursors.
"""
import json
import re
import subprocess
from pathlib import Path

from .telemetry import parse_windows_event, windows_hash_detection


def _indicators(config):
    """Local operator-reviewed SHA256 -> label mapping; no remote feed loading."""
    values = config.get('known_bad_sha256', {})
    if (not isinstance(values, dict) or len(values) > 10000
            or any(not isinstance(key, str) or not re.fullmatch('[a-f0-9]{64}', key)
                   or not isinstance(label, str) or not 1 <= len(label) <= 128
                   or any(ord(character) < 32 for character in label)
                   for key, label in values.items())):
        raise ValueError('invalid reviewed SHA256 indicator configuration')
    return values


def collect_windows(config, state, capacity):
    if capacity <= 0:
        return [], 'partial', 'backpressure'
    script = Path(config['export_script'])
    if not script.is_absolute() or script.suffix.lower() != '.ps1':
        raise ValueError('export_script must be an absolute .ps1 path')
    cursors = state.get('windows_cursors', {})
    try:
        known_bad = _indicators(config)
        # A matched Sysmon record yields both process and malware evidence. Reserve
        # both slots before export so advancing cursors cannot drop either event.
        budget = min(500, capacity // 2 if known_bad else capacity)
        if budget < 1:
            return [], 'partial', 'backpressure'
        completed = subprocess.run(
            [config.get('powershell', 'powershell.exe'), '-NoLogo', '-NoProfile', '-NonInteractive',
             '-File', str(script), '-CursorJson', json.dumps(cursors, separators=(',', ':')),
             '-MaxEvents', str(budget)], capture_output=True, text=True, encoding='utf-8',
            timeout=45, check=False)
        if completed.returncode or len(completed.stdout) > 2 * 1024 * 1024:
            return [], 'error', 'access_denied' if completed.returncode else 'scan_limit'
        payload = json.loads(completed.stdout.lstrip('\ufeff'))
        records = payload['records']
        next_cursors = payload['cursors']
        if not isinstance(records, list) or len(records) > budget or not isinstance(next_cursors, dict):
            raise ValueError('invalid event export envelope')
        if any(key not in ('Security', 'Microsoft-Windows-Sysmon/Operational')
               or type(value) is not int or value < 0 for key, value in next_cursors.items()):
            raise ValueError('invalid Windows cursor')
        items, malformed, missing_hashes = [], False, False
        for record in records:
            try:
                parsed = parse_windows_event(record)
                if parsed:
                    # Validate before advancing the durable eventlog cursor.
                    from .models import Event
                    items.append(Event(**parsed).model_dump(mode='json'))
                    if known_bad:
                        if parsed['kind'] == 'process_start' and not parsed.get('sha256'):
                            missing_hashes = True
                        detection = windows_hash_detection(parsed, known_bad)
                        if detection:
                            items.append(Event(**detection).model_dump(mode='json'))
            except (ValueError, TypeError):
                malformed = True
        state['windows_cursors'] = next_cursors
        if payload.get('errors') or malformed or missing_hashes or payload.get('reset'):
            return items, 'partial', 'input_error'
        if payload.get('has_more'):
            return items, 'partial', 'scan_limit'
        return items, 'ok', 'collected'
    except (OSError, subprocess.SubprocessError):
        return [], 'error', 'access_denied'
    except (ValueError, TypeError, KeyError, AttributeError):
        return [], 'error', 'input_error'


def main():
    from .agent import main as run
    run()


if __name__ == '__main__':
    main()
