"""Opt-in Linux sensors. Never transmit command arguments, environment or file contents."""
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path

MAX_FILE = 16 * 1024 * 1024
SHELLS = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'fish'}
WEB_PARENTS = {'nginx', 'apache2', 'httpd', 'php-fpm', 'php-fpm8.2', 'php-fpm8.3', 'gunicorn', 'uwsgi'}


def digest_file(path, follow=False):
    flags = os.O_RDONLY | os.O_NONBLOCK | (0 if follow else os.O_NOFOLLOW)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
            raise ValueError('scan_limit')
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(65536):
            size += len(chunk)
            if size > MAX_FILE:
                raise ValueError('scan_limit')
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('input_error')
        return digest.hexdigest()


def indicators(config):
    values = config.get('known_bad_sha256', {})
    if len(values) > 10000 or any(not re.fullmatch('[a-f0-9]{64}', key)
                                or not isinstance(value, str) or not 1 <= len(value) <= 128
                                for key, value in values.items()):
        raise ValueError('invalid SHA256 indicator configuration')
    return values


def process_events(config, state, proc_root='/proc', max_events=500):
    root = Path(proc_root)
    pids = sorted((p for p in root.iterdir() if p.name.isdigit()), key=lambda p: int(p.name))
    partial = len(pids) > 4096
    detail = 'scan_limit' if partial else 'collected'
    seen = state.setdefault('process_seen', {})
    current = {}
    events = []
    known_bad = indicators(config)
    hash_budget = 64
    hashes = {}
    pids = pids[:4096]
    cursor = state.get('process_cursor', 0) % max(1, len(pids))
    state['process_cursor'] = (cursor + 64) % max(1, len(pids))
    for directory in pids[cursor:] + pids[:cursor]:
        try:
            # stat field 22 is process start time; parse after the final ')' because comm can contain spaces.
            info = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
            ppid, start = int(info[1]), int(info[19])
            executable = os.readlink(directory / 'exe')
            deleted = executable.endswith(' (deleted)')
            executable = executable.removesuffix(' (deleted)')
            if not executable.startswith('/') or len(executable) > 1024:
                partial, detail = True, 'input_error'
                continue
            parent = None
            try:
                parent = os.readlink(root / str(ppid) / 'exe').removesuffix(' (deleted)')
            except (FileNotFoundError, ProcessLookupError):
                pass
            except PermissionError:
                partial, detail = True, 'access_denied'
            key = f'{directory.name}:{start}'
            observed = set(seen.get(key, []))
            rules = []
            if executable not in config.get('allowed_executables', []):
                if deleted:
                    rules.append('deleted_executable')
                if any(executable.startswith(prefix) for prefix in ('/tmp/', '/var/tmp/', '/dev/shm/')):
                    rules.append('writable_directory_execution')
                if Path(executable).name in SHELLS and parent and Path(parent).name in WEB_PARENTS:
                    rules.append('web_server_shell')
            for rule in rules:
                if rule not in observed and len(events) >= max_events:
                    partial, detail = True, 'scan_limit'
                    continue
                if rule not in observed:
                    events.append({'kind': 'process_alert', 'pid': int(directory.name), 'ppid': ppid,
                                   'start_ticks': start, 'executable': executable,
                                   'parent_executable': parent if parent and len(parent) <= 1024 else None,
                                   'process_rule': rule})
                    observed.add(rule)
            if known_bad:
                # Do not trust process paths for hashing: read the running executable via procfs.
                identity = os.stat(directory / 'exe')
                hash_key = (identity.st_dev, identity.st_ino, identity.st_mtime_ns, identity.st_ctime_ns)
                if hash_key not in hashes:
                    if hash_budget <= 0:
                        partial, detail = True, 'scan_limit'
                        current[key] = sorted(observed)
                        continue
                    hash_budget -= 1
                    hashes[hash_key] = digest_file(directory / 'exe', follow=True)
                digest = hashes[hash_key]
                marker = f'sha256:{digest}'
                if digest in known_bad and marker not in observed and len(events) < max_events:
                    events.append({'kind': 'malware_detection', 'engine': 'sha256',
                                   'signature': known_bad[digest], 'sha256': digest,
                                   'pid': int(directory.name), 'start_ticks': start, 'path': executable})
                    observed.add(marker)
            current[key] = sorted(observed)
        except (FileNotFoundError, ProcessLookupError):
            # Kernel threads and processes that exit during polling have no executable.
            continue
        except PermissionError:
            partial, detail = True, 'access_denied'
        except (OSError, ValueError, IndexError) as exc:
            partial, detail = True, 'scan_limit' if str(exc) == 'scan_limit' else 'input_error'
    # Cache only currently observed pid/start pairs; PID reuse cannot suppress a new alert.
    state['process_seen'] = current
    return events, 'partial' if partial else 'ok', detail


def malware_events(config, state):
    now = time.time()
    if now - state.get('malware_last_scan', 0) < max(60, int(config.get('interval_seconds', 300))):
        return [], None, None
    paths = config.get('scan_files', [])
    known_bad = indicators(config)
    events, hashes = [], {}
    partial = len(paths) > 8
    detail = 'scan_limit' if partial else 'collected'
    for path in paths[:8]:
        try:
            if not Path(path).is_absolute() or len(path) > 1024 or '\n' in path:
                raise ValueError('input_error')
            hashes[path] = digest_file(path)
            if hashes[path] in known_bad:
                events.append({'kind': 'malware_detection', 'engine': 'sha256', 'path': path,
                               'sha256': hashes[path], 'signature': known_bad[hashes[path]]})
        except (OSError, ValueError):
            partial, detail = True, 'input_error'
    if config.get('clamav', False) and hashes:
        try:
            result = subprocess.run(
                ['/usr/bin/clamscan', '--stdout', '--no-summary', '--infected',
                 '--follow-file-symlinks=0', '--follow-dir-symlinks=0',
                 '--max-filesize=16M', '--max-scansize=64M', '--max-recursion=8',
                 '--alert-exceeds-max=yes', '--fail-if-cvd-older-than=7', '--', *hashes],
                capture_output=True, text=True, timeout=60, check=False,
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            if result.returncode not in (0, 1):
                partial, detail = True, 'scanner_error'
            found = 0
            for line in result.stdout.splitlines():
                for path, digest in hashes.items():
                    prefix = f'{path}: '
                    if line.startswith(prefix) and line.endswith(' FOUND'):
                        signature = line[len(prefix):-6]
                        found += 1
                        if signature.startswith('Heuristics.Limits.Exceeded'):
                            partial, detail = True, 'scan_limit'
                            continue
                        if not 1 <= len(signature) <= 128:
                            partial, detail = True, 'scanner_error'
                            continue
                        # Verify the file did not change while the scanner read it.
                        if digest_file(path) != digest:
                            partial, detail = True, 'input_error'
                            continue
                        events.append({'kind': 'malware_detection', 'engine': 'clamav',
                                       'signature': signature, 'sha256': digest, 'path': path})
            if result.returncode == 1 and not found:
                partial, detail = True, 'scanner_error'
            for path, before in hashes.items():
                if digest_file(path) != before:
                    partial, detail = True, 'input_error'
        except (OSError, ValueError, subprocess.SubprocessError):
            partial, detail = True, 'scanner_error'
    if not hashes or not (known_bad or config.get('clamav', False)):
        partial, detail = True, 'input_error'
    state['malware_last_scan'] = now
    return events, 'partial' if partial else 'ok', detail


def parse_modsecurity(line):
    """ModSecurity v3 serial JSON: keep only IP, numeric rule IDs and intervention flag."""
    try:
        transaction = json.loads(line)['transaction']
        rules = sorted({int(message['details']['ruleId']) for message in transaction.get('messages', [])
                        if str(message.get('details', {}).get('ruleId', '')).isdigit()})
        rules = [rule for rule in rules if 1 <= rule <= 2147483647][:32]
        if not rules:
            return None
        from ipaddress import ip_address
        interrupted = transaction.get('is_interrupted')
        action = 'interrupted' if interrupted is True else 'detected' if interrupted is False else 'unknown'
        return {'kind': 'waf_match', 'source_ip': str(ip_address(transaction['client_ip'])),
                'rule_ids': rules, 'waf_action': action}
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError('invalid ModSecurity JSON record') from None
