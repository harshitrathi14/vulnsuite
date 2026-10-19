"""Allowlisted native event adapters; raw messages and command arguments stay local."""
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import PureWindowsPath
from uuid import NAMESPACE_URL, uuid5

AUDIT_ID = re.compile(r'\bmsg=audit\((\d+(?:\.\d+)?):(\d+)\):')
AUDIT_FIELDS = re.compile(r'(?:^|\s)([a-zA-Z_][a-zA-Z_0-9]*)=("[^"]*"|\S+)')
# syscall numbers are architecture-specific; never interpret arbitrary syscalls as execution.
EXEC_SYSCALLS = {'c000003e': {59, 322}, '40000003': {11, 358}, 'c00000b7': {221, 281}}
SECURITY = 'Microsoft-Windows-Security-Auditing'
SYSMON = 'Microsoft-Windows-Sysmon'
EVENTLOG = 'Microsoft-Windows-Eventlog'


def _identity(source, record, timestamp):
    return str(uuid5(NAMESPACE_URL, f'vulnsuite:{source}:{record}:{timestamp}'))


def _timestamp(value):
    parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('event timestamp must include timezone')
    return parsed.astimezone(timezone.utc).isoformat()


def _text(value, limit):
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError('invalid event field')
    return value


def _ip(value):
    address = ipaddress.ip_address(value)
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        return None
    return str(address)


def _sysmon_sha256(value):
    """Extract one unambiguous SHA256 observation; other hashes are not substitutes."""
    if not isinstance(value, str) or len(value) > 4096:
        return None
    candidates = []
    for part in value.split(','):
        name, separator, digest = part.partition('=')
        if separator and name.strip().upper() == 'SHA256':
            candidates.append(digest.strip().lower())
    if len(candidates) == 1 and re.fullmatch('[a-f0-9]{64}', candidates[0]):
        return candidates[0]
    return None


def windows_hash_detection(process, known_bad):
    """Derive a detection only from an exact reviewed indicator match.

    The hash is the process-image observation from Sysmon, not a present-time
    filesystem scan. The response adapter must verify current file content
    against this digest before quarantine. Unknown hashes are never malware.
    """
    if (process.get('kind') != 'process_start'
            or process.get('telemetry_source') != 'windows_sysmon'
            or process.get('event_code') != 1):
        return None
    digest = process.get('sha256')
    signature = known_bad.get(digest)
    if signature is None:
        return None
    return {
        'kind': 'malware_detection', 'platform': 'windows',
        'telemetry_source': 'windows_sysmon', 'event_code': 1,
        'event_id': _identity('windows_sysmon_sha256', process['event_id'], f'{digest}:{signature}'),
        'occurred_at': process['occurred_at'], 'record_id': process['record_id'],
        'path': process['executable'], 'pid': process['pid'],
        'engine': 'sha256', 'sha256': digest, 'signature': signature,
    }


LOG_TAMPER_KEY = 'vulnsuite_log_tamper'
_NAMETYPE_TAMPER = {'DELETE': 'deleted', 'CREATE': 'replaced', 'NORMAL': 'written'}


def _audit_text(raw, limit):
    """Decode one audit field: quoted literal or hex-encoded (special characters)."""
    value = raw[1:-1] if raw.startswith('"') else bytes.fromhex(raw).decode('utf-8')
    return _text(value, limit)


class LinuxAuditCorrelator:
    """Join the SYSCALL record of a watched-file write with its PATH record.

    auditd writes the records of one event contiguously under one serial. A
    SYSCALL tagged `vulnsuite_log_tamper` is held until its PATH record names the
    file (or until a record with another serial arrives), then emitted as one
    `log_tamper` event. Execution records pass straight through unchanged.
    """

    def __init__(self, ignore_executables=()):
        self.pending = None
        self.ignore = {str(p) for p in ignore_executables}

    def feed(self, line):
        events = []
        fields = dict(AUDIT_FIELDS.findall(line))
        match = AUDIT_ID.search(line)
        serial = match[2] if match else None
        if self.pending and self.pending['serial'] != serial:
            events.extend(self.flush())
        record_type = fields.get('type')
        if record_type == 'SYSCALL' and fields.get('key', '').strip('"') == LOG_TAMPER_KEY:
            if fields.get('success') == 'yes' and match:
                try:
                    executable = _audit_text(fields['exe'], 1024)
                    stamp = datetime.fromtimestamp(float(match[1]), timezone.utc).isoformat()
                    record = f'{match[1]}:{match[2]}'
                    if executable in self.ignore:
                        self.pending = None
                        return events
                    self.pending = {'serial': serial, 'event': {
                        'kind': 'log_tamper', 'tamper': 'written', 'telemetry_source': 'linux_audit',
                        'event_id': _identity('linux_audit_tamper', record, stamp), 'occurred_at': stamp,
                        'record_id': record, 'pid': int(fields['pid']), 'executable': executable,
                        'user': _text(fields.get('auid', fields.get('uid', '?')).strip('"'), 128)}}
                except (KeyError, TypeError, ValueError, UnicodeError, OverflowError):
                    raise ValueError('invalid audit watch record') from None
            return events
        if record_type == 'PATH' and self.pending and serial == self.pending['serial']:
            nametype = fields.get('nametype', '').strip('"')
            if nametype in _NAMETYPE_TAMPER and 'path' not in self.pending['event']:
                try:
                    self.pending['event']['path'] = _audit_text(fields.get('name', '""'), 1024)
                except (ValueError, UnicodeError):
                    pass
                self.pending['event']['tamper'] = _NAMETYPE_TAMPER[nametype]
            return events
        parsed = parse_linux_audit(line)
        if parsed:
            events.append(parsed)
        return events

    def flush(self):
        if not self.pending:
            return []
        event, self.pending = self.pending['event'], None
        return [event]


def parse_linux_audit(line):
    """Read only successful SYSCALL records tagged by the supplied audit rules.

    EXECVE/PROCTITLE records contain arguments; they are deliberately ignored.
    The one SYSCALL record supplies executable/PID/PPID and original event time.
    """
    fields = dict(AUDIT_FIELDS.findall(line))
    if fields.get('type') != 'SYSCALL' or fields.get('key', '').strip('"') != 'vulnsuite_exec':
        return None
    if fields.get('success') != 'yes':
        return None
    try:
        if int(fields['syscall']) not in EXEC_SYSCALLS.get(fields['arch'].lower(), set()):
            return None
        match = AUDIT_ID.search(line)
        if not match:
            raise ValueError('audit event identifier missing')
        stamp = datetime.fromtimestamp(float(match[1]), timezone.utc).isoformat()
        raw_exe = fields['exe']
        # audit encodes special characters as hex; decode only the executable field.
        executable = raw_exe[1:-1] if raw_exe.startswith('"') else bytes.fromhex(raw_exe).decode('utf-8')
        executable = _text(executable, 1024)
        if not executable.startswith('/'):
            raise ValueError('absolute executable path required')
        record = f'{match[1]}:{match[2]}'
        return {'kind': 'process_start', 'telemetry_source': 'linux_audit',
                'event_id': _identity('linux_audit', record, stamp), 'occurred_at': stamp,
                'record_id': record, 'pid': int(fields['pid']), 'ppid': int(fields['ppid']),
                'executable': executable}
    except (KeyError, TypeError, UnicodeError, OverflowError) as exc:
        raise ValueError('invalid audit execution record') from None


def parse_windows_event(line):
    """Normalize the JSON envelope emitted by Export-VulnSuiteEvents.ps1.

    4624/4625 type 3 identifies network logon, not a specific service. Type 10
    is RDP; 5140 explicitly identifies file-share access. No port guessing.
    """
    try:
        row = json.loads(line) if isinstance(line, str) else line
        provider = row['Provider']
        code = int(row['EventId'])
        data = row['EventData']
        stamp = _timestamp(row['TimeCreated'])
        record = _text(str(row['RecordId']), 128)
        source = 'windows_sysmon' if provider == SYSMON else 'windows_security'
        common = {'telemetry_source': source, 'event_code': code, 'record_id': record,
                  'occurred_at': stamp, 'event_id': _identity(provider, record, stamp)}
        # Audit-trail tampering: 1102 the Security log was cleared, 1100 the event
        # logging service stopped, 4719 the audit policy was changed.
        if (provider, code) in ((EVENTLOG, 1102), (EVENTLOG, 1100), (SECURITY, 4719)):
            tamper = {1102: 'cleared', 1100: 'audit_stopped', 4719: 'audit_policy_changed'}[code]
            result = {**common, 'kind': 'log_tamper', 'tamper': tamper, 'path': 'Security'}
            user = data.get('SubjectUserName')
            if isinstance(user, str) and user and user != '-':
                domain = data.get('SubjectDomainName', '')
                result['user'] = _text(f'{domain}\\{user}' if domain and domain != '-' else user, 128)
            return result
        if provider == SECURITY and code in (4624, 4625, 5140):
            if code != 5140 and int(data['LogonType']) not in (3, 10):
                return None
            ip = _ip(data['IpAddress'])
            if not ip:
                return None
            if code == 5140:
                # Windows audit outcome is a bitmask, independent of locale.
                keyword = int(str(row['Keywords']), 0)
                if keyword & 0x0010000000000000:
                    kind = 'auth_failure'
                elif keyword & 0x0020000000000000:
                    kind = 'auth_success'
                else:
                    raise ValueError('SMB access outcome missing')
                protocol, name = 'smb', 'SubjectUserName'
            else:
                logon = int(data['LogonType'])
                if logon not in (3, 10):
                    return None
                common['logon_type'] = logon
                protocol, name = ('rdp' if logon == 10 else 'network'), 'TargetUserName'
                kind = 'auth_success' if code == 4624 else 'auth_failure'
            user = _text(data[name], 128)
            domain = data.get(name.replace('UserName', 'DomainName'), '')
            if domain and domain != '-':
                user = _text(f'{domain}\\{user}', 128)
            return {**common, 'kind': kind, 'protocol': protocol, 'source_ip': ip, 'user': user}
        if provider == SYSMON and code == 1:
            executable = _text(data['Image'], 1024)
            parent = _text(data['ParentImage'], 1024)
            if not PureWindowsPath(executable).is_absolute() or not PureWindowsPath(parent).is_absolute():
                raise ValueError('absolute Windows executable paths required')
            result = {**common, 'kind': 'process_start', 'pid': int(data['ProcessId']),
                      'ppid': int(data['ParentProcessId']), 'executable': executable,
                      'parent_executable': parent, 'user': _text(data['User'], 128)}
            digest = _sysmon_sha256(data.get('Hashes', ''))
            if digest:
                result['sha256'] = digest
            # Remoting host ancestry is execution evidence; it does not establish a remote source IP.
            if parent.lower().endswith('\\system32\\wsmprovhost.exe'):
                result['protocol'] = 'winrm'
            return result
        return None
    except (KeyError, TypeError, AttributeError, OverflowError):
        raise ValueError('invalid Windows telemetry record') from None
