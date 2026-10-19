"""Windows quarantine orchestration. Native operations are isolated for OS testing."""
import ntpath
import os
import re
from uuid import UUID


def local_path(value):
    if not isinstance(value, str) or not re.match(r'^[A-Za-z]:\\', value):
        raise ValueError('absolute local drive path required')
    if len(value) > 240 or '/' in value or ':' in value[2:] or any(ord(c) < 32 for c in value):
        raise ValueError('device, stream, long or ambiguous paths are prohibited')
    parts = value[3:].split('\\')
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}
    if not parts or any(not part or part in ('.', '..') or part.endswith((' ', '.'))
                        or any(c in part for c in '<>"|?*') or part.split('.')[0].upper() in reserved for part in parts):
        raise ValueError('path contains prohibited components')
    return value[0].upper() + value[1:]


def _under(path, root):
    return path.casefold() == root.casefold() or path.casefold().startswith(root.casefold().rstrip('\\') + '\\')


class WindowsQuarantine:
    def __init__(self, config, *, adapter=None):
        self.directory = local_path(config['quarantine_dir'])
        self.max_bytes = config.get('max_file_bytes', 100 * 1024 * 1024)
        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= 1024 * 1024 * 1024:
            raise ValueError('invalid maximum file size')
        self.protected = [local_path(p) for p in config.get('protected_paths', [])]
        self.allowed = {local_path(p).casefold() for p in config.get('allowed_paths', [])}
        if not self.allowed:
            raise ValueError('exact allowed_paths required')
        for path in self.allowed:
            self._target(path)
        if adapter is None:
            from ._windows_native import WindowsNative
            adapter = WindowsNative()
        self.adapter = adapter

    def _target(self, path):
        path = local_path(path)
        if path.casefold() not in self.allowed:
            raise ValueError('target outside exact allowlist')
        drive, rest = ntpath.splitdrive(path)
        if '\\' not in rest[1:]:
            raise ValueError('drive-root files cannot be quarantined')
        critical = [drive + '\\' + name for name in ('Windows', 'Program Files', 'Program Files (x86)',
                    'Boot', 'Recovery', 'System Volume Information', '$Recycle.Bin', 'ProgramData\\Microsoft')]
        for name in ('SystemRoot', 'windir', 'ProgramFiles', 'ProgramFiles(x86)'):
            if os.environ.get(name):
                critical.append(local_path(os.environ[name]))
        if any(_under(path, root) for root in [self.directory, *critical, *self.protected]):
            raise ValueError('protected/system path cannot be quarantined')
        if drive.casefold() != ntpath.splitdrive(self.directory)[0].casefold():
            raise ValueError('source and vault must be on the same drive')
        return path

    @staticmethod
    def _receipt(manifest):
        restored = manifest['state'] == 'restored'
        return {'status': 'rolled_back' if restored else 'applied',
                'detail': 'restored' if restored else 'quarantined',
                'request_id': manifest['request_id'], 'path': manifest['path'], 'sha256': manifest['sha256']}

    def _verify(self, handle, manifest):
        info = self.adapter.info(handle)
        if info['identity'] != manifest['identity'] or info['links'] != 1 or info['size'] > self.max_bytes:
            raise ValueError('file identity or policy differs from approved evidence')
        if self.adapter.digest(handle, self.max_bytes) != manifest['sha256']:
            raise ValueError('file hash differs from approved evidence')

    def quarantine(self, path, sha256, request_id):
        path, request_id = self._target(path), str(UUID(request_id))
        if not isinstance(sha256, str) or not re.fullmatch('[a-f0-9]{64}', sha256):
            raise ValueError('approved SHA256 required')
        native = self.adapter
        with native.record(self.directory, request_id, create=True) as record:
            manifest = native.read_manifest(record)
            if manifest:
                if (manifest['path'].casefold(), manifest['sha256'], manifest['request_id']) != (path.casefold(), sha256, request_id):
                    raise ValueError('request identifier reused with different evidence')
                if manifest['state'] not in ('prepared', 'quarantined'):
                    raise ValueError('quarantine already restoring/restored')
                with native.open_payload(record, missing_ok=True) as payload:
                    if payload is not None:
                        self._verify(payload, manifest)
                        native.lockdown(payload)
                        manifest = {**manifest, 'state': 'quarantined'}
                        native.write_manifest(record, manifest)
                        return self._receipt(manifest)
                if manifest['state'] != 'prepared':
                    raise ValueError('quarantined payload is missing')
            with native.open_source(path) as source:
                info = native.info(source)
                if info['links'] != 1 or info['size'] > self.max_bytes or info['volume'] != record['volume']:
                    raise ValueError('hardlinked, oversized or cross-volume source refused')
                if manifest is None:
                    if native.digest(source, self.max_bytes) != sha256:
                        raise ValueError('source differs from approved hash')
                    manifest = {'version': 1, 'request_id': request_id, 'path': path, 'sha256': sha256,
                                'identity': info['identity'], 'security': native.security(source), 'state': 'prepared'}
                    native.write_manifest(record, manifest)
                self._verify(source, manifest)
                native.lockdown(source)
                try:
                    native.rename(source, record, 'payload')
                except Exception:
                    native.restore_security(source, manifest['security'])
                    raise
                self._verify(source, manifest)
                manifest = {**manifest, 'state': 'quarantined'}
                native.write_manifest(record, manifest)
                return self._receipt(manifest)

    def restore(self, request_id):
        request_id = str(UUID(request_id))
        native = self.adapter
        with native.record(self.directory, request_id, create=False) as record:
            manifest = native.read_manifest(record)
            if not manifest or manifest['request_id'] != request_id or manifest['state'] not in ('prepared', 'quarantined', 'restoring', 'restored'):
                raise ValueError('quarantine is not restorable')
            path = self._target(manifest['path'])
            with native.open_payload(record, missing_ok=True) as payload:
                if payload is None:
                    if manifest['state'] not in ('prepared', 'restoring', 'restored'):
                        raise ValueError('missing payload requires review')
                    with native.open_source(path) as source:
                        self._verify(source, manifest)
                        if manifest['state'] == 'prepared':
                            # Approved rollback of a crash after ACL lockdown but
                            # before the move. Identity/hash verification precedes
                            # every mutation of the original path.
                            manifest = {**manifest, 'state': 'restoring'}
                            native.write_manifest(record, manifest)
                        if manifest['state'] == 'restoring':
                            try:
                                native.restore_security(source, manifest['security'])
                            except Exception:
                                native.lockdown(source)
                                raise
                        if not native.security_matches(source, manifest['security']):
                            raise ValueError('restored security differs from the recorded ACL/owner/group')
                    manifest = {**manifest, 'state': 'restored'}
                    native.write_manifest(record, manifest)
                    return self._receipt(manifest)
                if manifest['state'] == 'restored':
                    raise ValueError('restored record unexpectedly contains a payload')
                self._verify(payload, manifest)
                with native.parent(path) as destination:
                    if destination['volume'] != record['volume']:
                        raise ValueError('restore volume differs')
                    manifest = {**manifest, 'state': 'restoring'}
                    native.write_manifest(record, manifest)
                    try:
                        # Keep the restrictive payload ACL through the move.
                        # Restore inherited ACLs only under the original parent.
                        native.rename(payload, destination, ntpath.basename(path))
                        self._verify(payload, manifest)
                        native.restore_security(payload, manifest['security'])
                    except Exception:
                        native.lockdown(payload)
                        raise
                    if not native.security_matches(payload, manifest['security']):
                        raise ValueError('restored security differs from recorded evidence')
                    manifest = {**manifest, 'state': 'restored'}
                    native.write_manifest(record, manifest)
                    return self._receipt(manifest)
