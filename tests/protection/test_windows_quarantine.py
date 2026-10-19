import copy
import hashlib
import ntpath
from contextlib import contextmanager
from uuid import uuid4

import pytest

from vulnsuite.protection.windows_quarantine import WindowsQuarantine, local_path

PATH = r'C:\Workloads\uploads\suspect.bin'
VAULT = r'C:\SecurityVault'
DIGEST = hashlib.sha256(b'synthetic evidence').hexdigest()


class FakeNative:
    """Models pinned handles as object identities independently of mutable path names."""
    def __init__(self):
        self.objects = {PATH: {'identity': [7, 0, 55], 'volume': 7, 'links': 1,
                             'size': 18, 'sha256': DIGEST, 'security': 'original-owner-group-dacl', 'private': False}}
        self.manifests = {}
        self.moves = []
        self.private_vault = True
        self.reparse = set()
        self.streams = set()
        self.crash_state = None
        self.crash_before_rename = False
        self.fail_restore_security = False
        self.substitute = False

    @contextmanager
    def record(self, vault, identifier, create=False):
        if not self.private_vault:
            raise ValueError('unsafe vault ACL')
        if vault in self.reparse:
            raise ValueError('reparse vault')
        key = ntpath.join(vault, identifier)
        if not create and key not in self.manifests:
            raise FileNotFoundError(key)
        yield {'path': key, 'volume': 7}

    @contextmanager
    def open_source(self, path):
        if path in self.reparse or path in self.streams:
            raise ValueError('reparse point or alternate stream')
        if path not in self.objects:
            raise FileNotFoundError(path)
        item = self.objects[path]
        if item['links'] != 1:
            raise ValueError('hardlinks prohibited')
        yield item

    @contextmanager
    def open_payload(self, record, missing_ok=False):
        item = self.objects.get(ntpath.join(record['path'], 'payload'))
        if item is None and not missing_ok:
            raise FileNotFoundError()
        yield item

    @contextmanager
    def parent(self, path):
        if ntpath.dirname(path) in self.reparse:
            raise ValueError('reparse parent')
        yield {'path': ntpath.dirname(path), 'volume': 7}

    def info(self, item):
        return {key: copy.deepcopy(item[key]) for key in ('identity', 'volume', 'links', 'size')}

    def digest(self, item, maximum):
        return item['sha256']

    def security(self, item):
        return item['security']

    def lockdown(self, item):
        item['private'], item['security'] = True, 'service-owner-private-deny-execute'

    def restore_security(self, item, sd):
        if self.fail_restore_security:
            raise PermissionError('simulated recorded owner/DACL restoration failure')
        item['private'], item['security'] = False, sd

    def security_matches(self, item, sd):
        return item['security'] == sd

    def rename(self, item, directory, leaf):
        if self.crash_before_rename:
            self.crash_before_rename = False
            raise SystemExit('simulated agent process termination')
        target = ntpath.join(directory['path'], leaf)
        if target in self.objects:
            raise FileExistsError(target)
        old = next(name for name, value in self.objects.items() if value is item)
        del self.objects[old]
        self.objects[target] = item
        self.moves.append((old, target))
        if self.substitute:
            item['identity'] = [7, 0, 99]

    def read_manifest(self, record):
        return copy.deepcopy(self.manifests.get(record['path']))

    def write_manifest(self, record, manifest):
        if self.crash_state == manifest['state']:
            self.crash_state = None
            raise OSError('simulated crash before manifest commit')
        self.manifests[record['path']] = copy.deepcopy(manifest)


def suite(native=None, **overrides):
    native = native or FakeNative()
    return WindowsQuarantine({'quarantine_dir': VAULT, 'allowed_paths': [PATH], **overrides}, adapter=native), native


@pytest.mark.parametrize('path', [r'\\server\share\a', r'\\?\C:\a', r'\\.\C:\a', r'C:relative',
    r'C:\Workloads\x:secret', r'C:\Workloads\..\Windows\a', r'C:\Workloads\bad.\a',
    r'C:\Workloads\bad \a', r'C:\Workloads\CON.txt', 'C:/Workloads/a', 'C:\\Workloads\\a\x00'])
def test_ambiguous_remote_device_and_ads_paths_rejected(path):
    with pytest.raises(ValueError):
        local_path(path)


@pytest.mark.parametrize('path', [r'C:\Windows\System32\cmd.exe', r'C:\Program Files\svc\x.exe',
    r'C:\ProgramData\Microsoft\x', r'C:\bootmgr', r'C:\SecurityVault\payload', r'D:\Apps\x'])
def test_critical_and_cross_drive_allowlists_rejected(path):
    with pytest.raises(ValueError):
        suite(allowed_paths=[path])


def test_quarantine_restore_preserves_bytes_identity_acl_and_idempotence():
    quarantine, native = suite()
    identifier = str(uuid4())
    first = quarantine.quarantine(PATH, DIGEST, identifier)
    payload = ntpath.join(VAULT, identifier, 'payload')
    assert first == {'status': 'applied', 'detail': 'quarantined', 'request_id': identifier, 'path': PATH, 'sha256': DIGEST}
    assert PATH not in native.objects and native.objects[payload]['private']
    assert quarantine.quarantine(PATH, DIGEST, identifier) == first
    assert len(native.moves) == 1
    restored = quarantine.restore(identifier)
    assert restored['status'] == 'rolled_back' and restored['detail'] == 'restored'
    assert native.objects[PATH]['sha256'] == DIGEST
    assert native.objects[PATH]['security'] == 'original-owner-group-dacl'
    assert not native.objects[PATH]['private']
    assert quarantine.restore(identifier) == restored
    assert len(native.moves) == 2
    with pytest.raises(ValueError):
        quarantine.quarantine(PATH, DIGEST, identifier)


@pytest.mark.parametrize('fault', ['hash', 'hardlink', 'size', 'volume', 'vault_acl', 'reparse', 'streams'])
def test_preflight_refusals_never_move_or_change_file(fault):
    quarantine, native = suite()
    item = native.objects[PATH]
    if fault == 'hash': item['sha256'] = 'a' * 64
    if fault == 'hardlink': item['links'] = 2
    if fault == 'size': item['size'] = 200 * 1024 * 1024
    if fault == 'volume': item['volume'] = 8
    if fault == 'vault_acl': native.private_vault = False
    if fault == 'reparse': native.reparse.add(PATH)
    if fault == 'streams': native.streams.add(PATH)
    with pytest.raises(ValueError):
        quarantine.quarantine(PATH, DIGEST, str(uuid4()))
    assert not native.moves and native.objects[PATH]['security'] == 'original-owner-group-dacl'


def test_restore_never_overwrites_and_relocks_payload():
    quarantine, native = suite()
    identifier = str(uuid4())
    quarantine.quarantine(PATH, DIGEST, identifier)
    native.objects[PATH] = {'identity': [7, 0, 88], 'sha256': 'b' * 64}
    with pytest.raises(FileExistsError):
        quarantine.restore(identifier)
    assert native.objects[PATH]['sha256'] == 'b' * 64
    payload = native.objects[ntpath.join(VAULT, identifier, 'payload')]
    assert payload['private'] and payload['sha256'] == DIGEST
    del native.objects[PATH]
    assert quarantine.restore(identifier)['detail'] == 'restored'


def test_restart_recovers_after_quarantine_rename_before_manifest():
    quarantine, native = suite()
    identifier = str(uuid4())
    native.crash_state = 'quarantined'
    with pytest.raises(OSError):
        quarantine.quarantine(PATH, DIGEST, identifier)
    assert PATH not in native.objects
    retry, _ = suite(native)
    assert retry.quarantine(PATH, DIGEST, identifier)['detail'] == 'quarantined'
    assert len(native.moves) == 1


def test_restart_recovers_after_restore_rename_before_manifest():
    quarantine, native = suite()
    identifier = str(uuid4())
    quarantine.quarantine(PATH, DIGEST, identifier)
    native.crash_state = 'restored'
    with pytest.raises(OSError):
        quarantine.restore(identifier)
    assert native.objects[PATH]['security'] == 'original-owner-group-dacl'
    retry, _ = suite(native)
    assert retry.restore(identifier)['detail'] == 'restored'
    assert len(native.moves) == 2


def test_separately_approved_restore_recovers_prepared_payload_and_verified_unmoved_source():
    quarantine, native = suite()
    identifier = str(uuid4())
    native.crash_state = 'quarantined'
    with pytest.raises(OSError):
        quarantine.quarantine(PATH, DIGEST, identifier)
    assert quarantine.restore(identifier)['detail'] == 'restored'
    identifier = str(uuid4())
    native.manifests[ntpath.join(VAULT, identifier)] = {
        'request_id': identifier, 'state': 'prepared', 'path': PATH,
        'identity': [7, 0, 55], 'sha256': DIGEST, 'security': 'original-owner-group-dacl'}
    native.objects[PATH]['security'] = 'service-owner-private-deny-execute'
    assert quarantine.restore(identifier)['detail'] == 'restored'
    assert native.objects[PATH]['security'] == 'original-owner-group-dacl'


def test_crash_after_lockdown_before_rename_recovers_acl_without_moving_file():
    quarantine, native = suite()
    identifier = str(uuid4())
    native.crash_before_rename = True
    with pytest.raises(SystemExit):
        quarantine.quarantine(PATH, DIGEST, identifier)
    assert native.objects[PATH]['private'] and not native.moves
    assert quarantine.restore(identifier)['detail'] == 'restored'
    assert native.objects[PATH]['security'] == 'original-owner-group-dacl'
    assert not native.moves


@pytest.mark.parametrize('change', ['missing', 'replaced', 'hardlinked', 'modified'])
def test_prepared_missing_payload_never_changes_unverified_original(change):
    quarantine, native = suite()
    identifier = str(uuid4())
    native.crash_before_rename = True
    with pytest.raises(SystemExit):
        quarantine.quarantine(PATH, DIGEST, identifier)
    if change == 'missing': del native.objects[PATH]
    if change == 'replaced': native.objects[PATH]['identity'] = [7, 0, 99]
    if change == 'hardlinked': native.objects[PATH]['links'] = 2
    if change == 'modified': native.objects[PATH]['sha256'] = 'a' * 64
    before = copy.deepcopy(native.objects)
    with pytest.raises((ValueError, FileNotFoundError)):
        quarantine.restore(identifier)
    assert native.objects == before and not native.moves


def test_completed_restore_does_not_overwrite_subsequent_acl_change():
    quarantine, native = suite()
    identifier = str(uuid4())
    quarantine.quarantine(PATH, DIGEST, identifier)
    quarantine.restore(identifier)
    native.objects[PATH]['security'] = 'new-acl-after-review'
    with pytest.raises(ValueError):
        quarantine.restore(identifier)
    assert native.objects[PATH]['security'] == 'new-acl-after-review'


def test_restore_acl_failure_after_move_keeps_private_source_and_recovers():
    quarantine, native = suite()
    identifier = str(uuid4())
    quarantine.quarantine(PATH, DIGEST, identifier)
    native.fail_restore_security = True
    with pytest.raises(PermissionError):
        quarantine.restore(identifier)
    assert native.objects[PATH]['private']
    assert native.manifests[ntpath.join(VAULT, identifier)]['state'] == 'restoring'
    native.fail_restore_security = False
    assert quarantine.restore(identifier)['detail'] == 'restored'
    assert native.objects[PATH]['security'] == 'original-owner-group-dacl'
    assert len(native.moves) == 2


def test_substituted_identity_preserved_in_private_vault_without_success():
    quarantine, native = suite()
    native.substitute = True
    identifier = str(uuid4())
    with pytest.raises(ValueError):
        quarantine.quarantine(PATH, DIGEST, identifier)
    assert native.objects[ntpath.join(VAULT, identifier, 'payload')]['private']
    with pytest.raises(ValueError):
        quarantine.quarantine(PATH, DIGEST, identifier)


def test_reused_request_and_changed_restore_policy_refused():
    quarantine, native = suite()
    identifier = str(uuid4())
    quarantine.quarantine(PATH, DIGEST, identifier)
    with pytest.raises(ValueError):
        quarantine.quarantine(PATH, 'a' * 64, identifier)
    changed, _ = suite(native, allowed_paths=[r'C:\Workloads\other.bin'])
    with pytest.raises(ValueError):
        changed.restore(identifier)


def test_native_import_and_construction_on_linux_has_no_side_effects():
    import os
    from vulnsuite.protection._windows_native import WindowsNative
    if os.name != 'nt':
        with pytest.raises(OSError):
            WindowsNative()


def test_native_handle_open_denies_write_delete_and_refuses_reparse_or_links():
    from types import SimpleNamespace
    from vulnsuite.protection._windows_native import WindowsNative
    native = WindowsNative.__new__(WindowsNative)
    opened = []
    class Handle:
        closed = False
        def __int__(self): return 12
        def Close(self): self.closed = True
    handle = Handle()
    metadata = [0, 0, 0, 0, 7, 0, 18, 1, 0, 55]
    def create(*args):
        opened.append(args)
        return handle
    def final(_handle, buffer, _size, _flags):
        buffer.value = '\\\\?\\' + PATH
        return len(buffer.value)
    native._call = lambda f, *args: f(*args)
    native.files = SimpleNamespace(CreateFile=create, GetFileInformationByHandle=lambda h: metadata)
    native.kernel = SimpleNamespace(GetFinalPathNameByHandleW=final)
    record = native._open(PATH)
    assert record['handle'] is handle
    assert opened[0][2] == 1  # FILE_SHARE_READ, no WRITE or DELETE
    assert opened[0][5] & 0x00200000  # FILE_FLAG_OPEN_REPARSE_POINT
    assert opened[0][1] & 0x10000  # DELETE, needed for handle rename
    metadata[0] = 0x400
    with pytest.raises(ValueError):
        native._open(PATH)
    assert handle.closed
    metadata[0], metadata[7] = 0, 2
    with pytest.raises(ValueError):
        native._open(PATH)
    metadata[0], metadata[7] = 0x10, 1
    native._open(PATH, directory=True)
    assert opened[-1][1] & 0x1  # FILE_LIST_DIRECTORY makes sharing restrictions effective
    assert opened[-1][2] == 3  # Directory allows internal rename writes, denies DELETE


def test_native_rename_uses_pinned_directory_and_never_replace():
    from types import SimpleNamespace
    from vulnsuite.protection._windows_native import WindowsNative
    native = WindowsNative.__new__(WindowsNative)
    captured = []
    def renamed(handle, status, pointer, size, info_class):
        data = pointer._obj
        captured.append((handle, info_class, data.replace, data.root, data.name, data.length))
        return 0
    native._call = lambda f, *args: f(*args)
    native.files = SimpleNamespace(GetFileInformationByHandle=lambda h: (0x10, 0, 0, 0, 7))
    native.ntdll = SimpleNamespace(NtSetInformationFile=renamed)
    native.info = lambda source: {'volume': 7}
    source = {'handle': 12, 'path': PATH}
    native.rename(source, {'handle': 99, 'volume': 7, 'path': VAULT}, 'payload')
    assert captured == [(12, 10, False, 99, 'payload', 14)]
    assert source['path'] == ntpath.join(VAULT, 'payload')


def test_native_rename_reparse_destination_rejected_before_syscall():
    from types import SimpleNamespace
    from vulnsuite.protection._windows_native import WindowsNative
    native = WindowsNative.__new__(WindowsNative)
    native._call = lambda f, *args: f(*args)
    native.files = SimpleNamespace(GetFileInformationByHandle=lambda h: (0x410, 0, 0, 0, 7))
    with pytest.raises(ValueError):
        native.rename({'handle': 12, 'path': PATH}, {'handle': 99, 'volume': 7, 'path': VAULT}, 'payload')


@pytest.mark.parametrize('status,error', [(0x103, 0), (-1073741771, 183), (-1073741184, 4392)])
def test_native_rename_pending_completion_or_failure_is_never_blind_success(status, error):
    from types import SimpleNamespace
    from vulnsuite.protection._windows_native import WindowsNative
    native = WindowsNative.__new__(WindowsNative)
    native._call = lambda f, *args: f(*args)
    native.files = SimpleNamespace(GetFileInformationByHandle=lambda h: (0x10, 0, 0, 0, 7))
    native.info = lambda record: {'volume': 7}
    waits = []
    native.kernel = SimpleNamespace(WaitForSingleObject=lambda h, timeout: waits.append(timeout) or 0)
    def invoke(handle, iosb, pointer, size, info_class):
        iosb._obj.status = 0 if status == 0x103 else status
        return status
    native.ntdll = SimpleNamespace(NtSetInformationFile=invoke, RtlNtStatusToDosError=lambda code: error)
    source = {'handle': 12, 'path': PATH}
    if status == 0x103:
        native.rename(source, {'handle': 99, 'volume': 7, 'path': VAULT}, 'payload')
        assert waits == [0xFFFFFFFF] and source['path'] != PATH
    else:
        with pytest.raises(FileExistsError if error == 183 else OSError):
            native.rename(source, {'handle': 99, 'volume': 7, 'path': VAULT}, 'payload')
        assert source['path'] == PATH


def test_native_error_boundary_converts_receiptable_failures():
    from types import SimpleNamespace
    from vulnsuite.protection._windows_native import WindowsNative
    native = WindowsNative.__new__(WindowsNative)
    class NativeFailure(Exception):
        winerror = 5
    native.types = SimpleNamespace(error=NativeFailure)
    def denied(): raise NativeFailure('native details must not leave the host')
    with pytest.raises(PermissionError) as error:
        native._call(denied)
    assert 'native details' not in str(error.value)


def test_native_vault_rejects_untrusted_allow_ace_and_unprotected_dacl():
    from types import SimpleNamespace
    from vulnsuite.protection._windows_native import WindowsNative
    native = WindowsNative.__new__(WindowsNative)
    native.sid_text = 'service'
    native._call = lambda f, *args: f(*args)
    control = [0x1000]
    acl = SimpleNamespace(GetAceCount=lambda: 1, GetAce=lambda i: ((0, 0), 0x1f01ff, 'untrusted'))
    sd = SimpleNamespace(GetSecurityDescriptorOwner=lambda: 'service', GetSecurityDescriptorControl=lambda: (control[0], 1),
                         GetSecurityDescriptorDacl=lambda: acl)
    native.sec = SimpleNamespace(GetSecurityInfo=lambda *args: sd, ConvertSidToStringSid=lambda sid: sid)
    with pytest.raises(ValueError):
        native._private({'handle': 1})
    acl.GetAce = lambda i: ((0, 0), 0x1f01ff, 'service')
    control[0] = 0
    with pytest.raises(ValueError):
        native._private({'handle': 1})
    control[0] = 0x1000
    native._private({'handle': 1})
