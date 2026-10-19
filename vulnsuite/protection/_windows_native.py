"""Windows-only file/ACL adapter. Lazy pywin32 loading keeps Linux imports inert."""
import ctypes
from ctypes import wintypes
from contextlib import ExitStack, contextmanager
import hashlib
import json
import ntpath
import os
import re
from uuid import uuid4


class _StatusUnion(ctypes.Union):
    _fields_ = [('status', ctypes.c_int32), ('pointer', ctypes.c_void_p)]


class _IoStatusBlock(ctypes.Structure):
    _anonymous_ = ('result',)
    _fields_ = [('result', _StatusUnion), ('information', ctypes.c_size_t)]


# Retain native output buffers if an impossible/failed wait leaves completion
# uncertain. Never release memory potentially still owned by an I/O request.
_UNCERTAIN_IO = []


class WindowsNative:
    STATES = ('prepared', 'quarantined', 'restoring', 'restored')

    def __init__(self):
        if os.name != 'nt':
            raise OSError('Windows quarantine requires Windows')
        try:
            import win32api, win32con, win32file, win32security, pywintypes
        except ImportError:
            raise OSError('Windows quarantine requires the reviewed pywin32 deployment dependency') from None
        self.api, self.con, self.files, self.sec, self.types = win32api, win32con, win32file, win32security, pywintypes
        token = self._call(self.sec.OpenProcessToken, self.api.GetCurrentProcess(), 0x0020 | 0x0008)
        try:
            self.sid = self._call(self.sec.GetTokenInformation, token, self.sec.TokenUser)[0]
            self.sid_text = self._call(self.sec.ConvertSidToStringSid, self.sid)
            privilege = self._call(self.sec.LookupPrivilegeValue, None, 'SeRestorePrivilege')
            self._call(self.sec.AdjustTokenPrivileges, token, False, [(privilege, 2)])
            if self.api.GetLastError() == 1300:
                raise PermissionError('service requires SeRestorePrivilege for recorded-owner restoration')
        finally:
            self._call(token.Close)
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
        self.ntdll.NtSetInformationFile.argtypes = [wintypes.HANDLE, ctypes.POINTER(_IoStatusBlock),
                                                   ctypes.c_void_p, wintypes.ULONG, ctypes.c_int]
        self.ntdll.NtSetInformationFile.restype = ctypes.c_int32
        self.ntdll.RtlNtStatusToDosError.argtypes = [ctypes.c_int32]
        self.ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        self.kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        self.kernel.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.FindFirstStreamW.restype = wintypes.HANDLE
        self.kernel.FindNextStreamW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        self.kernel.FindNextStreamW.restype = wintypes.BOOL
        self.kernel.FindClose.argtypes = [wintypes.HANDLE]
        self.kernel.FindClose.restype = wintypes.BOOL

    def _call(self, function, *args):
        try:
            return function(*args)
        except self.types.error as exc:
            code = exc.winerror
            cls = FileNotFoundError if code in (2, 3) else FileExistsError if code in (80, 183) else PermissionError if code == 5 else OSError
            raise cls(code, 'Windows quarantine native operation failed') from None

    def _descriptor(self, file=False):
        # A quarantined payload cannot be executed through the file's DACL.
        deny = '(D;;FX;;;WD)' if file else ''
        inherit = '' if file else 'OICI'
        sddl = f'O:{self.sid_text}G:BAD:P{deny}' + ''.join(
            f'(A;{inherit};FA;;;{sid})' for sid in ('SY', 'BA', self.sid_text))
        return self._call(self.sec.ConvertStringSecurityDescriptorToSecurityDescriptor, sddl, 1)

    def _attributes(self, file=False):
        attributes = self.types.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = self._descriptor(file)
        return attributes

    def _open(self, path, directory=False, creation=3, write=False, exclusive=False):
        # Directory handles pin ancestry against rename/delete. Write sharing is
        # needed by the kernel's relative rename target open; reparse destinations
        # are checked on their handle and the native relative rename fails closed.
        # File handles deny concurrent writes/deletes throughout verification.
        # FILE_LIST_DIRECTORY participates in sharing checks; metadata-only
        # access would not pin the directory identity against delete/rename.
        access = 0x1 | 0x80 | 0x20000 if directory else 0x80000000 | 0x10000 | 0x20000 | 0x40000 | 0x80000
        if write:
            access |= 0x40000000
        share = 0 if exclusive else 3 if directory else 1
        handle = self._call(self.files.CreateFile, path, access, share,
                            self._attributes(file=not directory) if creation != 3 else None,
                            creation, 0x00200000 | 0x02000000, None)
        try:
            data = self._call(self.files.GetFileInformationByHandle, handle)
            if data[0] & 0x400 or bool(data[0] & 0x10) != directory:
                raise ValueError('reparse points and unexpected file types are prohibited')
            if not directory and data[7] != 1:
                raise ValueError('hardlinked files are prohibited')
            buffer = ctypes.create_unicode_buffer(32768)
            length = self.kernel.GetFinalPathNameByHandleW(int(handle), buffer, len(buffer), 0)
            if not length or length >= len(buffer):
                raise OSError('cannot establish canonical handle path')
            final = buffer.value
            if not final.startswith('\\\\?\\') or final[4:].rstrip('\\').casefold() != path.rstrip('\\').casefold():
                raise ValueError('resolved path differs; aliases, mapped shares and substitutions are prohibited')
            return {'handle': handle, 'path': path, 'volume': data[4]}
        except BaseException:
            self._call(handle.Close)
            raise

    @contextmanager
    def _directory(self, path, private=False):
        with ExitStack() as stack:
            drive, tail = ntpath.splitdrive(path)
            paths = [drive + '\\']
            current = paths[0]
            for piece in tail.strip('\\').split('\\'):
                if piece:
                    current = ntpath.join(current, piece)
                    paths.append(current)
            record = None
            for component in paths:
                record = self._open(component, directory=True)
                stack.callback(self._call, record['handle'].Close)
            if private:
                self._private(record)
            yield record

    @contextmanager
    def parent(self, path):
        with self._directory(ntpath.dirname(path)) as parent:
            yield parent

    def _private(self, record):
        sd = self._call(self.sec.GetSecurityInfo, record['handle'], 1, 1 | 4)
        allowed = {'S-1-5-18', 'S-1-5-32-544', self.sid_text}
        owner = self._call(self.sec.ConvertSidToStringSid, self._call(sd.GetSecurityDescriptorOwner))
        control = self._call(sd.GetSecurityDescriptorControl)[0]
        acl = self._call(sd.GetSecurityDescriptorDacl)
        if owner not in allowed or not control & 0x1000 or acl is None:
            raise ValueError('vault must have a trusted owner and protected private DACL')
        for i in range(self._call(acl.GetAceCount)):
            ace = self._call(acl.GetAce, i)
            if ace[0][0] == 1:  # deny ACE cannot grant access
                continue
            if ace[0][0] != 0 or self._call(self.sec.ConvertSidToStringSid, ace[2]) not in allowed:
                raise ValueError('vault DACL grants access outside service/SYSTEM/Administrators')

    @contextmanager
    def record(self, vault, identifier, create=False):
        volume = self._call(self.api.GetVolumeInformation, ntpath.splitdrive(vault)[0] + '\\')
        if volume[4].upper() != 'NTFS':
            raise ValueError('quarantine requires a local NTFS volume')
        with self._directory(vault, private=True) as root:
            path = ntpath.join(vault, identifier)
            if create:
                try:
                    self._call(self.files.CreateDirectory, path, self._attributes())
                except FileExistsError:
                    pass
            with self._directory(path, private=True) as record:
                if record['volume'] != root['volume']:
                    raise ValueError('vault record changed volume')
                # Exclusive record lock serializes different agent processes too.
                lock = self._open(ntpath.join(path, 'operation.lock'), creation=4, write=True, exclusive=True)
                try:
                    yield record
                finally:
                    self._call(lock['handle'].Close)

    def _streams(self, path):
        class Stream(ctypes.Structure):
            _fields_ = [('size', ctypes.c_longlong), ('name', wintypes.WCHAR * 296)]
        data = Stream()
        search = self.kernel.FindFirstStreamW(path, 0, ctypes.byref(data), 0)
        if search == ctypes.c_void_p(-1).value:
            raise OSError('cannot verify NTFS data streams')
        try:
            while True:
                if data.name != '::$DATA':
                    raise ValueError('alternate data streams are prohibited')
                if not self.kernel.FindNextStreamW(search, ctypes.byref(data)):
                    if ctypes.get_last_error() != 38:  # ERROR_HANDLE_EOF
                        raise OSError('cannot complete data stream verification')
                    break
        finally:
            self.kernel.FindClose(search)

    @contextmanager
    def open_source(self, path):
        with self.parent(path):
            record = self._open(path)
            try:
                self._streams(path)
                yield record
            finally:
                self._call(record['handle'].Close)

    @contextmanager
    def open_payload(self, record, missing_ok=False):
        try:
            payload = self._open(ntpath.join(record['path'], 'payload'))
        except FileNotFoundError:
            if not missing_ok:
                raise
            yield None
            return
        try:
            self._streams(payload['path'])
            yield payload
        finally:
            self._call(payload['handle'].Close)

    def info(self, record):
        data = self._call(self.files.GetFileInformationByHandle, record['handle'])
        if data[0] & (0x400 | 0x10):
            raise ValueError('unexpected reparse point or directory')
        return {'identity': [data[4], data[8], data[9]], 'volume': data[4],
                'links': data[7], 'size': (data[5] << 32) | data[6]}

    def digest(self, record, maximum):
        before = self.info(record)
        if before['links'] != 1 or before['size'] > maximum:
            raise ValueError('file violates hash limits')
        self._call(self.files.SetFilePointer, record['handle'], 0, 0)
        digest, total = hashlib.sha256(), 0
        while True:
            _, chunk = self._call(self.files.ReadFile, record['handle'], 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError('file exceeds hash limits')
            digest.update(chunk)
        if self.info(record) != before or total != before['size']:
            raise ValueError('file changed during verification')
        return digest.hexdigest()

    def security(self, record):
        sd = self._call(self.sec.GetSecurityInfo, record['handle'], 1, 1 | 2 | 4)
        return self._call(self.sec.ConvertSecurityDescriptorToStringSecurityDescriptor, sd, 1, 1 | 2 | 4)

    def _set_security(self, record, sd, include_group=True):
        flags = 1 | 4 | (2 if include_group else 0)
        flags |= 0x80000000 if self._call(sd.GetSecurityDescriptorControl)[0] & 0x1000 else 0x20000000
        self._call(self.sec.SetSecurityInfo, record['handle'], 1, flags,
                   self._call(sd.GetSecurityDescriptorOwner), self._call(sd.GetSecurityDescriptorGroup) if include_group else None,
                   self._call(sd.GetSecurityDescriptorDacl), None)

    def lockdown(self, record):
        self._set_security(record, self._descriptor(file=True), include_group=False)

    def restore_security(self, record, security):
        if not isinstance(security, str) or len(security) > 60000:
            raise ValueError('recorded security descriptor is invalid')
        sd = self._call(self.sec.ConvertStringSecurityDescriptorToSecurityDescriptor, security, 1)
        self._set_security(record, sd)
        if not self.security_matches(record, security):
            raise ValueError('recorded owner/group/DACL was not restored')

    def security_matches(self, record, security):
        # Auto-inheritance bookkeeping flags may be recomputed by Windows; retain
        # protected/unprotected state and every original ACE, owner and group.
        def canonical(value):
            return re.sub(r'D:([PAIR]*)(?=\(|$)',
                          lambda m: 'D:' + ('P' if 'P' in m[1] else ''), value)
        return canonical(self.security(record)) == canonical(security)

    def rename(self, record, destination, leaf):
        if not leaf or ntpath.basename(leaf) != leaf or ':' in leaf:
            raise ValueError('rename target must be a leaf name')
        target = self._call(self.files.GetFileInformationByHandle, destination['handle'])
        if target[0] & 0x400 or not target[0] & 0x10:
            raise ValueError('rename destination became a reparse point or is not a directory')
        if self.info(record)['volume'] != destination['volume'] or target[4] != destination['volume']:
            raise ValueError('cross-volume rename refused')
        class Rename(ctypes.Structure):
            _fields_ = [('replace', wintypes.BOOLEAN), ('root', wintypes.HANDLE),
                        ('length', wintypes.DWORD), ('name', wintypes.WCHAR * (len(leaf.encode('utf-16-le')) // 2 + 1))]
        # Padding beyond the variable structure covers FILE_RENAME_INFORMATION's
        # fixed-header alignment on both 32-bit and 64-bit Windows.
        storage = ctypes.create_string_buffer(ctypes.sizeof(Rename) + 8)
        data = Rename.from_buffer(storage)
        data.replace, data.root, data.length, data.name = False, int(destination['handle']), len(leaf.encode('utf-16-le')), leaf
        completed = _IoStatusBlock()
        status = self.ntdll.NtSetInformationFile(int(record['handle']), ctypes.byref(completed),
                                               ctypes.byref(data), ctypes.sizeof(storage), 10)
        if status == 0x103:  # STATUS_PENDING: buffers must live through completion.
            if self.kernel.WaitForSingleObject(int(record['handle']), 0xFFFFFFFF) != 0:
                _UNCERTAIN_IO.append((storage, completed))
                raise OSError('native rename completion could not be established')
            status = completed.status
        elif status == 0:
            status = completed.status
        if status != 0:
            error = self.ntdll.RtlNtStatusToDosError(status)
            if error in (80, 183):
                raise FileExistsError('rename destination already exists')
            raise OSError(error, 'native relative handle rename failed')
        record['path'] = ntpath.join(destination['path'], leaf)

    def read_manifest(self, record):
        result = None
        for index, state in enumerate(self.STATES):
            try:
                opened = self._open(ntpath.join(record['path'], f'{index:02}-{state}.json'))
            except FileNotFoundError:
                continue
            try:
                if self.info(opened)['size'] > 65536:
                    raise ValueError('manifest exceeds limit')
                _, data = self._call(self.files.ReadFile, opened['handle'], 65537)
                result = json.loads(data)
                if result.get('state') != state:
                    raise ValueError('manifest state differs from record')
            finally:
                self._call(opened['handle'].Close)
        return result

    def write_manifest(self, record, manifest):
        state = manifest['state']
        name = f'{self.STATES.index(state):02}-{state}.json'
        existing = self.read_manifest(record)
        if existing == manifest:
            return
        if existing and self.STATES.index(existing['state']) >= self.STATES.index(state):
            raise ValueError('manifest cannot regress or replace recorded evidence')
        data = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
        if len(data) > 65536:
            raise ValueError('manifest exceeds limit')
        # A flushed temporary file is published by an exclusive handle rename.
        # Crashes before publication leave an ignored private temporary record.
        path = ntpath.join(record['path'], '.manifest-' + uuid4().hex + '.tmp')
        opened = self._open(path, creation=1, write=True, exclusive=True)
        try:
            self._call(self.files.WriteFile, opened['handle'], data)
            self._call(self.files.FlushFileBuffers, opened['handle'])
            self.rename(opened, record, name)
        finally:
            self._call(opened['handle'].Close)
