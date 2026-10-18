"""ODMM V201.7 - conservative, read-only sparse/ADS capability evidence.
Author: Abdelhalim Talbi. No migration, fallback, or cutover authorization.
"""
import errno
import hashlib
import json
import os
import stat
from pathlib import Path

SCHEMA = 'odmm.sparse.ads.preflight.v2017'

def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def sparse_extents(path, *, max_extents=100000):
    """SEEK_DATA/SEEK_HOLE extents; never interpret unsupported as all-data."""
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ValueError('REGULAR_FILE_REQUIRED')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(p, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError('REGULAR_FILE_REQUIRED')
        size = st.st_size
        if not hasattr(os, 'SEEK_DATA') or not hasattr(os, 'SEEK_HOLE'):
            return {'status': 'UNSUPPORTED', 'size': size, 'extents': []}
        extents = []
        offset = 0
        while offset < size:
            if len(extents) >= max_extents:
                return {'status': 'LIMIT_EXCEEDED', 'size': size, 'extents': []}
            try:
                data = os.lseek(fd, offset, os.SEEK_DATA)
            except OSError as e:
                if e.errno == errno.ENXIO:
                    extents.append(['HOLE', offset, size]); break
                if e.errno in (errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS):
                    return {'status': 'UNSUPPORTED', 'size': size, 'extents': []}
                raise
            if data > offset:
                extents.append(['HOLE', offset, data])
            try:
                end = os.lseek(fd, data, os.SEEK_HOLE)
            except OSError as e:
                if e.errno in (errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS):
                    return {'status': 'UNSUPPORTED', 'size': size, 'extents': []}
                raise
            if end <= data or end > size:
                return {'status': 'INVALID_EXTENTS', 'size': size, 'extents': []}
            extents.append(['DATA', data, end]); offset = end
        return {'status': 'OBSERVED', 'size': size, 'extents': extents}
    finally:
        os.close(fd)

def compare_sparse(source, target):
    a, b = sparse_extents(source), sparse_extents(target)
    status = ('UNVERIFIED' if a['status'] != 'OBSERVED' or b['status'] != 'OBSERVED'
              else 'MATCH' if a['size'] == b['size'] and a['extents'] == b['extents'] else 'MISMATCH')
    result = {'schema': SCHEMA, 'source': a, 'target': b, 'status': status,
              'cutover_authorized': False, 'writes_to_nas': False}
    result['report_sha256'] = _hash(result)
    return result

def ads_inventory(path):
    """Windows ADS stream names and lengths; no stream contents read.
    Windows API enumerates streams; failure remains UNVERIFIED.
    """
    if os.name != 'nt':
        return {'status': 'UNSUPPORTED_PLATFORM', 'streams': []}
    import ctypes
    from ctypes import wintypes
    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [('StreamSize', ctypes.c_int64), ('cStreamName', wintypes.WCHAR * 296)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    first = kernel.FindFirstStreamW
    first.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(WIN32_FIND_STREAM_DATA), wintypes.DWORD]
    first.restype = wintypes.HANDLE
    nxt = kernel.FindNextStreamW
    nxt.argtypes = [wintypes.HANDLE, ctypes.POINTER(WIN32_FIND_STREAM_DATA)]
    nxt.restype = wintypes.BOOL
    close = kernel.FindClose
    close.argtypes = [wintypes.HANDLE]
    data = WIN32_FIND_STREAM_DATA()
    handle = first(str(path), 0, ctypes.byref(data), 0)
    if handle == ctypes.c_void_p(-1).value:
        return {'status': 'UNVERIFIED', 'streams': []}
    streams = []
    try:
        while True:
            streams.append({'name': data.cStreamName, 'size': data.StreamSize})
            if not nxt(handle, ctypes.byref(data)):
                if ctypes.get_last_error() != 38:  # ERROR_HANDLE_EOF
                    return {'status': 'UNVERIFIED', 'streams': []}
                break
    finally:
        close(handle)
    return {'status': 'OBSERVED_NAMES_AND_SIZES_ONLY', 'streams': sorted(streams, key=lambda x:x['name'])}

def preflight(source_root, target_root, *, protocol='NFSv4', require_sparse=True, require_ads=False):
    """Non-destructive preflight; a feature cannot be declared supported by guesswork."""
    roots = [Path(source_root), Path(target_root)]
    if any(p.is_symlink() or not p.is_dir() for p in roots):
        raise ValueError('DIRECTORY_REQUIRED_NO_SYMLINK')
    checks = {'source_exists': True, 'target_exists': True,
              'sparse': 'REQUIRES_PER_FILE_EVIDENCE' if require_sparse else 'NOT_REQUIRED',
              'ads': 'REQUIRES_WINDOWS_STREAM_INVENTORY_AND_CONTENT_HASH' if require_ads else 'NOT_REQUIRED',
              'acl': 'REQUIRES_LIVE_PROTOCOL_AND_EFFECTIVE_ACCESS_EVIDENCE',
              'identity': 'REQUIRES_AD_LDAP_MAPPING_ATTESTATION'}
    result = {'schema': SCHEMA, 'protocol': protocol, 'checks': checks,
              'status': 'BLOCKED_UNVERIFIED', 'cutover_authorized': False,
              'native_engine_default': True, 'writes_to_nas': False,
              'silent_fallback_allowed': False}
    result['report_sha256'] = _hash(result)
    return result
