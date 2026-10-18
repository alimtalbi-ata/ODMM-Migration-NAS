"""Read-only active IPC liveness probe; no socket removal or service restart.

A successful response proves only that an endpoint answered the fixed audit request,
not that its process is trusted. Unix peer UID and socket inode are checked to
reduce substitution risk. This is not a distributed attestation mechanism.
"""
import json
import os
import socket
import stat
import struct
import time
from pathlib import Path
from ldaps_ipc_boundary import IPCBoundaryError

class ActiveAuditProbe:
    def __init__(self, socket_path, *, expected_uid, timeout=1.0, max_response=65536):
        if type(expected_uid) is not int or expected_uid < 0:
            raise IPCBoundaryError('INVALID_EXPECTED_UID')
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 10:
            raise IPCBoundaryError('INVALID_TIMEOUT')
        if type(max_response) is not int or not 128 <= max_response <= 1048576:
            raise IPCBoundaryError('INVALID_RESPONSE_LIMIT')
        self.path = Path(socket_path)
        self.uid = expected_uid
        self.timeout = timeout
        self.max_response = max_response

    def _identity(self):
        st = os.lstat(self.path)
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != self.uid or st.st_mode & 0o077:
            raise IPCBoundaryError('SOCKET_IDENTITY_INVALID')
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))

    def check(self):
        base = {'execution_authorized': False, 'cutover_authorized': False,
                'automatic_cleanup': False, 'automatic_restart': False}
        if os.name != 'posix' or not hasattr(socket, 'SO_PEERCRED'):
            return dict(base, status='LINUX_PEERCRED_REQUIRED')
        try:
            before = self._identity()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(self.timeout)
                conn.connect(str(self.path))
                raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
                pid, uid, gid = struct.unpack('3i', raw)
                if uid != self.uid:
                    raise IPCBoundaryError('PEER_UID_MISMATCH')
                conn.sendall(b'{"operation":"audit_status"}\n')
                data = bytearray()
                while len(data) <= self.max_response:
                    part = conn.recv(min(4096, self.max_response + 1 - len(data)))
                    if not part:
                        break
                    data.extend(part)
                    if b'\n' in data:
                        break
            after = self._identity()
            if before != after:
                raise IPCBoundaryError('SOCKET_REPLACED_DURING_PROBE')
            if len(data) > self.max_response or not data.endswith(b'\n') or data.count(b'\n') != 1:
                raise IPCBoundaryError('INVALID_RESPONSE_FRAMING')
            payload = json.loads(data)
            if not isinstance(payload, dict) or payload.get('status') != 'OK' or not isinstance(payload.get('audit'), dict):
                raise IPCBoundaryError('UNEXPECTED_AUDIT_RESPONSE')
            if payload.get('execution_authorized') is not False or payload.get('cutover_authorized') is not False:
                raise IPCBoundaryError('UNSAFE_RESPONSE_FLAGS')
            return dict(base, status='AUDIT_ENDPOINT_RESPONSIVE', peer_pid=pid, peer_uid=uid)
        except FileNotFoundError:
            return dict(base, status='SOCKET_ABSENT')
        except (OSError, ValueError, TypeError, IPCBoundaryError, UnicodeError):
            return dict(base, status='PROBE_FAILED_MANUAL_REVIEW')
