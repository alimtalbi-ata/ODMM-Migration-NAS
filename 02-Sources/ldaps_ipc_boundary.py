"""Local POSIX read-only IPC boundary for RBAC audit status.

No role mutation endpoint is exposed. SO_PEERCRED is Linux-specific; this
module fails closed elsewhere. The socket directory must be privately owned.
"""
import json
import os
import socket
import stat
import struct
from pathlib import Path

class IPCBoundaryError(PermissionError):
    pass

class LocalAuditIPC:
    def __init__(self, service, *, socket_path, allowed_uids, max_request=1024):
        if not isinstance(allowed_uids, (set, frozenset)) or not allowed_uids or any(type(x) is not int or x < 0 for x in allowed_uids):
            raise IPCBoundaryError('INVALID_ALLOWED_UIDS')
        if type(max_request) is not int or not 32 <= max_request <= 65536:
            raise IPCBoundaryError('INVALID_REQUEST_LIMIT')
        self.service = service
        self.path = Path(socket_path)
        self.allowed_uids = frozenset(allowed_uids)
        self.max_request = max_request

    def _check_directory(self):
        if os.name != 'posix' or not hasattr(socket, 'SO_PEERCRED') or not hasattr(os, 'geteuid'):
            raise IPCBoundaryError('LINUX_PEERCRED_REQUIRED')
        if os.geteuid() == 0:
            raise IPCBoundaryError('ROOT_SERVICE_REFUSED')
        parent = self.path.parent
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise IPCBoundaryError('PRIVATE_SOCKET_DIRECTORY_REQUIRED')
        if self.path.is_symlink() or self.path.exists():
            raise IPCBoundaryError('SOCKET_PATH_ALREADY_EXISTS')

    def bind(self):
        self._check_directory()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.path))
            os.chmod(self.path, 0o600)
            listener.listen(8)
            return listener
        except BaseException:
            listener.close()
            raise

    def handle(self, conn):
        """Handle one connected client; never return privileged internals."""
        conn.settimeout(3)
        try:
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
            _pid, uid, _gid = struct.unpack('3i', raw)
            if uid not in self.allowed_uids:
                raise IPCBoundaryError('PEER_UID_DENIED')
            payload = bytearray()
            while len(payload) <= self.max_request:
                part = conn.recv(min(512, self.max_request + 1 - len(payload)))
                if not part:
                    break
                payload.extend(part)
                if b'\n' in part:
                    break
            if len(payload) > self.max_request or not payload.endswith(b'\n'):
                raise IPCBoundaryError('REQUEST_SIZE_OR_FRAMING_INVALID')
            try:
                request = json.loads(payload)
            except (ValueError, UnicodeError) as exc:
                raise IPCBoundaryError('INVALID_REQUEST_JSON') from exc
            if type(request) is not dict or request != {'operation':'audit_status'}:
                raise IPCBoundaryError('OPERATION_NOT_EXPOSED')
            result = self.service.audit_status()
            response = {'status':'OK', 'audit':result, 'execution_authorized':False,'cutover_authorized':False}
            conn.sendall(json.dumps(response, sort_keys=True).encode() + b'\n')
            return response
        except (IPCBoundaryError, OSError, ValueError):
            try:
                conn.sendall(b'{"status":"DENIED","execution_authorized":false,"cutover_authorized":false}\n')
            except OSError:
                pass
            return {'status':'DENIED','execution_authorized':False,'cutover_authorized':False}
