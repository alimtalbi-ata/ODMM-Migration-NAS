"""Explicit, fail-closed lifecycle for the read-only Linux audit IPC service.

Only a socket created by this instance may be unlinked. Stale paths require
manual investigation; neither a restart nor a failed bind removes them.
"""
import os
import socket
import stat
import threading
from pathlib import Path
from ldaps_ipc_boundary import IPCBoundaryError

class AuditIPCLifecycle:
    def __init__(self, boundary, *, backlog=8, accept_timeout=0.2):
        if type(backlog) is not int or not 1 <= backlog <= 128:
            raise IPCBoundaryError('INVALID_BACKLOG')
        if not isinstance(accept_timeout, (int, float)) or isinstance(accept_timeout, bool) or not 0.01 <= accept_timeout <= 5:
            raise IPCBoundaryError('INVALID_ACCEPT_TIMEOUT')
        self.boundary = boundary
        self.backlog = backlog
        self.accept_timeout = accept_timeout
        self._listener = None
        self._identity = None
        self._stop = threading.Event()
        self._guard = threading.Lock()

    def start(self):
        with self._guard:
            if self._listener is not None:
                raise IPCBoundaryError('ALREADY_STARTED')
            listener = self.boundary.bind()
            try:
                listener.listen(self.backlog)
                listener.settimeout(self.accept_timeout)
                st = os.lstat(self.boundary.path)
                if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                    raise IPCBoundaryError('SOCKET_IDENTITY_INVALID')
                self._identity = (st.st_dev, st.st_ino)
                self._stop.clear()
                self._listener = listener
            except BaseException:
                listener.close()
                # Do not delete a path on failure; manual review is required.
                raise
        return {'status':'LISTENING','execution_authorized':False,'cutover_authorized':False}

    def serve(self, *, max_connections=None):
        if max_connections is not None and (type(max_connections) is not int or max_connections < 0):
            raise IPCBoundaryError('INVALID_CONNECTION_LIMIT')
        if self._listener is None:
            raise IPCBoundaryError('NOT_STARTED')
        count = 0
        while not self._stop.is_set() and (max_connections is None or count < max_connections):
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            with conn:
                self.boundary.handle(conn)
            count += 1
        return {'status':'STOPPED' if self._stop.is_set() else 'LIMIT_REACHED',
                'connections':count,'execution_authorized':False,'cutover_authorized':False}

    def stop(self):
        self._stop.set()
        with self._guard:
            listener, self._listener = self._listener, None
            identity, self._identity = self._identity, None
            if listener is not None:
                listener.close()
            if identity is None:
                return {'status':'NOT_RUNNING','execution_authorized':False,'cutover_authorized':False}
            try:
                st = os.lstat(self.boundary.path)
            except FileNotFoundError:
                raise IPCBoundaryError('SOCKET_DISAPPEARED_MANUAL_REVIEW')
            if not stat.S_ISSOCK(st.st_mode) or (st.st_dev, st.st_ino) != identity:
                raise IPCBoundaryError('SOCKET_REPLACED_MANUAL_REVIEW')
            os.unlink(self.boundary.path)
            return {'status':'STOPPED_CLEAN','execution_authorized':False,'cutover_authorized':False}
