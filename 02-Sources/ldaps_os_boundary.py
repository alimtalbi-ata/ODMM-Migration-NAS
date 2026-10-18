"""POSIX filesystem isolation attestation for a dedicated RBAC service.

Does not change permissions or pretend to block in-process legacy APIs.
Run the service under a dedicated unprivileged UID and isolate its DB directory.
"""
import os
import stat
from pathlib import Path

class OSBoundaryError(PermissionError):
    pass

class POSIXBoundaryAttestation:
    def __init__(self, *, database_path, gate_path, expected_uid=None):
        self.database = Path(database_path)
        self.gate = Path(gate_path)
        self.expected_uid = expected_uid

    def verify(self):
        if os.name != 'posix' or not hasattr(os, 'geteuid'):
            raise OSBoundaryError('POSIX_REQUIRED')
        uid = os.geteuid()
        if uid == 0:
            raise OSBoundaryError('ROOT_SERVICE_REFUSED')
        if self.expected_uid is not None and (type(self.expected_uid) is not int or uid != self.expected_uid):
            raise OSBoundaryError('SERVICE_UID_MISMATCH')
        # Verify path components without following symlinks. A dedicated private
        # directory is required; do not assume filesystem ACLs or namespaces.
        parents = {self.database.parent, self.gate.parent}
        for parent in parents:
            if parent.is_symlink():
                raise OSBoundaryError('SYMLINK_DIRECTORY_REFUSED')
            try:
                st = parent.lstat()
            except OSError as exc:
                raise OSBoundaryError('DIRECTORY_UNAVAILABLE') from exc
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or (st.st_mode & 0o077):
                raise OSBoundaryError('PRIVATE_DIRECTORY_REQUIRED')
        for path in (self.database, self.gate):
            try:
                st = path.lstat()
            except OSError as exc:
                raise OSBoundaryError('DATABASE_OR_GATE_UNAVAILABLE') from exc
            if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or (st.st_mode & 0o077):
                raise OSBoundaryError('PRIVATE_FILE_REQUIRED')
        for suffix in ('-wal', '-shm', '-journal'):
            path = Path(str(self.database) + suffix)
            if path.is_symlink():
                raise OSBoundaryError('SQLITE_SIDECAR_SYMLINK')
            if path.exists():
                st = path.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or (st.st_mode & 0o077):
                    raise OSBoundaryError('UNSAFE_SQLITE_SIDECAR')
        return {'status':'POSIX_FILESYSTEM_BOUNDARY_VERIFIED',
                'uid':uid,'legacy_api_isolation_proven':False,
                'execution_authorized':False,'cutover_authorized':False}
