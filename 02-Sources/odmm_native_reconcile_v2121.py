"""Read-only reconciliation of native staging journal. Author: Abdelhalim Talbi.

No state transition is performed: a matching digest is evidence, not proof of
ACL fidelity, source stability, fencing ownership, or authorized cutover.
"""
import os
import stat
from odmm_native_secure_v2120 import SecureStaging, _parts, _parent, FLAGS, _digest, Blocked

class ReconciledStaging(SecureStaging):
    def reconcile(self, *, fence):
        """Inspect journal rows and destination files, fail closed on missing fencing.

        Uses pinned directory descriptors, rejects symlinks and hardlinks, and
        checks inode identity before and after hashing. Never repairs automatically.
        """
        if not callable(fence) or fence() is not True:
            raise Blocked('FENCE_REQUIRED')
        rows = self.db.execute('SELECT path,sha256,state,attempts FROM secure_transfers ORDER BY path').fetchall()
        result = []
        for name, expected, state, attempts in rows:
            parent = None
            fd = None
            status = 'UNKNOWN'
            try:
                parts = _parts(name)
                parent = _parent(self.dstfd, parts)
                try:
                    fd = os.open(parts[-1], FLAGS | getattr(os,'O_NONBLOCK',0), dir_fd=parent)
                except FileNotFoundError:
                    status = 'MISSING'
                else:
                    before = os.fstat(fd)
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                        status = 'UNSAFE_TARGET'
                    else:
                        actual = _digest(fd)
                        after = os.fstat(fd)
                        identity = lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
                        status = ('MATCH' if actual == expected else 'HASH_MISMATCH') if identity(before)==identity(after) else 'TARGET_CHANGED'
            except (OSError, Blocked, ValueError):
                status = 'UNSAFE_PATH'
            finally:
                if fd is not None: os.close(fd)
                if parent is not None: os.close(parent)
            if fence() is not True:
                raise Blocked('FENCE_LOST')
            result.append({'path':name,'journal_state':state,'target_status':status,
                           'attempts':attempts,'requires_human_review': state!='VERIFIED' or status!='MATCH',
                           'cutover_authorized':False,'acl_fidelity_verified':False})
        return result
