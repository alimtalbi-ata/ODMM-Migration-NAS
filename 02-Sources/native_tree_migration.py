"""Fail-closed POSIX tree orchestration over the V189.2 transactional file engine.

Not a NAS/ACL or distributed-fencing implementation. Destination directories must
already exist; no implicit topology or security metadata changes are performed.
"""
import os
import stat
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked


class NativeTreeMigration:
    def __init__(self, source, target, database):
        self.engine = NativePosixMigration(source, target, database)

    def close(self):
        self.engine.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def inventory(self):
        """Return a stable ordered snapshot of regular-file paths, refusing special entries."""
        result = []
        for root, dirs, files in os.walk(self.engine.source, topdown=True, followlinks=False):
            dirs.sort()
            files.sort()
            for name in dirs:
                p = Path(root) / name
                st = p.lstat()
                if not stat.S_ISDIR(st.st_mode):
                    raise MigrationBlocked('UNSUPPORTED_DIRECTORY_ENTRY')
            for name in files:
                p = Path(root) / name
                st = p.lstat()
                if not stat.S_ISREG(st.st_mode):
                    raise MigrationBlocked('UNSUPPORTED_FILE_ENTRY')
                rel = p.relative_to(self.engine.source).as_posix()
                self.engine._paths(rel)
                result.append(rel)
        return result

    def run(self, *, limit=None, nas_preflight=None):
        """Migrate up to limit files. Stops on first failure, never skips an error."""
        if nas_preflight is not None:
            # A structural preflight cannot authorize real NAS cutover.
            if getattr(nas_preflight, "cutover_authorized", None) is not False or getattr(nas_preflight, "blockers", None) is None:
                raise MigrationBlocked("INVALID_NAS_PREFLIGHT")
            raise MigrationBlocked("NAS_PREFLIGHT_NOT_QUALIFIED")
        if limit is not None and (type(limit) is not int or limit < 0):
            raise ValueError('INVALID_LIMIT')
        paths = self.inventory()
        selected = paths if limit is None else paths[:limit]
        outcomes = []
        for rel in selected:
            outcomes.append(self.engine.copy(rel))
        return {'status':'BATCH_COMPLETE_POSIX_SUBSET_ONLY', 'inventory_count':len(paths),
                'processed_count':len(outcomes), 'results':outcomes,
                'cutover_authorized':False, 'acl_fidelity_verified':False}

    def verify_all(self):
        paths = self.inventory()
        results = [self.engine.verify(rel) for rel in paths]
        return {'status':'TREE_VERIFIED_POSIX_SUBSET_ONLY', 'count':len(results),
                'cutover_authorized':False, 'acl_fidelity_verified':False}
