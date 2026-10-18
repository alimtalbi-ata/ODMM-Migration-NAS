"""Durable, read-only POSIX incremental inventory for the native ODMM engine.

Inventory passes are observations, not filesystem snapshots. Never authorize cutover.
"""
import hashlib
import os
import sqlite3
import stat
import time
import uuid
from pathlib import Path
from native_migration_errors import MigrationBlocked

class IncrementalInventory:
    def __init__(self, engine):
        self.engine = engine
        self.db = engine.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS inventory_passes
            (pass_id TEXT PRIMARY KEY, started_ns INTEGER NOT NULL, completed_ns INTEGER,
             status TEXT NOT NULL CHECK(status IN ('SCANNING','COMPLETE','FAILED')),
             count INTEGER NOT NULL DEFAULT 0, digest TEXT)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS inventory_entries
            (pass_id TEXT NOT NULL, path TEXT NOT NULL, device INTEGER NOT NULL,
             inode INTEGER NOT NULL, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
             ctime_ns INTEGER NOT NULL, mode INTEGER NOT NULL,
             PRIMARY KEY(pass_id,path), FOREIGN KEY(pass_id) REFERENCES inventory_passes(pass_id))''')

    def _scan(self):
        """Traverse pinned root by fd, refuse symlinks/special files; no data copying."""
        rootfd = self.engine._root_fds[0]
        def visit(fd, prefix):
            names = sorted(os.listdir(fd))
            for name in names:
                if name in ('.','..') or '/' in name:
                    raise MigrationBlocked('INVALID_INVENTORY_NAME')
                rel = prefix + name
                s = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(s.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        actual = os.fstat(child)
                        if (actual.st_dev,actual.st_ino)!=(s.st_dev,s.st_ino):
                            raise MigrationBlocked('INVENTORY_DIRECTORY_CHANGED')
                        yield from visit(child,rel+'/')
                        latest=os.stat(name,dir_fd=fd,follow_symlinks=False)
                        if (latest.st_dev,latest.st_ino)!=(s.st_dev,s.st_ino):
                            raise MigrationBlocked('INVENTORY_DIRECTORY_CHANGED')
                    finally: os.close(child)
                elif stat.S_ISREG(s.st_mode):
                    self.engine._paths(rel)
                    yield (rel,s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,stat.S_IMODE(s.st_mode))
                else:
                    raise MigrationBlocked('UNSUPPORTED_INVENTORY_ENTRY')
        yield from visit(rootfd,'')

    def capture(self):
        with self.engine._exclusive():
            self.engine._check_roots()
            pid=uuid.uuid4().hex
            self.db.execute('INSERT INTO inventory_passes(pass_id,started_ns,status) VALUES (?,?,?)',(pid,time.time_ns(),'SCANNING'))
            count=0
            digest=hashlib.sha256()
            try:
                for entry in self._scan():
                    self.db.execute('INSERT INTO inventory_entries VALUES (?,?,?,?,?,?,?,?)',(pid,*entry))
                    digest.update(repr(entry).encode('utf-8'))
                    count+=1
                self.engine._check_roots()
                self.db.execute('UPDATE inventory_passes SET status=?,completed_ns=?,count=?,digest=? WHERE pass_id=?',('COMPLETE',time.time_ns(),count,digest.hexdigest(),pid))
            except BaseException:
                self.db.execute('UPDATE inventory_passes SET status=?,completed_ns=? WHERE pass_id=?',('FAILED',time.time_ns(),pid))
                raise
            return {'pass_id':pid,'count':count,'digest':digest.hexdigest(),'status':'INVENTORY_COMPLETE_NOT_SNAPSHOT','cutover_authorized':False}

    def diff(self, previous, current):
        with self.engine._exclusive():
            def load(pid):
                row=self.db.execute('SELECT status FROM inventory_passes WHERE pass_id=?',(pid,)).fetchone()
                if row != ('COMPLETE',): raise MigrationBlocked('INCOMPLETE_OR_UNKNOWN_PASS')
                return {r[0]:tuple(r[1:]) for r in self.db.execute('SELECT path,device,inode,size,mtime_ns,ctime_ns,mode FROM inventory_entries WHERE pass_id=?',(pid,))}
            old,new=load(previous),load(current)
            added=sorted(new.keys()-old.keys()); deleted=sorted(old.keys()-new.keys())
            modified=sorted(p for p in new.keys()&old.keys() if new[p]!=old[p])
            return {'status':'INCREMENTAL_DIFF_REVIEW_REQUIRED','added':added,'deleted':deleted,'modified':modified,
                    'unchanged_count':len(new)-len(added)-len(modified),'cutover_authorized':False,
                    'acl_fidelity_verified':False,'snapshot_consistent':False}
