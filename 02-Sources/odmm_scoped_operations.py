"""V197.1 strict per-principal job visibility. Separate from legacy unscoped app.

A deployment-managed authorization database must explicitly grant each subject
access to each job. No wildcard, inferred scope, or implicit admin bypass.
"""
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import quote
from odmm_operations import OperationsView, _limit
from odmm_operations_security import require_permission

class ScopedOperationsView:
    def __init__(self, registry_path, grants_path):
        self.registry = OperationsView(registry_path)
        self.grants = Path(grants_path).resolve(strict=True)
        if not self.grants.is_file(): raise ValueError('GRANTS_FILE_REQUIRED')

    def _allowed(self, principal):
        require_permission(principal, 'operations:read')
        uri = 'file:' + quote(str(self.grants),safe='/') + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            rows=db.execute('SELECT job_id FROM job_grants WHERE subject=?', (principal.subject,)).fetchall()
        return frozenset(row[0] for row in rows)

    def jobs(self, principal, limit=50):
        limit=_limit(limit)
        allowed=self._allowed(principal)
        if not allowed: return {'schema':'odmm.jobs.v1','items':[],'read_only':True}
        with self.registry._connect() as db:
            placeholders=','.join('?' for _ in allowed)
            rows=db.execute('SELECT id,source,target,state,created_at FROM jobs WHERE id IN ('+placeholders+') ORDER BY created_at DESC,id DESC LIMIT ?', (*sorted(allowed),limit)).fetchall()
        return {'schema':'odmm.jobs.v1','items':[dict(r) for r in rows],'read_only':True}

    def operations(self, principal, job_id, limit=50):
        if not isinstance(job_id,str) or not 1<=len(job_id)<=128: raise ValueError('JOB_ID_INVALID')
        limit=_limit(limit)
        if job_id not in self._allowed(principal): raise LookupError('JOB_NOT_FOUND')
        return self.registry.operations(job_id,limit)

    def overview(self, principal):
        allowed=self._allowed(principal)
        if not allowed: return {'schema':'odmm.operations.v1','jobs':0,'operations':{},'audit_head':None,'read_only':True}
        with self.registry._connect() as db:
            placeholders=','.join('?' for _ in allowed)
            ids=tuple(sorted(allowed))
            count=db.execute('SELECT COUNT(*) FROM jobs WHERE id IN ('+placeholders+')',ids).fetchone()[0]
            rows=db.execute('SELECT state,COUNT(*) AS n FROM operations WHERE job_id IN ('+placeholders+') GROUP BY state',ids).fetchall()
        # Global audit head could leak activity in other scopes.
        return {'schema':'odmm.operations.v1','jobs':count,'operations':{r['state']:r['n'] for r in rows},'audit_head':None,'read_only':True}

def initialize_grants_schema(connection):
    """Explicit provisioning helper; never invoked by request handlers."""
    connection.execute('CREATE TABLE IF NOT EXISTS job_grants (subject TEXT NOT NULL, job_id TEXT NOT NULL, PRIMARY KEY(subject,job_id))')
