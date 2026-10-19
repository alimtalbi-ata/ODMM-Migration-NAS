"""Fail-closed durable incremental work planner. No filesystem mutation or cutover.

A plan is a proposal based on two observations, NOT a snapshot or authorization.
"""
import hashlib
import json
import sqlite3
import time
import uuid
from native_migration_errors import MigrationBlocked


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


class IncrementalPlanner:
    def __init__(self, inventory):
        self.inventory = inventory
        self.engine = inventory.engine
        self.db = self.engine.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS incremental_plans (
            plan_id TEXT PRIMARY KEY, previous_pass TEXT NOT NULL, current_pass TEXT NOT NULL,
            digest TEXT NOT NULL, created_ns INTEGER NOT NULL, status TEXT NOT NULL)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS incremental_tasks (
            plan_id TEXT NOT NULL, path TEXT NOT NULL, action TEXT NOT NULL,
            status TEXT NOT NULL, claim_token TEXT, claimed_ns INTEGER,
            PRIMARY KEY(plan_id,path),
            FOREIGN KEY(plan_id) REFERENCES incremental_plans(plan_id))''')
        self.db.execute('''CREATE UNIQUE INDEX IF NOT EXISTS incremental_pair_unique
            ON incremental_plans(previous_pass,current_pass)''')

    def _load_pass(self, pass_id):
        row = self.db.execute('SELECT status,digest FROM inventory_passes WHERE pass_id=?',(pass_id,)).fetchone()
        if row is None or row[0] != 'COMPLETE':
            raise MigrationBlocked('INCOMPLETE_INVENTORY_PASS')
        entries = {r[0]:list(r[1:]) for r in self.db.execute(
            'SELECT path,device,inode,size,mtime_ns,ctime_ns,mode FROM inventory_entries WHERE pass_id=? ORDER BY path', (pass_id,))}
        # Recalculate the original inventory digest; fail closed if entries changed.
        h = hashlib.sha256()
        for path, meta in entries.items():
            h.update(repr((path,*meta)).encode('utf-8'))
        if h.hexdigest() != row[1]:
            raise MigrationBlocked('INVENTORY_DIGEST_MISMATCH')
        return entries

    def create(self, previous, current):
        if previous == current:
            raise MigrationBlocked('IDENTICAL_PASSES')
        with self.engine._exclusive():
            old, new = self._load_pass(previous), self._load_pass(current)
            tasks = [(p,'COPY') for p in new if p not in old or new[p] != old[p]]
            tasks += [(p,'DELETE_REVIEW') for p in old if p not in new]
            tasks.sort()
            digest = hashlib.sha256(canonical({'previous':previous,'current':current,'tasks':tasks})).hexdigest()
            prior = self.db.execute('SELECT plan_id,digest FROM incremental_plans WHERE previous_pass=? AND current_pass=?', (previous,current)).fetchone()
            if prior:
                if prior[1] != digest:
                    raise MigrationBlocked('PLAN_DIGEST_CONFLICT')
                self._verify_locked(prior[0])
                return self._summary_locked(prior[0])
            plan_id = uuid.uuid4().hex
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('INSERT INTO incremental_plans VALUES (?,?,?,?,?,?)', (plan_id,previous,current,digest,time.time_ns(),'READY'))
                self.db.executemany('INSERT INTO incremental_tasks(plan_id,path,action,status) VALUES (?,?,?,?)',
                                    [(plan_id,p,a,'REVIEW_REQUIRED' if a == 'DELETE_REVIEW' else 'PENDING') for p,a in tasks])
                self.db.execute('COMMIT')
            except BaseException:
                # COMMIT can succeed before an I/O or wrapper error is raised.
                # Never mask the original error with a spurious ROLLBACK.
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
                raise
            return self._summary_locked(plan_id)

    def _verify_locked(self, plan_id):
        plan = self.db.execute('SELECT previous_pass,current_pass,digest FROM incremental_plans WHERE plan_id=?',(plan_id,)).fetchone()
        if plan is None:
            raise MigrationBlocked('UNKNOWN_PLAN')
        old,new = self._load_pass(plan[0]),self._load_pass(plan[1])
        expected = sorted([(p,'COPY') for p in new if p not in old or new[p]!=old[p]] +
                          [(p,'DELETE_REVIEW') for p in old if p not in new])
        rows = self.db.execute('SELECT path,action FROM incremental_tasks WHERE plan_id=? ORDER BY path',(plan_id,)).fetchall()
        digest = hashlib.sha256(canonical({'previous':plan[0],'current':plan[1],'tasks':expected})).hexdigest()
        if digest != plan[2] or rows != expected:
            raise MigrationBlocked('PLAN_INTEGRITY_MISMATCH')
        return plan

    def _summary_locked(self, plan_id):
        self._verify_locked(plan_id)
        tasks = self.db.execute('SELECT path,action,status FROM incremental_tasks WHERE plan_id=? ORDER BY path',(plan_id,)).fetchall()
        return {'plan_id':plan_id,'tasks':[{'path':p,'action':a,'status':s} for p,a,s in tasks],
                'status':'PLAN_REVIEW_REQUIRED','snapshot_consistent':False,
                'deletions_authorized':False,'cutover_authorized':False}

    def inspect(self, plan_id):
        with self.engine._exclusive():
            return self._summary_locked(plan_id)

    def recovery_report(self, plan_id):
        """Classify interrupted tasks without resetting claims or touching files.

        This is an advisory snapshot under the native engine lock. A later
        operator action must recheck current state independently.
        """
        with self.engine._exclusive():
            self._verify_locked(plan_id)
            rows = self.db.execute(
                'SELECT path,action,status,claim_token FROM incremental_tasks '
                'WHERE plan_id=? ORDER BY path', (plan_id,)
            ).fetchall()
            result = []
            for path, action, status, token in rows:
                native_intent = self.db.execute(
                    'SELECT 1 FROM intents WHERE path=?', (path,)
                ).fetchone() is not None
                native_file = self.db.execute(
                    'SELECT 1 FROM files WHERE path=?', (path,)
                ).fetchone() is not None
                if action != 'COPY':
                    decision = 'HUMAN_REVIEW'
                elif native_intent or native_file:
                    decision = 'NATIVE_RECONCILIATION_REQUIRED'
                elif status == 'CLAIMED':
                    decision = 'OPERATOR_RESET_ELIGIBLE' if token else 'BLOCKED_MISSING_CLAIM_TOKEN'
                elif status == 'PENDING':
                    decision = 'CLAIM_ELIGIBLE'
                else:
                    decision = 'HUMAN_REVIEW'
                result.append({
                    'path': path, 'action': action, 'status': status,
                    'decision': decision, 'native_intent': native_intent,
                    'native_file_record': native_file,
                })
            return {
                'plan_id': plan_id, 'tasks': result,
                'read_only': True, 'automatic_reset': False,
                'cutover_authorized': False,
                'snapshot_consistent': False,
            }

    def claim_copy(self, plan_id, path):
        """Lease-free durable claim: interrupted work remains blocked until explicit review."""
        with self.engine._exclusive():
            self._verify_locked(plan_id)
            token=uuid.uuid4().hex
            self.db.execute('BEGIN IMMEDIATE')
            try:
                result=self.db.execute('''UPDATE incremental_tasks SET status='CLAIMED',claim_token=?,claimed_ns=?
                    WHERE plan_id=? AND path=? AND action='COPY' AND status='PENDING' ''',
                    (token,time.time_ns(),plan_id,path))
                if result.rowcount != 1:
                    raise MigrationBlocked('COPY_NOT_CLAIMABLE')
                self.db.execute('COMMIT')
            except BaseException:
                # COMMIT can succeed before an I/O or wrapper error is raised.
                # Never mask the original error with a spurious ROLLBACK.
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
                raise
            return {'status':'CLAIMED_NOT_EXECUTED','claim_token':token,'cutover_authorized':False}

    def record_verified(self, plan_id, path, *, claim_token):
        """Requires prior independent verification of the actual copy via engine.verify()."""
        with self.engine._exclusive():
            self._verify_locked(plan_id)
            row=self.db.execute('SELECT action,status,claim_token FROM incremental_tasks WHERE plan_id=? AND path=?',(plan_id,path)).fetchone()
            if row != ('COPY','CLAIMED',claim_token) or not claim_token:
                raise MigrationBlocked('INVALID_COPY_CLAIM')
            # Cannot call engine.verify here: it reacquires flock. Require a committed
            # native-engine record; verify actual data via pinned fd before transition.
            if self.engine.db.execute('SELECT 1 FROM files WHERE path=?',(path,)).fetchone() is None:
                raise MigrationBlocked('NATIVE_COPY_NOT_COMMITTED')
            # This is a ledger acknowledgement, not proof of a fresh re-hash.
            self.db.execute('UPDATE incremental_tasks SET status=\'COMMITTED_REVERIFY_REQUIRED\' WHERE plan_id=? AND path=?',(plan_id,path))
            return {'status':'COMMITTED_REVERIFY_REQUIRED','cutover_authorized':False}

    def reset_interrupted(self, plan_id, path, *, claim_token, operator_confirmed=False):
        if operator_confirmed is not True:
            raise MigrationBlocked('OPERATOR_CONFIRMATION_REQUIRED')
        with self.engine._exclusive():
            self._verify_locked(plan_id)
            row=self.db.execute('SELECT action,status,claim_token FROM incremental_tasks WHERE plan_id=? AND path=?',(plan_id,path)).fetchone()
            if row != ('COPY','CLAIMED',claim_token) or not claim_token:
                raise MigrationBlocked('CLAIM_MISMATCH')
            # If a native engine intent or committed record exists, human reconciliation
            # must happen in the native engine first; never reset and re-copy blindly.
            if self.db.execute('SELECT 1 FROM intents WHERE path=? UNION SELECT 1 FROM files WHERE path=?',(path,path)).fetchone():
                raise MigrationBlocked('NATIVE_STATE_REQUIRES_RECONCILIATION')
            self.db.execute('UPDATE incremental_tasks SET status=\'PENDING\',claim_token=NULL,claimed_ns=NULL WHERE plan_id=? AND path=?',(plan_id,path))
            return {'status':'RESET_BY_OPERATOR','cutover_authorized':False}
