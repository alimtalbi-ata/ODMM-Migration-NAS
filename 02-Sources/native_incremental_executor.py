"""V190.2 conservative executor for *already claimed* incremental COPY tasks.

Never performs deletion, fallback, cutover, or automatic claim recovery.
A successful execution remains explicitly marked POSIX_SUBSET_ONLY.
"""
import os
import stat
import time
from native_migration_errors import MigrationBlocked
from native_posix_migration import _identity, _verified_hash
from native_dirfd_guard import parent_fd

class IncrementalExecutor:
    def __init__(self, planner, *, timing_sink=None):
        self.planner=planner
        self.engine=planner.engine
        self.db=planner.db
        self.timing_sink=timing_sink
        self.last_timings=[]

    def _record_timing(self, stage, elapsed_ns, *, start_ns=None):
        record={"stage":stage,"elapsed_ns":max(0,int(elapsed_ns))}
        if start_ns is not None:
            record["start_ns"]=int(start_ns)
            record["end_ns"]=int(start_ns)+record["elapsed_ns"]
        self.last_timings.append(record)
        if self.timing_sink is not None:
            try:
                self.timing_sink(dict(record))
            except Exception:
                pass  # Observability must never change migration decisions.

    def _source_matches_inventory(self, plan_id, path):
        row=self.db.execute('''SELECT e.device,e.inode,e.size,e.mtime_ns,e.ctime_ns,e.mode
            FROM incremental_plans p JOIN inventory_entries e ON e.pass_id=p.current_pass
            WHERE p.plan_id=? AND e.path=?''',(plan_id,path)).fetchone()
        if row is None:
            raise MigrationBlocked('MISSING_INVENTORY_ENTRY')
        with parent_fd(self.engine.source,path,root_fd=self.engine._root_fds[0]) as (directory,name):
            fd,st=self.engine._open_file(directory,name)
            try:
                actual=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns,stat.S_IMODE(st.st_mode))
                if actual!=row:
                    raise MigrationBlocked('SOURCE_DRIFT_SINCE_INVENTORY')
                self.engine._check_source_entry(directory,name,fd)
                self.engine._check_parent_identity(self.engine.source,path,directory)
            finally:os.close(fd)

    def _verify_locked(self, path):
        started=time.perf_counter_ns()
        row=self.db.execute('SELECT size,sha256,mode,mtime_ns FROM files WHERE path=?',(path,)).fetchone()
        self._record_timing("verify.sqlite_lookup",time.perf_counter_ns()-started,start_ns=started)
        if row is None:raise MigrationBlocked('NATIVE_COPY_NOT_COMMITTED')
        for root,idx,target in ((self.engine.source,0,False),(self.engine.target,1,True)):
            with parent_fd(root,path,root_fd=self.engine._root_fds[idx]) as (directory,name):
                fd,st=self.engine._open_file(directory,name)
                try:
                    hash_started=time.perf_counter_ns()
                    digest=_verified_hash(fd,expected=st) if st.st_size==row[0] else None
                    self._record_timing("verify.target_sha256" if target else "verify.source_sha256",time.perf_counter_ns()-hash_started,start_ns=hash_started)
                    if st.st_size!=row[0] or digest!=row[1]:
                        raise MigrationBlocked('COPY_REVERIFY_FAILED')
                    # Catch external writers that modify the inode during hashing.
                    # This is not an atomic snapshot or protection against later writes.
                    post=os.fstat(fd)
                    if (post.st_dev,post.st_ino,post.st_size,post.st_mtime_ns,post.st_ctime_ns) != (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns):
                        raise MigrationBlocked('COPY_CHANGED_DURING_HASH')
                    if target and (stat.S_IMODE(st.st_mode),st.st_mtime_ns)!=(row[2],row[3]):
                        raise MigrationBlocked('COPY_METADATA_DRIFT')
                    self.engine._check_source_entry(directory,name,fd)
                    self.engine._check_parent_identity(root,path,directory)
                finally:os.close(fd)
        return row[1]

    def _commit_verified_claim_locked(self, plan_id, path, claim_token):
        """Reverify claim and files in the final database transaction.

        External non-cooperating filesystem writers remain a TOCTOU risk.
        """
        transaction_started=time.perf_counter_ns()
        self.db.execute('BEGIN IMMEDIATE')
        try:
            stage_started=time.perf_counter_ns()
            claim = self.db.execute("""SELECT action,status,claim_token
                FROM incremental_tasks WHERE plan_id=? AND path=?""",
                (plan_id, path)).fetchone()
            self._record_timing('commit.claim_lookup',time.perf_counter_ns()-stage_started,start_ns=stage_started)
            if claim != ('COPY', 'CLAIMED', claim_token):
                raise MigrationBlocked('CLAIM_CHANGED_DURING_VERIFICATION')
            if self.db.execute('SELECT 1 FROM intents WHERE path=?', (path,)).fetchone():
                raise MigrationBlocked('PENDING_NATIVE_INTENT')
            self._source_matches_inventory(plan_id, path)
            self._verify_locked(path)
            stage_started=time.perf_counter_ns()
            changed = self.db.execute("""UPDATE incremental_tasks
                SET status='VERIFIED_POSIX_SUBSET'
                WHERE plan_id=? AND path=? AND action='COPY'
                  AND status='CLAIMED' AND claim_token=?""",
                (plan_id, path, claim_token))
            self._record_timing('commit.claim_update',time.perf_counter_ns()-stage_started,start_ns=stage_started)
            if changed.rowcount != 1:
                raise MigrationBlocked('CLAIM_CHANGED_DURING_VERIFICATION')
            stage_started=time.perf_counter_ns()
            self.db.execute('COMMIT')
            self._record_timing('commit.sqlite_commit',time.perf_counter_ns()-stage_started,start_ns=stage_started)
            self._record_timing('commit.sqlite_transaction',time.perf_counter_ns()-transaction_started,start_ns=transaction_started)
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            self._record_timing('rollback.sqlite_transaction',time.perf_counter_ns()-transaction_started,start_ns=transaction_started)
            raise

    def execute_claimed(self,plan_id,path,*,claim_token,after_publish=None):
        if not isinstance(claim_token,str) or not claim_token:
            raise MigrationBlocked('CLAIM_TOKEN_REQUIRED')
        with self.engine._exclusive():
            self.engine._check_roots()
            self.planner._verify_locked(plan_id)
            row=self.db.execute('SELECT action,status,claim_token FROM incremental_tasks WHERE plan_id=? AND path=?',(plan_id,path)).fetchone()
            if row!=('COPY','CLAIMED',claim_token):
                raise MigrationBlocked('INVALID_COPY_CLAIM')
            self._source_matches_inventory(plan_id,path)
            # If an earlier attempt published before crashing, explicit native
            # reconciliation is required; never overwrite or infer success.
            if self.db.execute('SELECT 1 FROM intents WHERE path=?',(path,)).fetchone():
                raise MigrationBlocked('NATIVE_INTENT_REQUIRES_RECONCILIATION')
            if self.db.execute('SELECT 1 FROM files WHERE path=?',(path,)).fetchone():
                raise MigrationBlocked('NATIVE_COMMIT_REQUIRES_ACK_REVIEW')
            copy_started=time.perf_counter_ns()
            try:
                result=self.engine._copy_locked(path,after_publish=after_publish)
            finally:
                self._record_timing("copy.native_posix",time.perf_counter_ns()-copy_started,start_ns=copy_started)
            source_started=time.perf_counter_ns()
            try:
                self._source_matches_inventory(plan_id,path)
            finally:
                self._record_timing("verify.source_inventory",time.perf_counter_ns()-source_started,start_ns=source_started)
            digest=self._verify_locked(path)
            self._commit_verified_claim_locked(plan_id,path,claim_token)
            return {'status':'VERIFIED_POSIX_SUBSET','path':path,'sha256':digest,
                    'acl_fidelity_verified':False,'snapshot_consistent':False,
                    'deletions_authorized':False,'cutover_authorized':False}

    def acknowledge_reconciled(self,plan_id,path,*,claim_token,operator_confirmed=False):
        if operator_confirmed is not True:raise MigrationBlocked('OPERATOR_CONFIRMATION_REQUIRED')
        with self.engine._exclusive():
            self.engine._check_roots()
            self.planner._verify_locked(plan_id)
            row=self.db.execute('SELECT action,status,claim_token FROM incremental_tasks WHERE plan_id=? AND path=?',(plan_id,path)).fetchone()
            if row!=('COPY','CLAIMED',claim_token) or not claim_token:
                raise MigrationBlocked('INVALID_COPY_CLAIM')
            if self.db.execute('SELECT 1 FROM intents WHERE path=?',(path,)).fetchone():
                raise MigrationBlocked('PENDING_NATIVE_INTENT')
            source_started=time.perf_counter_ns()
            try:
                self._source_matches_inventory(plan_id,path)
            finally:
                self._record_timing("verify.source_inventory",time.perf_counter_ns()-source_started,start_ns=source_started)
            digest=self._verify_locked(path)
            self._commit_verified_claim_locked(plan_id,path,claim_token)
            return {'status':'VERIFIED_POSIX_SUBSET','sha256':digest,'cutover_authorized':False,
                    'acl_fidelity_verified':False,'snapshot_consistent':False}
