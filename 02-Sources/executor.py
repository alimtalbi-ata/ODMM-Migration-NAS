"""V177.0 atomic approval consumption + execution preparation; no external writes."""
import time, uuid
from recovery_plan import RecoveryExecutionRegistry, SAFE_DECISIONS

class RecoveryExecutorRegistry(RecoveryExecutionRegistry):
    def __init__(self,path):
        super().__init__(path)
        self.db.execute('''CREATE TABLE IF NOT EXISTS recovery_executions(
          execution_id TEXT PRIMARY KEY, approval_id TEXT NOT NULL UNIQUE,
          intent_id TEXT NOT NULL, decision TEXT NOT NULL, owner TEXT NOT NULL,
          epoch INTEGER NOT NULL, state TEXT NOT NULL,
          created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL,
          observation TEXT)''')

    def prepare_execution(self, approval_id, owner, epoch, *, fault_point=None):
        """One SQLite transaction for approval, transition, execution and audit.
        fault_point is test-only and simulates a failure before commit.
        """
        if not owner or type(epoch) is not int:
            raise ValueError('INVALID_FENCING_IDENTITY')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            existing=self.db.execute('SELECT * FROM recovery_executions WHERE approval_id=?',(approval_id,)).fetchone()
            if existing:
                if existing['owner'] != owner or existing['epoch'] != epoch:
                    raise ValueError('EXECUTION_OWNERSHIP_MISMATCH')
                self.db.commit()
                return existing['execution_id'],False
            approval=self.db.execute('SELECT * FROM recovery_approvals WHERE approval_id=?',(approval_id,)).fetchone()
            if approval is None: raise KeyError(approval_id)
            if approval['state'] != 'APPROVED':
                raise ValueError('APPROVAL_CONSUMED_WITHOUT_EXECUTION')
            intent=self.db.execute('SELECT * FROM write_intents WHERE intent_id=?',(approval['intent_id'],)).fetchone()
            if intent is None: raise ValueError('INTENT_MISSING')
            op=self.db.execute('SELECT * FROM operations WHERE id=?',(intent['operation_id'],)).fetchone()
            if not op or op['state']!='RUNNING' or op['owner']!=owner or op['epoch']!=epoch or (op['lease_until'] or 0)<=int(time.time()):
                raise ValueError('STALE_OR_MISSING_LEASE')
            evidence=self.classify_recovery(approval['intent_id'])
            if (evidence['classification']!=approval['classification'] or
                self.evidence_digest(evidence)!=approval['evidence_hash'] or
                approval['decision'] not in SAFE_DECISIONS.get(evidence['classification'],set())):
                raise ValueError('EVIDENCE_CHANGED')
            if self.db.execute("UPDATE recovery_approvals SET state='CONSUMED' WHERE approval_id=? AND state='APPROVED'",(approval_id,)).rowcount!=1:
                raise ValueError('APPROVAL_RACE')
            now=time.time_ns()
            self.db.execute('INSERT INTO recovery_transitions VALUES(?,?,?,?,?,?,?)',
                            (approval_id,approval['intent_id'],approval['decision'],owner,epoch,approval['evidence_hash'],now))
            execution_id=str(uuid.uuid4())
            self.db.execute('INSERT INTO recovery_executions VALUES(?,?,?,?,?,?,?,?,?,?)',
                            (execution_id,approval_id,approval['intent_id'],approval['decision'],owner,epoch,'PREPARED',now,now,None))
            self._audit('RECOVERY_APPROVAL_CONSUMED',approval['intent_id'],
                        {'approval_id':approval_id,'owner':owner,'epoch':epoch,'evidence_hash':approval['evidence_hash']})
            self._audit('RECOVERY_EXECUTION_PREPARED',approval['intent_id'],
                        {'execution_id':execution_id,'approval_id':approval_id})
            if fault_point=='BEFORE_COMMIT': raise RuntimeError('INJECTED_CRASH_BEFORE_COMMIT')
            self.db.commit()
            return execution_id,True
        except BaseException:
            self.db.rollback()
            raise

    def inspect_execution(self, execution_id):
        row=self.db.execute('SELECT * FROM recovery_executions WHERE execution_id=?',(execution_id,)).fetchone()
        if not row: raise KeyError(execution_id)
        evidence=self.classify_recovery(row['intent_id'])
        return {'execution_id':execution_id,'state':row['state'],'decision':row['decision'],
                'classification':evidence['classification'],'evidence_sha256':self.evidence_digest(evidence),
                'automatic_replay_allowed':False}

    def record_observation(self, execution_id, owner, epoch, observation):
        if observation not in ('REQUIRES_RECONCILIATION','BLOCKED','OBSERVED_COMPLETE'):
            raise ValueError('INVALID_OBSERVATION')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT * FROM recovery_executions WHERE execution_id=?',(execution_id,)).fetchone()
            if not row: raise KeyError(execution_id)
            if row['owner']!=owner or row['epoch']!=epoch: raise ValueError('STALE_EXECUTOR')
            op=self.db.execute('SELECT o.* FROM operations o JOIN write_intents i ON i.operation_id=o.id WHERE i.intent_id=?',(row['intent_id'],)).fetchone()
            if not op or op['state']!='RUNNING' or op['owner']!=owner or op['epoch']!=epoch or (op['lease_until'] or 0)<=int(time.time()):
                raise ValueError('STALE_OR_MISSING_LEASE')
            if row['state']!='PREPARED': raise ValueError('ALREADY_OBSERVED')
            self.db.execute('UPDATE recovery_executions SET state=?,observation=?,updated_ns=? WHERE execution_id=?',
                            ('RECONCILIATION_REQUIRED',observation,time.time_ns(),execution_id))
            self._audit('RECOVERY_EXECUTION_OBSERVED',row['intent_id'],{'execution_id':execution_id,'observation':observation})
            self.db.commit()
        except BaseException:
            self.db.rollback(); raise
