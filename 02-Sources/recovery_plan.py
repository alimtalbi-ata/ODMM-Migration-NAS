"""V176.7: audited recovery approvals. Never performs external writes."""
import json, time, uuid, hashlib, os, stat
from pathlib import Path
from reconcile import ReconciliationRegistry

SAFE_DECISIONS = {
    'PUBLISHED_UNACKNOWLEDGED': {'ACK_PUBLISHED'},
    'STAGE_COMPLETE_UNPUBLISHED': {'AUTHORIZE_REPUBLISH'},
    'STAGE_PARTIAL': {'AUTHORIZE_RESUME'},
}

class RecoveryPlanRegistry(ReconciliationRegistry):
    def __init__(self, path):
        super().__init__(path)
        self.db.execute('''CREATE TABLE IF NOT EXISTS recovery_approvals(
          approval_id TEXT PRIMARY KEY, intent_id TEXT NOT NULL,
          classification TEXT NOT NULL, decision TEXT NOT NULL,
          evidence_hash TEXT NOT NULL, actor TEXT NOT NULL,
          created_at INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'APPROVED',
          UNIQUE(intent_id, evidence_hash, decision))''')

    def authorize_recovery(self, intent_id, decision, actor, expected_evidence_hash):
        if not isinstance(actor, str) or not actor.strip(): raise ValueError('ACTOR_REQUIRED')
        classification = self.classify_recovery(intent_id)
        if decision not in SAFE_DECISIONS.get(classification['classification'], set()):
            raise ValueError('RECOVERY_DECISION_NOT_ALLOWED')
        evidence_hash = self.evidence_digest(classification)
        if evidence_hash != expected_evidence_hash: raise ValueError('STALE_EVIDENCE')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT approval_id FROM recovery_approvals WHERE intent_id=? AND evidence_hash=? AND decision=?',
                                (intent_id,evidence_hash,decision)).fetchone()
            if row:
                self.db.commit(); return row['approval_id'],False
            approval_id=str(uuid.uuid4())
            self.db.execute('INSERT INTO recovery_approvals(approval_id,intent_id,classification,decision,evidence_hash,actor,created_at) VALUES(?,?,?,?,?,?,?)',
                            (approval_id,intent_id,classification['classification'],decision,evidence_hash,actor,int(time.time())))
            self._audit('RECOVERY_APPROVED',intent_id,{'approval_id':approval_id,'decision':decision,'classification':classification['classification'],'evidence_hash':evidence_hash,'actor':actor})
            self.db.commit(); return approval_id,True
        except BaseException:
            self.db.rollback(); raise

    @staticmethod
    def evidence_digest(evidence):
        return hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def recovery_preview(self, intent_id):
        classification=self.classify_recovery(intent_id)
        return {'classification':classification,'evidence_sha256':self.evidence_digest(classification),
                'allowed_decisions':sorted(SAFE_DECISIONS.get(classification['classification'],set())),
                'automatic_replay_allowed':False}


def snapshot_posix_metadata(path):
    """Read-only lstat snapshot. ACL/xattrs deliberately not claimed preserved."""
    p=Path(path)
    s=p.lstat()
    if not stat.S_ISREG(s.st_mode) or p.is_symlink(): raise ValueError('REGULAR_FILE_REQUIRED')
    return {'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,
            'size':s.st_size,'mtime_ns':s.st_mtime_ns,'platform':os.name,
            'acl_preserved':False,'xattrs_preserved':False}


class RecoveryExecutionRegistry(RecoveryPlanRegistry):
    """Transactionally consumes approvals. Does not write to destination files."""
    def __init__(self, path):
        super().__init__(path)
        self.db.execute("""CREATE TABLE IF NOT EXISTS recovery_transitions(
          approval_id TEXT PRIMARY KEY REFERENCES recovery_approvals(approval_id),
          intent_id TEXT NOT NULL, decision TEXT NOT NULL,
          owner TEXT NOT NULL, epoch INTEGER NOT NULL,
          evidence_hash TEXT NOT NULL, committed_at_ns INTEGER NOT NULL)""")

    def consume_approval(self, approval_id, owner, epoch):
        if not owner or not isinstance(epoch,int) or isinstance(epoch,bool):
            raise ValueError('INVALID_FENCING_IDENTITY')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            approval=self.db.execute('SELECT * FROM recovery_approvals WHERE approval_id=?',(approval_id,)).fetchone()
            if approval is None: raise KeyError(approval_id)
            if approval['state']!='APPROVED':
                self.db.rollback(); return False
            intent=self.db.execute('SELECT * FROM write_intents WHERE intent_id=?',(approval['intent_id'],)).fetchone()
            if intent is None: raise ValueError('INTENT_MISSING')
            op=self.db.execute('SELECT * FROM operations WHERE id=?',(intent['operation_id'],)).fetchone()
            now=int(time.time())
            if not op or op['state']!='RUNNING' or op['owner']!=owner or op['epoch']!=epoch or (op['lease_until'] or 0)<=now:
                raise ValueError('STALE_OR_MISSING_LEASE')
            # The approval is only valid for the exact evidence it was issued against.
            evidence=self.classify_recovery(approval['intent_id'])
            if (evidence['classification']!=approval['classification'] or
                self.evidence_digest(evidence)!=approval['evidence_hash'] or
                approval['decision'] not in SAFE_DECISIONS.get(evidence['classification'],set())):
                raise ValueError('EVIDENCE_CHANGED')
            self.db.execute('UPDATE recovery_approvals SET state=? WHERE approval_id=? AND state=?',
                            ('CONSUMED',approval_id,'APPROVED'))
            self.db.execute('INSERT INTO recovery_transitions VALUES(?,?,?,?,?,?,?)',
                            (approval_id,approval['intent_id'],approval['decision'],owner,epoch,approval['evidence_hash'],time.time_ns()))
            self._audit('RECOVERY_APPROVAL_CONSUMED',approval['intent_id'],
                        {'approval_id':approval_id,'decision':approval['decision'],'owner':owner,'epoch':epoch,'evidence_hash':approval['evidence_hash']})
            self.db.commit(); return True
        except BaseException:
            self.db.rollback(); raise
