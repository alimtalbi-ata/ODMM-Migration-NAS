"""ODMM V176.1 recovery layer. Never replays an external write automatically."""
import json, time
from registry import Registry

class RecoveryRegistry(Registry):
    def __init__(self, path):
        super().__init__(path)
        self.db.execute('''CREATE TABLE IF NOT EXISTS checkpoints (
            operation_id TEXT PRIMARY KEY REFERENCES operations(id),
            epoch INTEGER NOT NULL, owner TEXT NOT NULL,
            offset_bytes INTEGER NOT NULL CHECK(offset_bytes>=0),
            evidence_json TEXT NOT NULL, updated_at INTEGER NOT NULL)''')

    def claim(self, oid, owner, ttl=60):
        """Only PENDING operations can be claimed; expired RUNNING must reconcile."""
        if ttl <= 0: raise ValueError('INVALID_TTL')
        now=int(time.time())
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT state,epoch FROM operations WHERE id=?',(oid,)).fetchone()
            if not row or row['state'] != 'PENDING':
                self.db.commit(); return None
            epoch=row['epoch']+1
            self.db.execute("UPDATE operations SET state='RUNNING',owner=?,epoch=?,lease_until=?,updated_at=? WHERE id=?",(owner,epoch,now+ttl,now,oid))
            self._audit('CLAIM',oid,{'owner':owner,'epoch':epoch})
            self.db.commit(); return epoch
        except BaseException:
            self.db.rollback(); raise

    def checkpoint(self, oid, owner, epoch, offset_bytes, evidence):
        if not isinstance(offset_bytes, int) or isinstance(offset_bytes, bool) or offset_bytes < 0:
            raise ValueError('INVALID_OFFSET')
        now = int(time.time())
        self.db.execute('BEGIN IMMEDIATE')
        try:
            op = self.db.execute('SELECT * FROM operations WHERE id=?', (oid,)).fetchone()
            if not op or op['state'] != 'RUNNING' or op['owner'] != owner or op['epoch'] != epoch or (op['lease_until'] or 0) <= now:
                self.db.rollback(); return False
            old = self.db.execute('SELECT offset_bytes FROM checkpoints WHERE operation_id=?', (oid,)).fetchone()
            if old and offset_bytes < old['offset_bytes']:
                raise ValueError('CHECKPOINT_REGRESSION')
            self.db.execute('''INSERT INTO checkpoints(operation_id,epoch,owner,offset_bytes,evidence_json,updated_at)
                VALUES(?,?,?,?,?,?) ON CONFLICT(operation_id) DO UPDATE SET
                epoch=excluded.epoch,owner=excluded.owner,offset_bytes=excluded.offset_bytes,
                evidence_json=excluded.evidence_json,updated_at=excluded.updated_at''',
                (oid,epoch,owner,offset_bytes,json.dumps(evidence,sort_keys=True),now))
            self._audit('CHECKPOINT',oid,{'epoch':epoch,'owner':owner,'offset_bytes':offset_bytes,'evidence':evidence})
            self.db.commit(); return True
        except BaseException:
            self.db.rollback(); raise

    def heartbeat(self, oid, owner, epoch, ttl=60):
        if ttl <= 0: raise ValueError('INVALID_TTL')
        now=int(time.time())
        self.db.execute('BEGIN IMMEDIATE')
        try:
            cur=self.db.execute('''UPDATE operations SET lease_until=?,updated_at=? WHERE id=? AND owner=?
                AND epoch=? AND state='RUNNING' AND lease_until>?''',
                (now+ttl,now,oid,owner,epoch,now))
            if cur.rowcount: self._audit('HEARTBEAT',oid,{'owner':owner,'epoch':epoch})
            self.db.commit(); return cur.rowcount==1
        except BaseException:
            self.db.rollback(); raise

    def quarantine_expired(self):
        """Expired leases become NEEDS_RECONCILIATION, never PENDING."""
        now=int(time.time()); ids=[]
        self.db.execute('BEGIN IMMEDIATE')
        try:
            rows=self.db.execute("SELECT id,epoch FROM operations WHERE state='RUNNING' AND lease_until<=? ORDER BY id",(now,)).fetchall()
            for row in rows:
                self.db.execute("UPDATE operations SET state='NEEDS_RECONCILIATION',owner=NULL,lease_until=NULL,epoch=epoch+1,updated_at=? WHERE id=?",(now,row['id']))
                self._audit('QUARANTINED',row['id'],{'previous_epoch':row['epoch'],'reason':'LEASE_EXPIRED'})
                ids.append(row['id'])
            self.db.commit(); return ids
        except BaseException:
            self.db.rollback(); raise

    def reconcile(self, oid, evidence, decision):
        """Explicit operator decision only. RETRY allows claim; DONE confirms external effect."""
        if decision not in ('RETRY','DONE','FAILED'): raise ValueError('INVALID_DECISION')
        if not isinstance(evidence,dict) or not evidence: raise ValueError('EVIDENCE_REQUIRED')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            new_state={'RETRY':'PENDING','DONE':'DONE','FAILED':'FAILED'}[decision]
            cur=self.db.execute("UPDATE operations SET state=?,updated_at=? WHERE id=? AND state='NEEDS_RECONCILIATION'",(new_state,int(time.time()),oid))
            if cur.rowcount!=1: self.db.rollback(); return False
            self._audit('RECONCILED',oid,{'decision':decision,'evidence':evidence})
            self.db.commit(); return True
        except BaseException:
            self.db.rollback(); raise
