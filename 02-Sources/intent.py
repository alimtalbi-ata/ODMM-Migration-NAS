"""V176.3 write-ahead intent and conservative local-file reconciliation.
No NAS writes are performed by this module.
"""
import hashlib, json, time, uuid
from pathlib import Path
from advanced import AdvancedRegistry

class IntentRegistry(AdvancedRegistry):
    def __init__(self, path):
        super().__init__(path)
        self.db.execute('''CREATE TABLE IF NOT EXISTS write_intents (
          intent_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL REFERENCES operations(id),
          epoch INTEGER NOT NULL, owner TEXT NOT NULL, target_path TEXT NOT NULL,
          offset_bytes INTEGER NOT NULL CHECK(offset_bytes>=0), length_bytes INTEGER NOT NULL CHECK(length_bytes>0),
          expected_sha256 TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'PREPARED',
          created_at INTEGER NOT NULL, UNIQUE(operation_id,epoch,offset_bytes,length_bytes))''')

    def prepare_write(self, oid, owner, epoch, target_path, offset, length, sha256):
        if not isinstance(offset,int) or isinstance(offset,bool) or offset<0 or not isinstance(length,int) or isinstance(length,bool) or length<=0:
            raise ValueError('INVALID_RANGE')
        if len(sha256)!=64 or any(c not in '0123456789abcdef' for c in sha256):
            raise ValueError('INVALID_SHA256')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            now=int(time.time())
            op=self.db.execute('SELECT * FROM operations WHERE id=?',(oid,)).fetchone()
            if not op or op['state']!='RUNNING' or op['owner']!=owner or op['epoch']!=epoch or (op['lease_until'] or 0)<=now:
                self.db.rollback(); return None
            prior=self.db.execute('SELECT * FROM write_intents WHERE operation_id=? AND epoch=? AND offset_bytes=? AND length_bytes=?',(oid,epoch,offset,length)).fetchone()
            if prior:
                if prior['target_path']!=str(target_path) or prior['expected_sha256']!=sha256: raise ValueError('INTENT_CONFLICT')
                self.db.commit(); return prior['intent_id']
            iid=str(uuid.uuid4())
            self.db.execute('INSERT INTO write_intents VALUES(?,?,?,?,?,?,?,?,?,?)',(iid,oid,epoch,owner,str(target_path),offset,length,sha256,'PREPARED',now))
            self._audit('WRITE_INTENT_PREPARED',iid,{'operation_id':oid,'epoch':epoch,'offset':offset,'length':length,'sha256':sha256})
            self.db.commit(); return iid
        except BaseException:
            self.db.rollback(); raise

    def inspect_intent(self, intent_id):
        r=self.db.execute('SELECT * FROM write_intents WHERE intent_id=?',(intent_id,)).fetchone()
        if not r: raise KeyError(intent_id)
        p=Path(r['target_path'])
        result={'intent_id':intent_id,'state':r['state'],'expected_sha256':r['expected_sha256'],'verified':False,'reason':'MISSING_DESTINATION'}
        if not p.is_file(): return result
        with p.open('rb') as f:
            f.seek(r['offset_bytes']); data=f.read(r['length_bytes'])
        digest=hashlib.sha256(data).hexdigest()
        result.update(actual_sha256=digest,bytes_read=len(data),verified=len(data)==r['length_bytes'] and digest==r['expected_sha256'],reason='MATCH' if len(data)==r['length_bytes'] and digest==r['expected_sha256'] else 'MISMATCH')
        return result

    def acknowledge_write(self, intent_id, owner, epoch):
        """Commit evidence only while original worker still holds a valid lease."""
        self.db.execute('BEGIN IMMEDIATE')
        try:
            r=self.db.execute('SELECT * FROM write_intents WHERE intent_id=?',(intent_id,)).fetchone()
            now=int(time.time())
            if not r or r['owner']!=owner or r['epoch']!=epoch or r['state']!='PREPARED':
                self.db.rollback(); return False
            op=self.db.execute('SELECT * FROM operations WHERE id=?',(r['operation_id'],)).fetchone()
            if not op or op['state']!='RUNNING' or op['owner']!=owner or op['epoch']!=epoch or (op['lease_until'] or 0)<=now:
                self.db.rollback(); return False
            proof=self.inspect_intent(intent_id)
            if not proof['verified']:
                self.db.rollback(); return False
            self.db.execute("UPDATE write_intents SET state='VERIFIED' WHERE intent_id=?",(intent_id,))
            self._audit('WRITE_INTENT_VERIFIED',intent_id,{'sha256':proof['actual_sha256'],'length':r['length_bytes']})
            self.db.commit(); return True
        except BaseException:
            self.db.rollback(); raise
