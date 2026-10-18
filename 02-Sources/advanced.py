"""ODMM V176.2: conservative recovery evidence and concurrent claims."""
import hashlib, json, os, time
from pathlib import Path
from recovery import RecoveryRegistry

class AdvancedRegistry(RecoveryRegistry):
    def claim_next(self, owner, ttl=60):
        if not owner or ttl <= 0: raise ValueError('INVALID_CLAIM')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute("SELECT id,epoch FROM operations WHERE state='PENDING' ORDER BY updated_at,id LIMIT 1").fetchone()
            if row is None:
                self.db.commit(); return None
            oid=row['id']; epoch=row['epoch']+1; now=int(time.time())
            self.db.execute("UPDATE operations SET state='RUNNING',owner=?,epoch=?,lease_until=?,updated_at=? WHERE id=?",(owner,epoch,now+ttl,now,oid))
            self._audit('CLAIM',oid,{'owner':owner,'epoch':epoch,'via':'claim_next'})
            self.db.commit(); return oid,epoch
        except BaseException:
            self.db.rollback(); raise

    def recovery_plan(self, oid, destination_file=None):
        op=self.db.execute('SELECT state,epoch FROM operations WHERE id=?',(oid,)).fetchone()
        if op is None: raise KeyError(oid)
        cp=self.db.execute('SELECT offset_bytes,evidence_json FROM checkpoints WHERE operation_id=?',(oid,)).fetchone()
        plan={'operation_id':oid,'state':op['state'],'epoch':op['epoch'],'checkpoint_offset':cp['offset_bytes'] if cp else None,
              'decision':'MANUAL_RECONCILIATION_REQUIRED','safe_to_replay':False}
        if destination_file is not None:
            p=Path(destination_file)
            if p.is_file():
                h=hashlib.sha256()
                with p.open('rb') as f:
                    for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
                st=p.stat()
                plan['destination_evidence']={'size_bytes':st.st_size,'sha256':h.hexdigest(),'mtime_ns':st.st_mtime_ns}
            else: plan['destination_evidence']={'exists':False}
        return plan

    def reconcile_verified(self, oid, evidence, decision):
        if not isinstance(evidence,dict) or evidence.get('operator_approved') is not True or not evidence.get('destination_checked'):
            raise ValueError('OPERATOR_APPROVAL_AND_DESTINATION_CHECK_REQUIRED')
        return self.reconcile(oid,evidence,decision)

    def export_snapshot(self, path):
        """Consistent audit export using an independent read transaction."""
        import sqlite3
        from registry import verify
        conn=sqlite3.connect(self.path,timeout=30,isolation_level=None)
        conn.row_factory=sqlite3.Row
        try:
            conn.execute('BEGIN')
            rows=[dict(r) for r in conn.execute('SELECT * FROM audit ORDER BY seq')]
            conn.commit()
        finally: conn.close()
        p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
        tmp=p.with_name(p.name+'.tmp')
        with tmp.open('w',encoding='utf-8') as f:
            for r in rows: f.write(json.dumps(r,sort_keys=True)+'\n')
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp,p)
        manifest={'format':'ODMM-AUDIT-1','events':len(rows),'head_hash':rows[-1]['hash'] if rows else '0'*64,
                  'file_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'signature_status':'UNSIGNED'}
        mp=Path(str(p)+'.manifest.json'); mt=Path(str(mp)+'.tmp')
        with mt.open('w',encoding='utf-8') as f:
            json.dump(manifest,f,sort_keys=True,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(mt,mp)
        return manifest
