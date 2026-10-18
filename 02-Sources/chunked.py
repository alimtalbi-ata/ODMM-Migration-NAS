"""ODMM V176.5: conservative local chunk staging with durable chunk evidence.
Single trusted local filesystem only; no NAS/SMB durability assertion.
"""
import hashlib, os, time, json
from pathlib import Path
from staging import StagedRegistry

class ChunkedRegistry(StagedRegistry):
    def __init__(self,path):
        super().__init__(path)
        self.db.execute('''CREATE TABLE IF NOT EXISTS chunk_sessions(
          intent_id TEXT PRIMARY KEY REFERENCES write_intents(intent_id),
          stage_path TEXT NOT NULL, total_bytes INTEGER NOT NULL,
          chunk_bytes INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'STAGING')''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS chunk_evidence(
          intent_id TEXT NOT NULL REFERENCES chunk_sessions(intent_id),
          offset_bytes INTEGER NOT NULL, length_bytes INTEGER NOT NULL,
          sha256 TEXT NOT NULL, PRIMARY KEY(intent_id,offset_bytes))''')

    def _authorized(self,r,owner,epoch):
        op=self.db.execute('SELECT * FROM operations WHERE id=?',(r['operation_id'],)).fetchone()
        return bool(r['owner']==owner and r['epoch']==epoch and r['state']=='PREPARED' and op and
          op['state']=='RUNNING' and op['owner']==owner and op['epoch']==epoch and
          (op['lease_until'] or 0)>int(time.time()))

    def begin_chunks(self,iid,owner,epoch,chunk_bytes=1024*1024):
        if not isinstance(chunk_bytes,int) or isinstance(chunk_bytes,bool) or chunk_bytes<=0: raise ValueError('INVALID_CHUNK_SIZE')
        r=self.db.execute('SELECT * FROM write_intents WHERE intent_id=?',(iid,)).fetchone()
        if not r: raise KeyError(iid)
        if not self._authorized(r,owner,epoch): return False
        if r['offset_bytes']!=0: raise ValueError('FULL_FILE_ONLY')
        target=Path(r['target_path']); parent=target.parent
        if not parent.is_dir() or parent.is_symlink() or target.is_symlink(): raise ValueError('UNSAFE_PATH')
        stage=parent/('.odmm-'+iid+'.chunks')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            old=self.db.execute('SELECT * FROM chunk_sessions WHERE intent_id=?',(iid,)).fetchone()
            if old:
                if old['stage_path']!=str(stage) or old['total_bytes']!=r['length_bytes'] or old['chunk_bytes']!=chunk_bytes: raise ValueError('SESSION_CONFLICT')
                self.db.commit(); return True
            flags=os.O_RDWR|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
            fd=os.open(stage,flags,0o600)
            try: os.fsync(fd)
            finally: os.close(fd)
            self.db.execute('INSERT INTO chunk_sessions VALUES(?,?,?,?,?)',(iid,str(stage),r['length_bytes'],chunk_bytes,'STAGING'))
            self._audit('CHUNK_SESSION_CREATED',iid,{'total_bytes':r['length_bytes'],'chunk_bytes':chunk_bytes})
            self.db.commit(); return True
        except BaseException:
            self.db.rollback(); raise

    def write_chunk(self,iid,owner,epoch,offset,data):
        if not isinstance(data,bytes) or not data: raise ValueError('NONEMPTY_BYTES_REQUIRED')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            r=self.db.execute('SELECT * FROM write_intents WHERE intent_id=?',(iid,)).fetchone()
            s=self.db.execute('SELECT * FROM chunk_sessions WHERE intent_id=?',(iid,)).fetchone()
            if not r or not s: raise KeyError(iid)
            if not self._authorized(r,owner,epoch): self.db.rollback(); return False
            if s['state']!='STAGING' or offset<0 or offset%s['chunk_bytes'] or offset+len(data)>s['total_bytes'] or len(data)>s['chunk_bytes'] or (offset+len(data)<s['total_bytes'] and len(data)!=s['chunk_bytes']): raise ValueError('INVALID_CHUNK_RANGE')
            digest=hashlib.sha256(data).hexdigest()
            prior=self.db.execute('SELECT * FROM chunk_evidence WHERE intent_id=? AND offset_bytes=?',(iid,offset)).fetchone()
            if prior and (prior['sha256']!=digest or prior['length_bytes']!=len(data)): raise ValueError('CHUNK_CONFLICT')
            stage=Path(s['stage_path'])
            if stage.is_symlink(): raise ValueError('UNSAFE_STAGE')
            fd=os.open(stage,os.O_RDWR|getattr(os,'O_NOFOLLOW',0))
            try:
                os.lseek(fd,offset,os.SEEK_SET)
                view=memoryview(data)
                while view: view=view[os.write(fd,view):]
                os.fsync(fd)
            finally: os.close(fd)
            self.db.execute('INSERT OR REPLACE INTO chunk_evidence VALUES(?,?,?,?)',(iid,offset,len(data),digest))
            self._audit('CHUNK_DURABLE',iid,{'offset':offset,'length':len(data),'sha256':digest})
            self.db.commit(); return True
        except BaseException:
            self.db.rollback(); raise

    def inspect_chunks(self,iid):
        s=self.db.execute('SELECT * FROM chunk_sessions WHERE intent_id=?',(iid,)).fetchone()
        if not s: raise KeyError(iid)
        rows=self.db.execute('SELECT * FROM chunk_evidence WHERE intent_id=? ORDER BY offset_bytes',(iid,)).fetchall()
        good=[]; bad=[]; stage=Path(s['stage_path'])
        if not stage.is_file() or stage.is_symlink(): return {'verified_offsets':[],'invalid_offsets':[x['offset_bytes'] for x in rows],'complete':False}
        with stage.open('rb') as f:
            for x in rows:
                f.seek(x['offset_bytes']); data=f.read(x['length_bytes'])
                (good if len(data)==x['length_bytes'] and hashlib.sha256(data).hexdigest()==x['sha256'] else bad).append(x['offset_bytes'])
        expected=list(range(0,s['total_bytes'],s['chunk_bytes']))
        return {'verified_offsets':good,'invalid_offsets':bad,'missing_offsets':sorted(set(expected)-set(good)),'complete':not bad and good==expected}

    def publish_chunks(self,iid,owner,epoch):
        """Never replay on restart; only publish with live lease and verified staged bytes."""
        self.db.execute('BEGIN IMMEDIATE')
        try:
            r=self.db.execute('SELECT * FROM write_intents WHERE intent_id=?',(iid,)).fetchone()
            s=self.db.execute('SELECT * FROM chunk_sessions WHERE intent_id=?',(iid,)).fetchone()
            if not r or not s: raise KeyError(iid)
            if not self._authorized(r,owner,epoch): self.db.rollback(); return False
            if not self.inspect_chunks(iid)['complete']: raise ValueError('INCOMPLETE_OR_CORRUPT_CHUNKS')
            stage=Path(s['stage_path']); target=Path(r['target_path'])
            if target.exists() or target.is_symlink(): raise FileExistsError(target)
            h=hashlib.sha256()
            with stage.open('rb') as f:
                for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
            if stage.stat().st_size!=s['total_bytes'] or h.hexdigest()!=r['expected_sha256']: raise ValueError('WHOLE_FILE_MISMATCH')
            # Still subject to external path races: only isolated trusted directories are supported.
            os.replace(stage,target)
            dirfd=os.open(target.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
            try: os.fsync(dirfd)
            finally: os.close(dirfd)
            self.db.execute("UPDATE chunk_sessions SET state='PUBLISHED' WHERE intent_id=?",(iid,))
            self.db.execute("UPDATE write_intents SET state='VERIFIED' WHERE intent_id=?",(iid,))
            self._audit('CHUNKS_PUBLISHED',iid,{'sha256':h.hexdigest(),'bytes':s['total_bytes']})
            self.db.commit(); return True
        except BaseException:
            self.db.rollback(); raise
