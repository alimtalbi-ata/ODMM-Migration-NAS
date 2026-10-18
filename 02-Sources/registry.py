import sqlite3, json, hashlib, time, uuid
from pathlib import Path

SCHEMA='''
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, source TEXT NOT NULL, target TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'PENDING', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id), idem_key TEXT NOT NULL UNIQUE, payload_hash TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'PENDING', owner TEXT, epoch INTEGER NOT NULL DEFAULT 0, lease_until INTEGER, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, detail TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
'''
class Registry:
 def __enter__(self): return self
 def __exit__(self,exc_type,exc,tb): self.close()
 def close(self): self.db.close()
 def __init__(self,path):
  self.path=str(path); Path(path).parent.mkdir(parents=True,exist_ok=True)
  self.db=sqlite3.connect(self.path,timeout=30,isolation_level=None)
  self.db.row_factory=sqlite3.Row
  self.db.executescript(SCHEMA)
  self.db.execute('PRAGMA busy_timeout=30000')
 def _audit(self,kind,subject,detail):
  prev=self.db.execute('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
  prev=prev['hash'] if prev else '0'*64
  ts=int(time.time_ns()); raw=json.dumps(dict(ts=ts,kind=kind,subject=subject,detail=detail,prev_hash=prev),sort_keys=True,separators=(',',':'))
  digest=hashlib.sha256(raw.encode()).hexdigest()
  self.db.execute('INSERT INTO audit(ts,kind,subject,detail,prev_hash,hash) VALUES(?,?,?,?,?,?)',(ts,kind,subject,json.dumps(detail,sort_keys=True),prev,digest))
 def create_job(self,source,target):
  jid=str(uuid.uuid4()); self.db.execute('BEGIN IMMEDIATE')
  try:
   self.db.execute('INSERT INTO jobs(id,source,target,created_at) VALUES(?,?,?,?)',(jid,source,target,int(time.time())))
   self._audit('JOB_CREATED',jid,{'source':source,'target':target}); self.db.commit(); return jid
  except: self.db.rollback(); raise
 def enqueue(self,job_id,idem_key,payload):
  digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  self.db.execute('BEGIN IMMEDIATE')
  try:
   row=self.db.execute('SELECT id,payload_hash FROM operations WHERE idem_key=?',(idem_key,)).fetchone()
   if row:
    if row['payload_hash']!=digest: raise ValueError('IDEMPOTENCY_CONFLICT')
    self.db.commit(); return row['id'],False
   oid=str(uuid.uuid4()); self.db.execute('INSERT INTO operations(id,job_id,idem_key,payload_hash,updated_at) VALUES(?,?,?,?,?)',(oid,job_id,idem_key,digest,int(time.time())))
   self._audit('ENQUEUED',oid,{'key':idem_key,'payload_hash':digest}); self.db.commit(); return oid,True
  except: self.db.rollback(); raise
 def claim(self,oid,owner,ttl=60):
  now=int(time.time()); self.db.execute('BEGIN IMMEDIATE')
  try:
   row=self.db.execute('SELECT state,lease_until,epoch FROM operations WHERE id=?',(oid,)).fetchone()
   if not row or row['state'] in ('DONE','FAILED') or (row['state']=='RUNNING' and (row['lease_until'] or 0)>now):
    self.db.commit(); return None
   epoch=row['epoch']+1
   self.db.execute("UPDATE operations SET state='RUNNING',owner=?,epoch=?,lease_until=?,updated_at=? WHERE id=?",(owner,epoch,now+ttl,now,oid))
   self._audit('CLAIM',oid,{'owner':owner,'epoch':epoch}); self.db.commit(); return epoch
  except: self.db.rollback(); raise
 def complete(self,oid,owner,epoch):
  self.db.execute('BEGIN IMMEDIATE')
  try:
   now=int(time.time())
   cur=self.db.execute("UPDATE operations SET state='DONE',lease_until=NULL,updated_at=? WHERE id=? AND owner=? AND epoch=? AND state='RUNNING' AND lease_until>=?",(now,oid,owner,epoch,now))
   if cur.rowcount!=1: self.db.rollback(); return False
   self._audit('DONE',oid,{'owner':owner,'epoch':epoch}); self.db.commit(); return True
  except: self.db.rollback(); raise
 def export(self,path):
  rows=[dict(r) for r in self.db.execute('SELECT * FROM audit ORDER BY seq')]
  out=Path(path); out.parent.mkdir(parents=True,exist_ok=True)
  with out.open('w') as f:
   for r in rows: f.write(json.dumps(r,sort_keys=True)+'\n')
  manifest={'format':'ODMM-AUDIT-1','events':len(rows),'head_hash':rows[-1]['hash'] if rows else '0'*64,'file_sha256':hashlib.sha256(out.read_bytes()).hexdigest()}
  Path(str(out)+'.manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
  return manifest

def verify(path):
 p=Path(path); m=json.loads(Path(str(p)+'.manifest.json').read_text())
 if hashlib.sha256(p.read_bytes()).hexdigest()!=m['file_sha256']: return False
 prev='0'*64; n=0
 for line in p.read_text().splitlines():
  r=json.loads(line); detail=json.loads(r['detail']); raw=json.dumps(dict(ts=r['ts'],kind=r['kind'],subject=r['subject'],detail=detail,prev_hash=prev),sort_keys=True,separators=(',',':'))
  if r['prev_hash']!=prev or hashlib.sha256(raw.encode()).hexdigest()!=r['hash']: return False
  prev=r['hash']; n+=1
 return n==m['events'] and prev==m['head_hash']
