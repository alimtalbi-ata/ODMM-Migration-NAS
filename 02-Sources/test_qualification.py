import unittest, tempfile, os, sqlite3, subprocess, sys, json
from pathlib import Path
from qualification import inspect_legacy, metadata_inventory
from executor import RecoveryExecutorRegistry

class QualificationTests(unittest.TestCase):
 def test_legacy_orphan_read_only(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'legacy.sqlite'; c=sqlite3.connect(p)
   c.executescript('CREATE TABLE recovery_approvals(approval_id TEXT,intent_id TEXT,state TEXT); CREATE TABLE recovery_executions(approval_id TEXT,execution_id TEXT); INSERT INTO recovery_approvals VALUES("a","i","CONSUMED");'); c.commit(); c.close()
   self.assertEqual(inspect_legacy(p)['orphans'][0]['approval_id'],'a')
   self.assertEqual(inspect_legacy(p)['status'],'RECONCILIATION_REQUIRED')
 def test_metadata_symlink_not_followed(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'original'; p.write_text('hello'); link=Path(d)/'link'; link.symlink_to(p)
   self.assertEqual(metadata_inventory(link)['kind'],'symlink')
   self.assertFalse(metadata_inventory(p)['acl_verified'])
 def test_hard_kill_uncommitted_transaction(self):
  with tempfile.TemporaryDirectory() as d:
   db=Path(d)/'reg.sqlite'; r=RecoveryExecutorRegistry(db); r.db.close()
   code='''import sqlite3,sys,os\nc=sqlite3.connect(sys.argv[1],isolation_level=None)\nc.execute("BEGIN IMMEDIATE")\nc.execute("INSERT INTO jobs(id,source,target,state,created_at) VALUES (?,?,?,?,?)",("KILLED","a","b","PENDING",1))\nos.write(1,b"READY\\n")\nos.kill(os.getpid(),9)'''
   proc=subprocess.run([sys.executable,'-c',code,str(db)],capture_output=True,timeout=10)
   self.assertIn(b'READY',proc.stdout)
   con=sqlite3.connect(db)
   self.assertEqual(con.execute('SELECT count(*) FROM jobs WHERE id="KILLED"').fetchone()[0],0)
   self.assertEqual(con.execute('PRAGMA integrity_check').fetchone()[0],'ok'); con.close()
 def test_hard_kill_after_commit(self):
  with tempfile.TemporaryDirectory() as d:
   db=Path(d)/'reg.sqlite'; r=RecoveryExecutorRegistry(db); r.db.close()
   code='''import sqlite3,sys,os\nc=sqlite3.connect(sys.argv[1],isolation_level=None)\nc.execute("BEGIN IMMEDIATE")\nc.execute("INSERT INTO jobs(id,source,target,state,created_at) VALUES (?,?,?,?,?)",("COMMITTED","a","b","PENDING",1))\nc.commit()\nos.write(1,b"READY\\n")\nos.kill(os.getpid(),9)'''
   proc=subprocess.run([sys.executable,'-c',code,str(db)],capture_output=True,timeout=10)
   self.assertIn(b'READY',proc.stdout)
   con=sqlite3.connect(db); self.assertEqual(con.execute('SELECT count(*) FROM jobs WHERE id="COMMITTED"').fetchone()[0],1); con.close()

if __name__=='__main__': unittest.main()
