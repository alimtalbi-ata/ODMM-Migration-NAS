"""V200.1 tests. Author: Abdelhalim Talbi."""
import json,multiprocessing,sqlite3,tempfile,unittest
from pathlib import Path
from odmm_sqlite_inventory_v2001 import inventory
from odmm_oidc_health_history_v1995 import ingest,snapshot

def writer(db,report):
    ingest(db,report)

class InventoryV2001(unittest.TestCase):
    def test_global_inventory(self):
        result=inventory(Path(__file__).parent)
        self.assertGreater(result["count"],0)
        self.assertFalse(result["native_engine_modified"])
        self.assertFalse(result["parse_errors"])
    def test_alias_detection(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"sample.py").write_text("from sqlite3 import connect as sqlite_connect\nsqlite_connect('x')\n")
            self.assertEqual(inventory(d)["count"],1)
    def test_parallel_process_writers(self):
        with tempfile.TemporaryDirectory() as d:
            db=Path(d,"events.sqlite"); report=Path(d,"input.json")
            report.write_text(json.dumps({"checks":[{"state":"AVAILABLE","discovery_jwks_ok":True,"latency_ms":1}]}))
            procs=[multiprocessing.Process(target=writer,args=(db,report)) for _ in range(4)]
            for p in procs:p.start()
            for p in procs:p.join(15);self.assertEqual(p.exitcode,0)
            self.assertEqual(snapshot(db,limit=100)["count"],4)
            with sqlite3.connect(db) as conn:self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0],"ok")
    def test_crash_rollback(self):
        import subprocess,sys
        with tempfile.TemporaryDirectory() as d:
            db=Path(d,"events.sqlite");report=Path(d,"input.json")
            report.write_text(json.dumps({"checks":[{"state":"AVAILABLE","discovery_jwks_ok":True,"latency_ms":1}]}))
            ingest(db,report)
            code = "import sqlite3,os,sys;d=sqlite3.connect(sys.argv[1]);d.execute('BEGIN IMMEDIATE');d.execute('INSERT INTO oidc_observations(observed_utc,state,discovery_jwks_ok,latency_ms) VALUES (\"x\",\"DEGRADED\",0,1)');os._exit(17)"
            done=subprocess.run([sys.executable,"-c",code,str(db)])
            self.assertEqual(done.returncode,17)
            self.assertEqual(snapshot(db)["count"],1)
if __name__=="__main__":unittest.main()
