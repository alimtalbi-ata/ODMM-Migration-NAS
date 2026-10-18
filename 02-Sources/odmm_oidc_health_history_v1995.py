"""Read-only OIDC dashboard history ingestion; Author: Abdelhalim Talbi."""
import argparse
import datetime
import json
import sqlite3
from contextlib import closing
from pathlib import Path

VALID={"UNKNOWN","RECOVERING","AVAILABLE","DEGRADED","UNAVAILABLE"}

def ingest(db_path, report_path):
    payload=json.loads(Path(report_path).read_text(encoding="utf-8"))
    checks=payload.get("checks")
    if not isinstance(checks,list) or not checks or len(checks)>1000:
        raise ValueError("INVALID_CHECKS")
    rows=[]
    for check in checks:
        if not isinstance(check,dict) or check.get("state") not in VALID or type(check.get("discovery_jwks_ok")) is not bool:
            raise ValueError("INVALID_OBSERVATION")
        latency=check.get("latency_ms")
        if not isinstance(latency,(float,int)) or isinstance(latency,bool) or not 0<=latency<=3600000:
            raise ValueError("INVALID_LATENCY")
        rows.append((check["state"],int(check["discovery_jwks_ok"]),float(latency)))
    path=Path(db_path);path.parent.mkdir(parents=True,exist_ok=True)
    with closing(sqlite3.connect(str(path),timeout=5)) as db, db:
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("CREATE TABLE IF NOT EXISTS oidc_observations (id INTEGER PRIMARY KEY, observed_utc TEXT NOT NULL, state TEXT NOT NULL, discovery_jwks_ok INTEGER NOT NULL, latency_ms REAL NOT NULL)")
        stamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
        db.executemany("INSERT INTO oidc_observations(observed_utc,state,discovery_jwks_ok,latency_ms) VALUES (?,?,?,?)",[(stamp,*r) for r in rows])
    return len(rows)

def snapshot(db_path,limit=100):
    if not 1<=limit<=1000:raise ValueError("INVALID_LIMIT")
    with closing(sqlite3.connect(str(db_path),timeout=5)) as db:
        rows=db.execute("SELECT observed_utc,state,discovery_jwks_ok,latency_ms FROM oidc_observations ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return {"author":"Abdelhalim Talbi","scope":"OIDC discovery/JWKS only","production_qualified":False,
            "migration_engine_status":"NOT_MEASURED", "count":len(rows),
            "observations":[dict(zip(("observed_utc","state","discovery_jwks_ok","latency_ms"),(r[0],r[1],bool(r[2]),r[3]))) for r in rows]}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--db",required=True);p.add_argument("--ingest",required=True);p.add_argument("--output",required=True)
    a=p.parse_args();ingest(a.db,a.ingest)
    Path(a.output).write_text(json.dumps(snapshot(a.db),indent=2)+"\n",encoding="utf-8")
    print(a.output)
if __name__=="__main__":main()
