"""Append-only SQLite evidence audit log; no authority to execute cutover."""
import hashlib
import json
import sqlite3
from pathlib import Path
from odmm_evidence_audit_v22813 import audit

SCHEMA = """CREATE TABLE IF NOT EXISTS audit_events (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 job_id TEXT NOT NULL,
 payload_sha256 TEXT NOT NULL,
 result_json TEXT NOT NULL,
 previous_hash TEXT NOT NULL,
 event_hash TEXT NOT NULL UNIQUE,
 UNIQUE(job_id, payload_sha256)
)"""

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)

def record(db_path, job_id, evidence):
    if not isinstance(job_id, str) or not job_id.strip() or len(job_id) > 128:
        raise ValueError("invalid job id")
    payload = canonical(evidence)
    if len(payload.encode("utf-8")) > 1024 * 1024:
        raise ValueError("evidence too large")
    result = audit(evidence, job_id)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    db = sqlite3.connect(str(db_path), timeout=15)
    try:
        db.execute("PRAGMA busy_timeout=15000")
        db.execute("PRAGMA synchronous=FULL")
        db.execute(SCHEMA)
        db.execute("BEGIN IMMEDIATE")
        prior = db.execute("SELECT sequence, result_json FROM audit_events WHERE job_id=? AND payload_sha256=?", (job_id,digest)).fetchone()
        if prior:
            db.commit()
            return {"sequence": prior[0], "duplicate": True, "result": json.loads(prior[1])}
        prev = db.execute("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").fetchone()
        prev_hash = prev[0] if prev else "0" * 64
        result_json = canonical(result)
        event_hash = hashlib.sha256(canonical([job_id,digest,result_json,prev_hash]).encode("utf-8")).hexdigest()
        cur = db.execute("INSERT INTO audit_events(job_id,payload_sha256,result_json,previous_hash,event_hash) VALUES(?,?,?,?,?)",(job_id,digest,result_json,prev_hash,event_hash))
        db.commit()
        return {"sequence":cur.lastrowid,"duplicate":False,"result":result}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def verify(db_path):
    with sqlite3.connect(str(db_path)) as db:
        rows = db.execute("SELECT sequence,job_id,payload_sha256,result_json,previous_hash,event_hash FROM audit_events ORDER BY sequence").fetchall()
    prev = "0" * 64
    for seq, job, digest, result, previous, stored in rows:
        expected = hashlib.sha256(canonical([job,digest,result,prev]).encode("utf-8")).hexdigest()
        if previous != prev or stored != expected:
            return {"valid":False,"first_invalid_sequence":seq,"events":len(rows)}
        prev=stored
    return {"valid":True,"events":len(rows),"head_hash":prev}
