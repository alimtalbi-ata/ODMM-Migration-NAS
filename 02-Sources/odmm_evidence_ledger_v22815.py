"""Read-only independent verification and externally anchored audit head (V228.15)."""
import hashlib
import json
import sqlite3
from pathlib import Path
from odmm_evidence_ledger_v22814 import canonical

GENESIS = "0" * 64

def inspect(db_path):
    """Open SQLite strictly read-only; reject missing or malformed stores."""
    path = Path(db_path).resolve(strict=True)
    if not path.is_file():
        raise ValueError("audit store is not a file")
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)
    try:
        db.execute("PRAGMA query_only=ON")
        rows = db.execute("SELECT sequence,job_id,payload_sha256,result_json,previous_hash,event_hash FROM audit_events ORDER BY sequence").fetchall()
    finally:
        db.close()
    prev = GENESIS
    for expected_sequence, (seq, job, digest, result, previous, stored) in enumerate(rows, 1):
        expected_hash = hashlib.sha256(canonical([job,digest,result,prev]).encode("utf-8")).hexdigest()
        if seq != expected_sequence or previous != prev or stored != expected_hash:
            return {"valid":False,"first_invalid_sequence":seq,"events":len(rows)}
        prev = stored
    return {"valid":True,"events":len(rows),"head_hash":prev}

def anchor(db_path):
    status = inspect(db_path)
    if not status["valid"]:
        raise ValueError("invalid audit chain")
    return {"format":"ODMM-AUDIT-ANCHOR-1","events":status["events"],"head_hash":status["head_hash"]}

def check_anchor(db_path, reference):
    status = inspect(db_path)
    valid_reference = (isinstance(reference,dict) and reference.get("format")=="ODMM-AUDIT-ANCHOR-1"
        and type(reference.get("events")) is int and reference["events"] >= 0
        and isinstance(reference.get("head_hash"),str) and len(reference["head_hash"])==64)
    return {"valid":bool(status["valid"] and valid_reference and status["events"]==reference["events"] and status["head_hash"]==reference["head_hash"]),"events":status["events"],"chain_valid":status["valid"]}
