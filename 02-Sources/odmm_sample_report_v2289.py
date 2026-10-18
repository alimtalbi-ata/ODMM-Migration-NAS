"""Clearly synthetic training fixture. Not evidence of real NAS migration."""
import json
from pathlib import Path

def sample_rows():
    return [{"id":"DEMO-001","status":"RUNNING"},{"id":"DEMO-002","status":"FAILED"},{"id":"DEMO-003","status":"PENDING"},{"id":"DEMO-004","status":"COMPLETED"},{"id":"DEMO-005","status":"UNKNOWN"}]

def write_sample(path):
    path = Path(path)
    payload={"example_only":True,"source":"SYNTHETIC - NOT A REAL NAS MIGRATION", "items":sample_rows()}
    with path.open("x",encoding="utf-8") as f:
        json.dump(payload,f,ensure_ascii=False,indent=2)
        f.write("\n")
    return path
