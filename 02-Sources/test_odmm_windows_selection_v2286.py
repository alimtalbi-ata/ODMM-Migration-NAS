"""Regression: UI callback must not shadow pure job lookup."""
import ast
from pathlib import Path
from odmm_job_detail_v2279 import select_job as find_job_by_id

def test_ui_lookup_not_shadowed():
    tree=ast.parse(Path(__file__).with_name("odmm_windows_compact_v2286.py").read_text())
    aliases=[a.asname for n in ast.walk(tree) if isinstance(n,ast.ImportFrom) and n.module=="odmm_job_detail_v2279" for a in n.names if a.name=="select_job"]
    assert aliases==["find_job_by_id"]
    assert "selected = find_job_by_id(rows, values[0])" in Path(__file__).with_name("odmm_windows_compact_v2286.py").read_text()

def test_lookup_real_job():
    assert find_job_by_id([{"id":"job-1","status":"FAILED"}],"job-1")["fields"]["id"]=="job-1"
