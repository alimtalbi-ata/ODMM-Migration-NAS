import json, subprocess, sys
from pathlib import Path
from odmm_editions_v2282 import EDITIONS

def run(*args):
    return subprocess.run([sys.executable,"odmm_linux_compact_v2282.py",*args],capture_output=True,text=True,cwd=Path(__file__).parent)

def test_editions():
    assert {x["version"] for x in EDITIONS.values()}=={"228.2","7.9.2"}

def test_bad_json(tmp_path):
    p=tmp_path/"bad.json"; p.write_text("{oops")
    r=run("--report",str(p)); assert r.returncode==2 and "Cannot read valid" in r.stderr

def test_missing_report():
    r=run("--report","/nonexistent-odmm-v2282.json"); assert r.returncode==2 and "Cannot read valid" in r.stderr

def test_bad_shape(tmp_path):
    p=tmp_path/"jobs.json"; p.write_text(json.dumps([None]))
    r=run("--report",str(p)); assert r.returncode==2 and "Invalid job registry" in r.stderr

def test_valid_json(tmp_path):
    p=tmp_path/"jobs.json"; p.write_text(json.dumps([{"id":"j1","status":"FAILED"}]))
    r=run("--report",str(p),"--attention","--json"); assert r.returncode==0
    result=json.loads(r.stdout); assert result["summary"]["failed"]==1

def test_windows_compiles():
    import py_compile
    py_compile.compile("odmm_windows_compact_v2282.py",doraise=True)
