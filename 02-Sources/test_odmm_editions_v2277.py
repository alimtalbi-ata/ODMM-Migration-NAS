import json
import subprocess
import sys
from pathlib import Path
from odmm_editions_v2277 import EDITIONS, FULL_NAME
ROOT=Path(__file__).parent

def test_three_editions():
    assert len(EDITIONS)==3
    assert all(x["name"].startswith(FULL_NAME) for x in EDITIONS.values())
    assert EDITIONS["linux-full"]["migration_engine"]=="native"
    assert all(x["execution"]=="read-only-supervision" for k,x in EDITIONS.items() if "compact" in k)

def test_compact_offline(tmp_path):
    report=tmp_path/"jobs.json"
    report.write_text(json.dumps({"items":[{"id":"job-1","status":"FAILED"},{"id":"job-2","status":"RUNNING"}]}))
    result=subprocess.run([sys.executable,str(ROOT/"odmm_linux_compact_v2277.py"),"--report",str(report),"--state","FAILED","--json"],capture_output=True,text=True,check=True)
    data=json.loads(result.stdout)
    assert data["read_only"] is True
    assert data["summary"]["total"]==1
    assert data["jobs"][0]["id"]=="job-1"

def test_windows_build_targets():
    build=(ROOT/"BUILD-WINDOWS-COMPACT-V2277.cmd").read_text()
    assert "odmm_windows_compact_v2277.py" in build
    assert "ODMM-COMPACT-WINDOWS-V2277.iss" in build
    assert "7.8.7" in build
    assert (ROOT/"ODMM-COMPACT-WINDOWS-V2277.iss").is_file()
