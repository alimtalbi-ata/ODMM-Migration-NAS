import json
import subprocess
import sys
from pathlib import Path
import pytest
from odmm_compact_dashboard_v2278 import dashboard
from odmm_editions_v2278 import EDITIONS
ROOT=Path(__file__).parent

def test_three_editions():
    assert len(EDITIONS)==3
    assert EDITIONS["linux-full"]["migration_engine"]=="native"
    assert all("Open Data Migration Manager" in e["name"] for e in EDITIONS.values())

def test_dashboard_separates_global_from_filtered():
    jobs=[{"id":"a","status":"FAILED"},{"id":"b","status":"RUNNING"}]
    out=dashboard(jobs,state="FAILED")
    assert out["total"]["total"]==2 and out["visible"]["total"]==1
    assert out["total"]["running"]==1 and out["visible"]["running"]==0
    assert jobs==[{"id":"a","status":"FAILED"},{"id":"b","status":"RUNNING"}]
    assert out["metrics_available"] is False

@pytest.mark.parametrize("bad",[None,{},[1],[None]])
def test_reject_invalid_jobs(bad):
    with pytest.raises(ValueError): dashboard(bad)

def test_linux_compact_cli(tmp_path):
    p=tmp_path/"jobs.json"
    p.write_text(json.dumps({"items":[{"id":"a","status":"FAILED"},{"id":"b","status":"RUNNING"}]}))
    run=subprocess.run([sys.executable,str(ROOT/"odmm_linux_compact_v2278.py"),"--report",str(p),"--state","FAILED","--json"],capture_output=True,text=True,check=True)
    out=json.loads(run.stdout)
    assert out["global_summary"]["total"]==2 and out["summary"]["total"]==1

def test_windows_artifacts():
    cmd=(ROOT/"BUILD-WINDOWS-COMPACT-V2278.cmd").read_text()
    assert "odmm_windows_compact_v2278.py" in cmd
    assert "ODMM-COMPACT-WINDOWS-V2278.iss" in cmd
    assert "7.8.8" in cmd
