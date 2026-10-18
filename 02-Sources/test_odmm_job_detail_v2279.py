import json,subprocess,sys
from pathlib import Path
import pytest
from odmm_job_detail_v2279 import job_detail,select_job,detail_lines
from odmm_editions_v2279 import EDITIONS

def test_detail_is_safe_and_immutable():
    job={"id":"j1","status":"FAILED","source":"NetApp","target":"FlashBlade","error":"ACL mismatch","secret":"NEVER"}
    detail=job_detail(job)
    assert detail["fields"]["error"]=="ACL mismatch"
    assert "secret" not in str(detail)
    assert detail["read_only"] and "throughput" in detail["unreported_metrics"]
    assert job["secret"]=="NEVER"

def test_duplicate_ids_rejected():
    with pytest.raises(ValueError):select_job([{"id":"x"},{"id":"x"}],"x")

@pytest.mark.parametrize("bad",[{},[],{"id":""},{"id":42}])
def test_bad_detail_rejected(bad):
    with pytest.raises(ValueError):job_detail(bad)

def test_linux_detail_cli(tmp_path):
    report=tmp_path/"jobs.json";report.write_text(json.dumps([{"id":"a","status":"RUNNING","source":"Isilon"}]))
    cmd=[sys.executable,str(Path(__file__).parent/"odmm_linux_compact_v2279.py"),"--report",str(report),"--job-id","a","--json"]
    result=subprocess.run(cmd,capture_output=True,text=True,check=True)
    assert json.loads(result.stdout)["detail"]["fields"]["source"]=="Isilon"

def test_three_editions():
    assert len(EDITIONS)==3
    assert EDITIONS["windows-compact"]["version"]=="7.8.9"

def test_windows_build_contract():
    root=Path(__file__).parent
    cmd=(root/"BUILD-WINDOWS-COMPACT-V2279.cmd").read_text()
    assert "odmm_windows_compact_v2279.py" in cmd
    assert "ODMM-COMPACT-WINDOWS-V2279.iss" in cmd
