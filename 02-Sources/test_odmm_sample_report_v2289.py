import json
import pytest
from odmm_sample_report_v2289 import sample_rows, write_sample
from odmm_payload_gate_v2285 import validate_jobs
from odmm_supervision_v2287 import supervision
from odmm_linux_compact_v2289 import main

def test_demo_valid():
    rows=sample_rows();validate_jobs(rows);assert supervision(rows)["needs_review"]==2

def test_demo_no_overwrite(tmp_path):
    path=tmp_path/"demo.json";write_sample(path)
    with pytest.raises(FileExistsError):write_sample(path)

def test_cli_demo(tmp_path,capsys):
    path=tmp_path/"demo.json";assert main(["--generate-demo-report",str(path)])==0
    assert json.loads(path.read_text())["example_only"] is True
    assert "SYNTHETIC" in capsys.readouterr().out

def test_cli_report(tmp_path,capsys):
    path=tmp_path/"demo.json";write_sample(path)
    assert main(["--report",str(path),"--overview"])==0
    assert "Bascule autorisée : NON" in capsys.readouterr().out
