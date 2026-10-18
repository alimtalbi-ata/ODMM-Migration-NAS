from pathlib import Path
from odmm_portable_qualification_v2247 import qualify

def test_missing_launchers_fail_closed(tmp_path):
    result = qualify(tmp_path)
    assert result['status'] == 'FAIL'
    assert len(result['findings']) == 3

def test_smoke_of_packaged_launchers():
    result = qualify(Path(__file__).resolve().parent)
    assert not result['findings'], result
    assert any(x['procedure'] == 'isolated-python-preflight' and x['status'] == 'PASS' for x in result['checks'])
    assert any(x['procedure'] == 'windows-native-execution' and x['status'] == 'NOT_TESTED' for x in result['checks'])

def test_missing_launchers_no_execution(tmp_path):
    (tmp_path / 'ODMM-PORTABLE-CHECK.cmd').write_text('@echo off\n')
    result = qualify(tmp_path)
    assert 'MISSING:odmm_portable_doctor_v2246.py' in result['findings']
    assert not any(x['procedure'] == 'isolated-python-preflight' for x in result['checks'])
