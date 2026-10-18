import tempfile
from pathlib import Path
from odmm_portable_doctor_v2246 import audit

def test_valid_source():
    with tempfile.TemporaryDirectory() as d:
        (Path(d)/'ok.py').write_text('x = 1\n')
        r = audit(Path(d), check_imports=False)
        assert r['status'] == 'PASS' and r['python_checked'] == 1

def test_invalid_source_fails_closed():
    with tempfile.TemporaryDirectory() as d:
        (Path(d)/'bad.py').write_text('def broken(:\n')
        r = audit(Path(d), check_imports=False)
        assert r['status'] == 'FAIL'
        assert r['findings'][0]['code'] == 'PYTHON_PARSE_ERROR'

def test_ignores_cache_and_finds_launcher():
    with tempfile.TemporaryDirectory() as d:
        (Path(d)/'__pycache__').mkdir()
        (Path(d)/'__pycache__'/'bad.py').write_text('bad syntax(')
        (Path(d)/'run.cmd').write_text('@echo off\n')
        r = audit(Path(d), check_imports=False)
        assert r['status'] == 'PASS' and 'run.cmd' in r['launchers']
