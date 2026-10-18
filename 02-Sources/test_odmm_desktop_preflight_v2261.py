from pathlib import Path
import tempfile
import pytest
from odmm_desktop_preflight_v2261 import inspect_local_source,windows_name_issue

def test_safe_read_only():
    with tempfile.TemporaryDirectory() as d:
        a,b=Path(d)/'src',Path(d)/'dst';a.mkdir();b.mkdir();(a/'a.txt').write_text('a')
        r=inspect_local_source(a,b)
        assert r['status']=='PRECHECK_ONLY' and r['files']==1 and not list(b.iterdir())

def test_case_collision():
    with tempfile.TemporaryDirectory() as d:
        a,b=Path(d)/'src',Path(d)/'dst';a.mkdir();b.mkdir()
        (a/'A.txt').write_text('a');(a/'a.txt').write_text('b')
        assert 'CASE_INSENSITIVE_SOURCE_COLLISION' in {x['issue'] for x in inspect_local_source(a,b)['issues']}

def test_destination_case_collision():
    with tempfile.TemporaryDirectory() as d:
        a,b=Path(d)/'src',Path(d)/'dst';a.mkdir();b.mkdir()
        (a/'Data').write_text('a');(b/'data').write_text('b')
        assert inspect_local_source(a,b)['status']=='BLOCKED'

def test_unsafe_names():
    assert windows_name_issue('CON.txt')=='WINDOWS_RESERVED_NAME'
    assert windows_name_issue('trailing.')=='WINDOWS_UNSAFE_NAME'
    assert windows_name_issue('normal.txt') is None

def test_no_overlap():
    with tempfile.TemporaryDirectory() as d:
        a=Path(d)/'src';a.mkdir();b=a/'dst';b.mkdir()
        with pytest.raises(ValueError,match='OVERLAPPING_ROOTS'):inspect_local_source(a,b)

def test_symlink_blocked():
    with tempfile.TemporaryDirectory() as d:
        a,b=Path(d)/'src',Path(d)/'dst';a.mkdir();b.mkdir();(a/'link').symlink_to(b)
        assert inspect_local_source(a,b)['status']=='BLOCKED'
