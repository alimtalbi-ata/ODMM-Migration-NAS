import tempfile
from pathlib import Path
import pytest
from odmm_desktop_preflight_v2260 import inspect_local_source

def test_inventory_is_read_only():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d); a=root/'a'; b=root/'b'; a.mkdir(); b.mkdir()
        (a/'data').write_bytes(b'abc')
        result=inspect_local_source(a,b)
        assert result['status']=='PRECHECK_ONLY' and result['bytes']==3
        assert not (b/'data').exists()

def test_overlap_rejected():
    with tempfile.TemporaryDirectory() as d:
        a=Path(d)/'a'; a.mkdir(); (a/'b').mkdir()
        with pytest.raises(ValueError, match='OVERLAPPING_ROOTS'):
            inspect_local_source(a,a/'b')

def test_symlink_blocked():
    with tempfile.TemporaryDirectory() as d:
        root=Path(d); a=root/'a'; b=root/'b'; a.mkdir(); b.mkdir()
        (a/'link').symlink_to(b)
        result=inspect_local_source(a,b)
        assert result['status']=='BLOCKED'

def test_destination_collision():
    with tempfile.TemporaryDirectory() as d:
        root=Path(d); a=root/'a'; b=root/'b'; a.mkdir(); b.mkdir()
        (a/'x').write_text('source'); (b/'x').write_text('target')
        assert inspect_local_source(a,b)['status']=='BLOCKED'
        assert (b/'x').read_text()=='target'
