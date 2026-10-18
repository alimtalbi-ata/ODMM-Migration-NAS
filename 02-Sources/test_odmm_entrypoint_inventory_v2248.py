from pathlib import Path
from odmm_entrypoint_inventory_v2248 import inventory, CANDIDATES

def test_real_project_inventory():
    result=inventory(Path(__file__).parent)
    assert result['status']=='PASS_WITH_UNQUALIFIED_ITEMS'
    assert len(result['entries'])==len(CANDIDATES)
    assert result['qualification']['nas_migration_e2e']=='NOT_TESTED'

def test_missing_files_fail_closed(tmp_path):
    result=inventory(tmp_path)
    assert result['status']=='FAIL'
    assert len(result['missing_or_invalid'])==len(CANDIDATES)

def test_syntax_error_fail_closed(tmp_path):
    for name in CANDIDATES:(tmp_path/name).write_text('def valid():\n    pass\n')
    (tmp_path/CANDIDATES[0]).write_text('def invalid(:')
    result=inventory(tmp_path)
    assert result['status']=='FAIL'
    assert result['entries'][0]['parse']=='FAIL'
