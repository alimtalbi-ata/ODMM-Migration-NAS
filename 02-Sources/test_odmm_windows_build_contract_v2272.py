from pathlib import Path
from odmm_windows_build_contract_v2272 import audit

ROOT=Path(__file__).parent

def test_release_contract_passes():
    assert audit(ROOT)==[]

def test_missing_hidden_import_detected(tmp_path):
    for name in ('BUILD-WINDOWS-V2272.cmd','odmm_windows_desktop_v2272.py','ODMM-WINDOWS-V2272.iss'):
        (tmp_path/name).write_bytes((ROOT/name).read_bytes())
    errors=audit(tmp_path)
    assert any(e.startswith('MISSING_HIDDEN_IMPORT:') for e in errors)
    assert any(e.startswith('MISSING_DESKTOP_DEPENDENCY:') for e in errors)

def test_bad_installer_detected(tmp_path):
    for name in ('BUILD-WINDOWS-V2272.cmd','odmm_windows_desktop_v2272.py','ODMM-WINDOWS-V2272.iss'):
        (tmp_path/name).write_bytes((ROOT/name).read_bytes())
    (tmp_path/'ODMM-WINDOWS-V2272.iss').write_text('broken')
    assert 'WRONG_INNO_OUTPUT' in audit(tmp_path)
