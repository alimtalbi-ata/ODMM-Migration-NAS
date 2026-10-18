from pathlib import Path
from odmm_windows_build_audit_v2259 import audit
ROOT=Path(__file__).resolve().parent

def test_required_files():
    report=audit(ROOT)
    assert all(report['checks'][n] for n in ('odmm_windows_desktop_v2258.py','odmm_desktop_model_v2258.py','ODMM-WINDOWS-V2259.iss','BUILD-WINDOWS-V2259.cmd'))

def test_no_false_build_claim():
    report=audit(ROOT,True)
    if not report['checks']['windows_host']:
        assert not report['ready_for_windows_build']
    if not report['checks']['portable_exe'] or not report['checks']['installer_exe']:
        assert not report['windows_build_executed']

def test_iss_artifact_names():
    text=(ROOT/'ODMM-WINDOWS-V2259.iss').read_text()
    assert 'ODMM-Setup-V225.9' in text and 'ODMM-Desktop.exe' in text

def test_builder_checks_exit_codes():
    text=(ROOT/'BUILD-WINDOWS-V2259.cmd').read_text()
    assert 'exit /b 14' in text and 'exit /b 17' in text
    assert 'INNO_ISCC' in text
