"""Static packaging and UI regression checks for Windows Compact."""
from pathlib import Path
ROOT = Path(__file__).resolve().parent
def test_compact_ui_shortcuts_and_selection():
    s=(ROOT/'odmm_windows_compact_v2276.py').read_text()
    assert '<<TreeviewSelect>>' in s and '<Control-f>' in s and '<Control-r>' in s
    assert 'summarize_rows(visible)' in s
def test_packaging_paths():
    cmd=(ROOT/'BUILD-WINDOWS-COMPACT-V2276.cmd').read_text()
    iss=(ROOT/'ODMM-COMPACT-WINDOWS-V2276.iss').read_text()
    assert 'odmm_windows_compact_v2276.py' in cmd
    assert 'ODMM-COMPACT-WINDOWS-V2276.iss' in cmd
    assert 'ODMM-Compact-Setup-V7.8.6.exe' in cmd
    assert 'ODMM-Compact-Setup-V7.8.6' in iss
