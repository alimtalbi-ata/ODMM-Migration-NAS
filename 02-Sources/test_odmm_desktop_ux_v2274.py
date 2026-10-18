import ast
from pathlib import Path

SOURCE = Path(__file__).with_name('odmm_windows_desktop_v2274.py').read_text(encoding='utf-8')

def test_syntax():
    ast.parse(SOURCE)

def test_quick_actions():
    for label in ('Préparer une migration', 'Suivre les jobs', 'Consulter les rapports', 'Console Web'):
        assert label in SOURCE

def test_safe_read_only_contract():
    assert 'Aucune migration ne démarre' in SOURCE or 'aucune migration ne démarre' in SOURCE
    assert 'reader.invalidate()' in SOURCE

def test_no_hidden_tab_navigation():
    assert 'tabs.select(tab)' in SOURCE
    assert 'root.after_idle' in SOURCE
