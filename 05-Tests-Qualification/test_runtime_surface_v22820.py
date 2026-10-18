import importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('surface',ROOT/'09-Tools/runtime_surface_v22820.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
def test_schema():
 report=mod.scan(ROOT)
 assert report['schema']=='odmm.runtime-surface.v1'
 assert len(report['entries'])==3
 assert not report['missing_launchers']
def test_no_auto_deletion():
 assert mod.scan(ROOT)['disposition']['remove'].startswith('None')
def test_safe_paths():
 assert not mod.scan(ROOT)['unsafe_paths']
