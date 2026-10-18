import importlib.util, tempfile, pathlib
p=pathlib.Path(__file__).resolve().parents[1]/'09-Tools'/'runtime_inventory_v22821.py'
s=importlib.util.spec_from_file_location('inventory21',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def test_python_entrypoint():
 with tempfile.TemporaryDirectory() as d:
  r=pathlib.Path(d);(r/'launch.sh').write_text('python3 worker.py\n');(r/'worker.py').write_text('print(1)')
  out=m.inventory(r);assert any(x['kind']=='python-file' and x['local_target_exists'] for x in out['references'])
def test_missing_reference():
 with tempfile.TemporaryDirectory() as d:
  (pathlib.Path(d)/'launch.sh').write_text('python3 absent.py\n')
  assert m.inventory(d)['summary']['missing_local_targets']==1
def test_safe_no_deletion():
 with tempfile.TemporaryDirectory() as d:
  p=pathlib.Path(d)/'launch.sh';p.write_text('source missing.sh\n');m.inventory(d);assert p.exists()
def test_systemd():
 with tempfile.TemporaryDirectory() as d:
  (pathlib.Path(d)/'odmm.service').write_text('[Service]\nExecStart=/usr/bin/python3 /opt/odmm/main.py\n')
  assert any(x['kind']=='systemd-exec' for x in m.inventory(d)['references'])
