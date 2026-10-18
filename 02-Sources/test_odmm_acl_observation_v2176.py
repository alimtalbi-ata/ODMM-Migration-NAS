import os
import subprocess
from dataclasses import replace
from types import SimpleNamespace
import pytest
import odmm_acl_observation_v2176 as m


def test_observe_local_acl_with_mock_tool(tmp_path, monkeypatch):
    f=tmp_path/'a'; f.write_text('x')
    monkeypatch.setattr(m.shutil,'which',lambda _: '/usr/bin/getfacl')
    calls=[]
    def runner(argv, **kw):
        calls.append((argv,kw))
        return SimpleNamespace(returncode=0, stdout=b'# file: a\nuser::rw-\ngroup::r--\nother::---\n')
    o=m.observe_posix(f,runner=runner)
    assert len(o.entries)==3 and o.owner==os.getuid()
    assert calls[0][0][-2:] == ['--',str(f)]
    assert calls[0][1]['timeout']==5
    assert not o.effective_access_verified and not o.vendor_qualified


def test_symlink_rejected(tmp_path):
    f=tmp_path/'a'; f.write_text('x'); (tmp_path/'link').symlink_to(f)
    with pytest.raises(m.ACLObservationError,match='UNSAFE'):
        m.observe_posix(tmp_path/'link')


def test_missing_collector_fails_closed(tmp_path,monkeypatch):
    f=tmp_path/'a'; f.write_text('x')
    monkeypatch.setattr(m.shutil,'which',lambda _: None)
    with pytest.raises(m.ACLObservationError,match='UNAVAILABLE'):
        m.observe_posix(f)


def test_bad_output_fails_closed(tmp_path,monkeypatch):
    f=tmp_path/'a'; f.write_text('x')
    monkeypatch.setattr(m.shutil,'which',lambda _: '/usr/bin/getfacl')
    with pytest.raises(m.ACLObservationError,match='OUTPUT_INVALID'):
        m.observe_posix(f,runner=lambda *a,**kw:SimpleNamespace(returncode=0,stdout=b'# only comment'))


def test_compare_never_grants_cutover():
    a=m.ACLObservation('/a',('user::rw-',),100,100,0o600)
    b=replace(a,path='/b')
    assert m.compare_posix(a,b)['acl_entries_equal']
    assert not m.compare_posix(a,b)['nas_cutover_authorized']
    assert not m.compare_posix(a,replace(b,entries=('user::r--',)))['acl_entries_equal']
    with pytest.raises(m.ACLObservationError,match='PROVENANCE'):
        m.compare_posix(a,replace(b,provenance='SMB'))
