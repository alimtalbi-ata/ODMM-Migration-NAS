import os
import pytest
from odmm_live_access_v2182 import AccessCase, LiveAccessError, run_readonly_case, compare_cases

DIRECTIONS=[('NetApp','FlashBlade'),('FlashBlade','NetApp'),('NetApp','OneFS'),('OneFS','NetApp'),('FlashBlade','OneFS'),('OneFS','FlashBlade')]

def case(tmp_path, a='NetApp',b='FlashBlade', name='one'):
    src=tmp_path/'src'; dst=tmp_path/'dst'; src.mkdir(exist_ok=True); dst.mkdir(exist_ok=True)
    (src/'payload').write_bytes(b'hello'); (dst/'payload').write_bytes(b'hello')
    return AccessCase(name,str(src),str(dst),'payload',os.geteuid(),os.getegid(),a,b)

def test_equal_local_reads(tmp_path):
    r=run_readonly_case(case(tmp_path))
    assert r['report']['local_open_outcomes_equal']
    assert not r['report']['effective_nas_acl_verified'] and not r['report']['cutover_authorized']
    assert len(r['sha256'])==64

@pytest.mark.parametrize('a,b',DIRECTIONS)
def test_all_six_directions(tmp_path,a,b):
    r=run_readonly_case(case(tmp_path,a,b))
    assert r['report']['direction']==f'{a}->{b}'

@pytest.mark.parametrize('path', ['../payload','/etc/passwd','link'])
def test_unsafe_path_fails_closed(tmp_path,path):
    c=case(tmp_path)
    if path=='link':
        (tmp_path/'src'/'link').symlink_to(tmp_path/'src'/'payload')
    c=AccessCase(c.case_id,c.source_root,c.target_root,path,c.expected_euid,c.expected_egid,c.source_vendor,c.target_vendor)
    with pytest.raises(LiveAccessError,match='PROBE_FAILED_CLOSED'):
        run_readonly_case(c)

def test_identity_mismatch(tmp_path):
    c=case(tmp_path)
    c=AccessCase(c.case_id,c.source_root,c.target_root,c.relative_path,c.expected_euid+1,c.expected_egid,c.source_vendor,c.target_vendor)
    with pytest.raises(LiveAccessError,match='EXECUTION_IDENTITY_MISMATCH'):
        run_readonly_case(c)

def test_missing_target_fails_closed(tmp_path):
    c=case(tmp_path)
    (tmp_path/'dst'/'payload').unlink()
    with pytest.raises(LiveAccessError,match='PROBE_FAILED_CLOSED'):
        run_readonly_case(c)

def test_duplicate_case_rejected(tmp_path):
    c=case(tmp_path)
    with pytest.raises(LiveAccessError,match='EMPTY_OR_DUPLICATE_CASES'):
        compare_cases([c,c])

def test_campaign_no_cutover(tmp_path):
    c=case(tmp_path)
    result=compare_cases([c])
    assert result['all_local_outcomes_equal'] and not result['nas_qualified'] and not result['cutover_authorized']
