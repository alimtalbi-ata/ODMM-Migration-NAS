import json
import pytest
from odmm_desktop_plan_v2262 import create_plan, export_plan

def fixture(status='PRECHECK_ONLY', issues=None):
    return {'status':status,'issues':issues if issues is not None else [],'entries':[{'path':'a','bytes':1}],'source':'a','target':'b','files':1,'bytes':1}

def test_safe_plan():
    p=create_plan(fixture()); assert p['state']=='READY_FOR_SERVER_REVIEW'; assert p['engine']=='ODMM_NATIVE_PRIMARY'; assert p['execution_authorized'] is False; assert p['cutover_authorized'] is False

def test_blocked():
    p=create_plan(fixture('BLOCKED',[{'issue':'SYMLINK_UNSUPPORTED'}])); assert p['state']=='BLOCKED'

def test_invalid_state():
    with pytest.raises(ValueError): create_plan(fixture('BLOCKED'))

def test_no_overwrite(tmp_path):
    p=create_plan(fixture()); dest=tmp_path/'plan.json'; export_plan(dest,p)
    with pytest.raises(FileExistsError): export_plan(dest,p)
    assert json.loads(dest.read_text())['schema']=='odmm.desktop.plan.v1'

def test_tampered_execution(tmp_path):
    p=create_plan(fixture()); p['execution_authorized']=True
    with pytest.raises(ValueError): export_plan(tmp_path/'bad.json',p)
