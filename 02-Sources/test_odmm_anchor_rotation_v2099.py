from datetime import datetime,timezone,timedelta
from unittest.mock import patch
from odmm_anchor_rotation_v2099 import assess_rotation

NOW=datetime(2026,10,15,tzinfo=timezone.utc)
def policy(key='key1',state='ACTIVE',start=-2,end=30):
 return {'key_id':key,'state':state,'not_before':(NOW+timedelta(days=start)).isoformat(),'not_after':(NOW+timedelta(days=end)).isoformat()}
def check(p=None,**kw):
 with patch('odmm_anchor_rotation_v2099.assess_anchor_status',return_value={'integrity':'VERIFIED','key_id':'key1','status':'BLOCKED','cutover_authorized':False}):
  return assess_rotation(None,'campaign',anchor_provider=None,resolver=None,policy_provider=lambda _:p,now=NOW,**kw)
def test_current():assert check(policy())['rotation']=='CURRENT'
def test_expiring():assert check(policy(end=2))['warning'] is True
def test_expired():assert check(policy(end=-1))['rotation']=='EXPIRED'
def test_revoked():assert check(policy(state='REVOKED'))['rotation']=='REVOKED'
def test_retired():assert check(policy(state='RETIRED'))['rotation']=='REVOKED'
def test_not_yet():assert check(policy(start=1))['rotation']=='NOT_YET_VALID'
def test_mismatch():assert check(policy(key='other'))['reason']=='KEY_POLICY_MISMATCH'
def test_missing():assert check(None)['rotation']=='UNVERIFIED'
def test_bad_timestamp():
 p=policy();p['not_after']='tomorrow';assert check(p)['reason']=='INVALID_POLICY_TIMESTAMP'
def test_naive_timestamp():
 p=policy();p['not_before']='2026-10-15';assert check(p)['reason']=='INVALID_POLICY_TIMESTAMP'
def test_bad_range():assert check(policy(start=2,end=1))['reason']=='INVALID_POLICY'
def test_fail_closed():
 for p in [policy(),policy(end=-1),None]:
  r=check(p);assert r['status']=='BLOCKED' and r['cutover_authorized'] is False
