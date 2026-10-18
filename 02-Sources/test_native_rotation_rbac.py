import asyncio
import json
import unittest
from native_rotation_rbac import build_rotation_authorization
from native_rotation_target_binding import sign_target_approval
from native_rotation_portal_binding import build_rotation_endpoint
try:
    from starlette.requests import Request
    from fastapi import HTTPException
except ImportError:
    Request=None

@unittest.skipIf(Request is None,'FastAPI optional')
class RotationRBACTests(unittest.TestCase):
    def setUp(self):
        self.key=b'K'*32
        self.audit=[]
        self.identity={'authenticated':True,'subject':'operator','roles':['rotation_executor']}
        self.approval=sign_target_approval(gateway_key=self.key,request_id='req1',requester='requester',reviewer='reviewer',target_key_id='next',expected_head='0'*64,issued_ns=100,expires_ns=200)
        self.body={'request_id':'req1','target_key_id':'next','signed_target':self.approval}
    def policy(self,**kwargs):
        return build_rotation_authorization(identity_provider=lambda r:self.identity,gateway_key_provider=lambda:self.key,denial_audit=self.audit.append,clock_ns=lambda:150,**kwargs)
    def test_valid_executor(self):self.assertTrue(self.policy()(None,self.body));self.assertEqual([],self.audit)
    def test_unauthenticated(self):
        self.identity['authenticated']=False
        self.assertFalse(self.policy()(None,self.body));self.assertEqual('UNAUTHENTICATED',self.audit[-1]['reason'])
    def test_missing_role(self):
        self.identity['roles']=['viewer']
        self.assertFalse(self.policy()(None,self.body));self.assertEqual('ROLE_DENIED',self.audit[-1]['reason'])
    def test_requester_not_executor(self):
        self.identity['subject']='requester'
        self.assertFalse(self.policy()(None,self.body));self.assertEqual('SEPARATION_OF_DUTIES',self.audit[-1]['reason'])
    def test_reviewer_not_executor(self):
        self.identity['subject']='reviewer'
        self.assertFalse(self.policy()(None,self.body));self.assertEqual('SEPARATION_OF_DUTIES',self.audit[-1]['reason'])
    def test_tampered_approval(self):
        self.body['signed_target']['payload']['reviewer']='attacker'
        self.assertFalse(self.policy()(None,self.body));self.assertEqual('VERIFICATION_ERROR',self.audit[-1]['reason'])
    def test_mismatched_target(self):
        self.body['target_key_id']='other'
        self.assertFalse(self.policy()(None,self.body));self.assertEqual('APPROVAL_MISMATCH',self.audit[-1]['reason'])
    def test_audit_failure_propagates(self):
        self.identity['roles']=[]
        policy=build_rotation_authorization(identity_provider=lambda r:self.identity,gateway_key_provider=lambda:self.key,denial_audit=lambda r:(_ for _ in ()).throw(RuntimeError('audit offline')))
        with self.assertRaisesRegex(RuntimeError,'audit offline'):policy(None,self.body)
    def test_portal_denies_before_trusted_secrets(self):
        self.identity['roles']=[]
        def receive():return None
        payload=json.dumps(self.body).encode()
        async def recv():return {'type':'http.request','body':payload,'more_body':False}
        req=Request({'type':'http','method':'POST','path':'/','headers':[]},recv)
        endpoint=build_rotation_endpoint(db='unused',authorization=self.policy(),secrets_provider=lambda:(_ for _ in ()).throw(AssertionError('secret called')))
        with self.assertRaises(HTTPException) as cm:asyncio.run(endpoint(req))
        self.assertEqual(403,cm.exception.status_code)
