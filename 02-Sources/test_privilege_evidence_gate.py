import unittest
from identity_mapping_matrix import build_mapping_matrix
from nested_group_review import review_nested_groups
from group_membership_compare import compare_group_memberships
from effective_access_compare import compare_effective_access
from collector_evidence_bridge import bridge_collection
from privilege_evidence_gate import assess_privilege_evidence, verify_privilege_assessment, PrivilegeGateError

def ident(kind,n):
    return {'system':'POSIX','realm':'example','kind':kind,'id_type':'UID' if kind=='user' else 'GID','identifier':str(n)}

def acl():
    return {'mount_attestation':{'protocol':'NFSv4','mount_id':'9','device':'0:9','source':'private','mountpoint':'/mnt/test','fstype':'nfs4'},
            'path_identity':{'device':1,'inode':2,'mode':33188},'limitations':['NOT_REMOTE_VERIFIED']}

class GateTests(unittest.TestCase):
    def setUp(self):
        su,tu,sg,tg=ident('user',1),ident('user',2),ident('group',10),ident('group',20)
        self.ss=[{'identity':su,'snapshot_ref':'s1','groups':[sg]},{'identity':sg,'snapshot_ref':'s2','groups':[]}]
        self.ts=[{'identity':tu,'snapshot_ref':'t1','groups':[tg]},{'identity':tg,'snapshot_ref':'t2','groups':[]}]
        self.entries=[{'source':su,'target':tu,'evidence_ref':'e1'},{'source':sg,'target':tg,'evidence_ref':'e2'}]
        self.left=[{'principal_alias':'alice','object_alias':'file','action':'read','decision':'ALLOW'}]
        self.right=[dict(self.left[0])]
    def args(self):
        group_args=(build_mapping_matrix(self.entries),review_nested_groups(self.ss),review_nested_groups(self.ts),self.ss,self.ts)
        group=compare_group_memberships(*group_args)
        access=compare_effective_access('NFSv4',self.left,self.right)
        return group,group_args,access,bridge_collection('NetApp','NFSv4','source',acl()),bridge_collection('NetApp','NFSv4','target',acl())
    def test_pending_not_authorized(self):
        report=assess_privilege_evidence(*self.args())['report']; self.assertEqual(report['status'],'PENDING_LIVE_VERIFICATION'); self.assertFalse(report['cutover_authorized'])
    def test_access_drift_blocked(self):
        self.right[0]['decision']='DENY'; self.assertEqual(assess_privilege_evidence(*self.args())['report']['status'],'BLOCKED_PRIVILEGE_DRIFT')
    def test_group_drift_blocked(self):
        self.ts[0]['groups']=[]; self.assertEqual(assess_privilege_evidence(*self.args())['report']['status'],'BLOCKED_PRIVILEGE_DRIFT')
    def test_unknown_access_indeterminate(self):
        self.right[0]['decision']='UNKNOWN'; self.assertEqual(assess_privilege_evidence(*self.args())['report']['status'],'INDETERMINATE_EVIDENCE')
    def test_missing_mapping_indeterminate(self):
        self.entries.pop(); self.assertEqual(assess_privilege_evidence(*self.args())['report']['status'],'INDETERMINATE_EVIDENCE')
    def test_protocol_mismatch(self):
        args=list(self.args()); args[2]=compare_effective_access('SMB',self.left,self.right)
        with self.assertRaises(PrivilegeGateError): assess_privilege_evidence(*args)
    def test_vendor_mismatch(self):
        args=list(self.args()); args[4]=bridge_collection('Dell','NFSv4','target',acl())
        with self.assertRaises(PrivilegeGateError): assess_privilege_evidence(*args)
    def test_tamper_rejected(self):
        args=list(self.args()); args[2]['sha256']='0'*64
        with self.assertRaises(PrivilegeGateError): assess_privilege_evidence(*args)
    def test_determinism(self): self.assertEqual(assess_privilege_evidence(*self.args()),assess_privilege_evidence(*self.args()))
    def test_verify_report(self):
        args=self.args(); bundle=assess_privilege_evidence(*args); self.assertTrue(verify_privilege_assessment(bundle,*args)); bundle['report']['cutover_authorized']=True
        with self.assertRaises(PrivilegeGateError): verify_privilege_assessment(bundle,*args)
    def test_reject_incomplete_inputs(self):
        args=list(self.args()); args[1]=()
        with self.assertRaises(PrivilegeGateError): assess_privilege_evidence(*args)

if __name__=='__main__': unittest.main()
