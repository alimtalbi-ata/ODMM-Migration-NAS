import copy
import unittest
from identity_mapping_matrix import build_mapping_matrix
from nested_group_review import review_nested_groups
from group_membership_compare import compare_group_memberships, verify_group_comparison, GroupComparisonError

def ident(system, kind, identifier, realm='example'):
    return {'system':system,'realm':realm,'kind':kind,'id_type':'SID' if system=='AD' else ('UID' if kind=='user' else 'GID'),'identifier':identifier}

class CompareTests(unittest.TestCase):
    def setUp(self):
        self.su=ident('POSIX','user','1001'); self.tu=ident('POSIX','user','2001')
        self.sg=ident('POSIX','group','101'); self.tg=ident('POSIX','group','201')
        self.ss=[{'identity':self.su,'snapshot_ref':'s1','groups':[self.sg]},{'identity':self.sg,'snapshot_ref':'s2','groups':[]}]
        self.ts=[{'identity':self.tu,'snapshot_ref':'t1','groups':[self.tg]},{'identity':self.tg,'snapshot_ref':'t2','groups':[]}]
        self.entries=[{'source':a,'target':b,'evidence_ref':'ref'} for a,b in ((self.su,self.tu),(self.sg,self.tg))]
    def run_compare(self):
        return compare_group_memberships(build_mapping_matrix(self.entries),review_nested_groups(self.ss),review_nested_groups(self.ts),self.ss,self.ts)
    def test_declared_match_not_verified(self):
        r=self.run_compare(); self.assertEqual(r['report']['findings'][0]['status'],'DECLARED_MATCH_ONLY'); self.assertFalse(r['report']['production_qualified'])
    def test_deterministic(self): self.assertEqual(self.run_compare(),self.run_compare())
    def test_missing_group(self):
        self.ts[0]['groups']=[]; self.assertEqual(self.run_compare()['report']['findings'][0]['status'],'BLOCKED_PRIVILEGE_DRIFT')
    def test_extra_group(self):
        g=ident('POSIX','group','202'); self.ts[0]['groups'].append(g); self.ts.append({'identity':g,'snapshot_ref':'t3','groups':[]}); self.assertEqual(self.run_compare()['report']['findings'][0]['status'],'BLOCKED_PRIVILEGE_DRIFT')
    def test_unmapped_group(self):
        self.entries.pop(); self.assertEqual(self.run_compare()['report']['findings'][0]['status'],'INDETERMINATE_MAPPING')
    def test_missing_target_user(self):
        self.ts=self.ts[1:]; self.assertEqual(self.run_compare()['report']['findings'][0]['status'],'INDETERMINATE_IDENTITY')
    def test_cycle(self):
        self.ss[1]['groups']=[self.sg]; self.assertEqual(self.run_compare()['report']['findings'][0]['status'],'INDETERMINATE_GROUP_GRAPH')
    def test_tampered_snapshot_report(self):
        a=review_nested_groups(self.ss); a['sha256']='0'*64
        with self.assertRaises(GroupComparisonError): compare_group_memberships(build_mapping_matrix(self.entries),a,review_nested_groups(self.ts),self.ss,self.ts)
    def test_orphan_target_user(self):
        other=ident('POSIX','user','2002'); self.ts.append({'identity':other,'snapshot_ref':'t4','groups':[]}); self.assertEqual(self.run_compare()['report']['status'],'BLOCKED')
    def test_verify_tamper(self):
        args=(build_mapping_matrix(self.entries),review_nested_groups(self.ss),review_nested_groups(self.ts),self.ss,self.ts)
        r=compare_group_memberships(*args); self.assertTrue(verify_group_comparison(r,*args)); r['sha256']='bad'
        with self.assertRaises(GroupComparisonError): verify_group_comparison(r,*args)
    def test_ambiguous_mapping(self):
        other=ident('POSIX','group','202'); self.entries.append({'source':self.sg,'target':other,'evidence_ref':'ref2'})
        with self.assertRaises(GroupComparisonError): self.run_compare()

if __name__=='__main__': unittest.main()
