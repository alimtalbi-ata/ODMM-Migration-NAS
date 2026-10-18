import copy
import unittest
from nested_group_review import review_nested_groups,verify_nested_group_review,NestedGroupError

def ident(kind,number):
    return {'system':'POSIX','realm':'local','kind':kind,'id_type':'UID' if kind=='user' else 'GID','identifier':str(number)}
def snap(i,groups):return {'identity':i,'snapshot_ref':'ref-1','groups':groups}
U=ident('user',1000);A=ident('group',100);B=ident('group',200);C=ident('group',300)
class Tests(unittest.TestCase):
    def test_nested(self):
        r=review_nested_groups([snap(U,[A]),snap(A,[B]),snap(B,[])])
        self.assertEqual(r['report']['findings'][0]['status'],'DECLARED_ONLY')
        self.assertEqual(len(r['report']['findings'][0]['groups']),2)
    def test_cycle(self):
        r=review_nested_groups([snap(U,[A]),snap(A,[B]),snap(B,[A])]);self.assertEqual(r['report']['findings'][0]['status'],'BLOCKED_CYCLE')
    def test_missing(self):self.assertEqual(review_nested_groups([snap(U,[A])])['report']['findings'][0]['status'],'INDETERMINATE_MISSING')
    def test_depth(self):self.assertEqual(review_nested_groups([snap(U,[A]),snap(A,[B]),snap(B,[C]),snap(C,[])],max_depth=2)['report']['findings'][0]['status'],'INDETERMINATE_LIMIT')
    def test_duplicate(self):
        with self.assertRaises(NestedGroupError):review_nested_groups([snap(U,[]),snap(U,[])])
    def test_duplicate_membership(self):
        with self.assertRaises(NestedGroupError):review_nested_groups([snap(U,[A,A])])
    def test_bad_group_kind(self):
        with self.assertRaises(NestedGroupError):review_nested_groups([snap(U,[U])])
    def test_bad_limits(self):
        with self.assertRaises(NestedGroupError):review_nested_groups([],max_depth=True)
    def test_deterministic(self):
        a=[snap(U,[A]),snap(A,[B]),snap(B,[])];self.assertEqual(review_nested_groups(a),review_nested_groups(list(reversed(a))))
    def test_tamper(self):
        a=[snap(U,[])];r=review_nested_groups(a);r['report']['directory_verified']=True
        with self.assertRaises(NestedGroupError):verify_nested_group_review(r,a)
    def test_verify(self):
        a=[snap(U,[])];self.assertTrue(verify_nested_group_review(review_nested_groups(a),a))
    def test_no_prod(self):self.assertFalse(review_nested_groups([snap(U,[])])['report']['production_qualified'])
if __name__=='__main__':unittest.main()
