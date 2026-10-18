"""V177.5: offline comparison of externally collected effective-access observations.
No impersonation, filesystem modification, or remote access is performed here.
"""
from dataclasses import dataclass, asdict
from hashlib import sha256
import json

RIGHTS = frozenset(('read','write','execute','delete','change_acl','take_ownership'))
OUTCOMES = frozenset(('ALLOW','DENY','UNKNOWN','ERROR','NOT_RUN'))

@dataclass(frozen=True)
class Observation:
    test_id: str
    side: str
    principal_id: str
    path: str
    right: str
    outcome: str
    evidence_id: str

    def __post_init__(self):
        if self.side not in ('source','target') or self.right not in RIGHTS or self.outcome not in OUTCOMES:
            raise ValueError('invalid observation')
        if not all((self.test_id,self.principal_id,self.path,self.evidence_id)):
            raise ValueError('missing observation identity/evidence')

def compare_observations(observations, *, expected_test_ids):
    """Fail closed: both sides required; unknown/errored outcomes never qualify."""
    expected = set(expected_test_ids)
    if len(expected) != len(expected_test_ids):
        raise ValueError('duplicate expected test id')
    index = {}
    for o in observations:
        key = (o.test_id, o.side)
        if o.test_id not in expected or key in index:
            raise ValueError('unexpected or duplicate observation')
        index[key] = o
    failures = []
    for test_id in sorted(expected):
        a, b = index.get((test_id,'source')), index.get((test_id,'target'))
        if a is None or b is None:
            failures.append({'test_id':test_id,'reason':'MISSING_OBSERVATION'})
        elif (a.principal_id,a.path,a.right) != (b.principal_id,b.path,b.right):
            failures.append({'test_id':test_id,'reason':'TEST_IDENTITY_MISMATCH'})
        elif a.outcome not in ('ALLOW','DENY') or b.outcome not in ('ALLOW','DENY'):
            failures.append({'test_id':test_id,'reason':'UNQUALIFIED_RESULT'})
        elif a.outcome != b.outcome:
            failures.append({'test_id':test_id,'reason':'ACCESS_DRIFT', 'source':a.outcome,'target':b.outcome})
    payload = [asdict(o) for o in sorted(observations,key=lambda x:(x.test_id,x.side))]
    digest = sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'status':'MATCHED_OBSERVATIONS' if not failures else 'BLOCKED',
            'effective_access_certified':False, 'observed_test_count':len(expected)-len(failures),
            'failures':failures, 'evidence_sha256':digest,
            'note':'Offline comparison only; authenticity and completeness of external probes require independent validation.'}

def detect_orphans(principals, identity_map):
    return [asdict(p) for p in principals if identity_map.resolve(p) is None]
