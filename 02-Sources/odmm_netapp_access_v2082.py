"""Evidence-based comparison of SMB/NFS access and identity mappings.
Evidence is observational only and never authorizes cutover.
Auteur: Abdelhalim Talbi.
"""
from collections import defaultdict

_REQUIRED=('principal','protocol','path','operation','expected','observed','identity_source')
_VALID_PROTOCOLS={'SMB','NFS3','NFS4'}
_VALID_OPERATIONS={'read','write','list','delete','traverse'}

def assess_access_evidence(source_tests, target_tests, identity_mappings, *, snapmirror=None):
    """Compare explicitly observed source/target effective access, not ACL text.
    Input rows: principal, protocol, path, operation, expected(bool), observed(bool), identity_source.
    Ambiguities and missing samples fail closed; no implicit identity translation.
    """
    blockers=[]; warnings=[]; differences=[]
    mappings={}; reverse=defaultdict(set)
    for entry in identity_mappings:
        if not isinstance(entry,dict) or not all(isinstance(entry.get(k),str) and entry[k].strip() for k in ('source','target','kind')):
            blockers.append('IDENTITY_MAPPING_INVALID');continue
        if entry['kind'] not in ('SID','UID','GID','LDAP','AD'):
            blockers.append('IDENTITY_KIND_UNSUPPORTED');continue
        key=(entry['kind'],entry['source']); value=entry['target']
        if key in mappings and mappings[key]!=value: blockers.append('IDENTITY_MAPPING_CONFLICT')
        mappings[key]=value;reverse[(entry['kind'],value)].add(entry['source'])
    if any(len(v)>1 for v in reverse.values()):blockers.append('IDENTITY_MAPPING_COLLISION')
    def index(rows, side):
        result={}
        for row in rows:
            if not isinstance(row,dict) or any(k not in row for k in _REQUIRED):
                blockers.append(side+'_ACCESS_EVIDENCE_INCOMPLETE');continue
            if row['protocol'] not in _VALID_PROTOCOLS or row['operation'] not in _VALID_OPERATIONS or type(row['expected']) is not bool or type(row['observed']) is not bool:
                blockers.append(side+'_ACCESS_EVIDENCE_INVALID');continue
            if not all(isinstance(row[k],str) and row[k] for k in ('principal','path','identity_source')) or not row['path'].startswith('/'):
                blockers.append(side+'_ACCESS_EVIDENCE_INVALID');continue
            key=(row['principal'],row['protocol'],row['path'],row['operation'],row['identity_source'])
            if key in result:blockers.append(side+'_ACCESS_EVIDENCE_DUPLICATE');continue
            result[key]=row
            if row['expected']!=row['observed']:blockers.append(side+'_ACCESS_EXPECTATION_MISMATCH')
        return result
    source=index(source_tests,'SOURCE');target=index(target_tests,'TARGET')
    for (principal,protocol,path,operation,kind),s in source.items():
        target_principal=mappings.get((kind,principal))
        if not target_principal:
            blockers.append('IDENTITY_MAPPING_MISSING');continue
        key=(target_principal,protocol,path,operation,kind)
        t=target.get(key)
        if t is None:
            blockers.append('TARGET_ACCESS_PROOF_MISSING');continue
        if s['observed']!=t['observed']:
            blockers.append('EFFECTIVE_ACCESS_DRIFT')
            differences.append({'protocol':protocol,'path':path,'operation':operation,'source_principal':principal,'target_principal':target_principal,'source_allowed':s['observed'],'target_allowed':t['observed']})
    if not source or not target:blockers.append('ACCESS_PROOF_EMPTY')
    if len(target)!=len(source):warnings.append('ACCESS_SAMPLE_CARDINALITY_DIFFERS')
    if snapmirror is not None:
        if not isinstance(snapmirror,dict) or snapmirror.get('healthy') is not True or snapmirror.get('lag_seconds') is None or type(snapmirror['lag_seconds']) not in (int,float) or snapmirror['lag_seconds']<0 or snapmirror.get('rpo_seconds') is None or type(snapmirror['rpo_seconds']) not in (int,float) or snapmirror['rpo_seconds']<0 or snapmirror['lag_seconds']>snapmirror['rpo_seconds']:
            blockers.append('SNAPMIRROR_RPO_NOT_MET_OR_UNVERIFIED')
    else: warnings.append('SNAPMIRROR_NOT_EVALUATED')
    return {'schema':'odmm.netapp.access.v2082','status':'BLOCKED','cutover_authorized':False,'blockers':sorted(set(blockers)),'warnings':sorted(set(warnings)),'differences':differences,'samples_compared':len(source)}
