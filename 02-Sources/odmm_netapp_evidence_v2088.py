"""Fail-closed evidence provenance and effective-access recipe. Author: Abdelhalim Talbi."""
import hashlib,hmac,json,re
from datetime import datetime,timezone
PROTOCOLS={'SMB','NFS3','NFS4'}
OPERATIONS={'read','write','delete','traverse','list','create'}
def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(obj):return hashlib.sha256(canonical(obj)).hexdigest()
def assess_recipe(source,target,identity_map,*,trusted_collectors,now=None,max_age_seconds=3600):
    """Observations must be externally collected and authenticated by an allowlisted collector.
    A digest alone never authenticates origin. No direct NAS connection or cutover is performed.
    """
    now=now or datetime.now(timezone.utc)
    blockers=[];differences=[];pairs=[]
    mapping={};reverse={}
    for m in identity_map if isinstance(identity_map,list) else []:
        if not isinstance(m,dict) or m.get('kind') not in ('SID','UID','GID') or not all(isinstance(m.get(k),str) and m[k] for k in ('source','target')):
            blockers.append('IDENTITY_INVALID');continue
        key=(m['kind'],m['source']);value=(m['kind'],m['target'])
        if key in mapping and mapping[key]!=value:blockers.append('IDENTITY_CONFLICT')
        if value in reverse and reverse[value]!=key:blockers.append('IDENTITY_COLLISION')
        mapping[key]=value;reverse[value]=key
    def parse(records,side):
        out={}
        if not isinstance(records,list) or not records:blockers.append(side+'_EVIDENCE_MISSING');return out
        for r in records:
            if not isinstance(r,dict):blockers.append(side+'_EVIDENCE_INVALID');continue
            required=('collector_id','attestation','collected_at','evidence_id','principal_kind','principal','protocol','path','operation','allowed','sha256')
            if any(k not in r for k in required):blockers.append(side+'_EVIDENCE_INCOMPLETE');continue
            try:
                ts=datetime.fromisoformat(r['collected_at'].replace('Z','+00:00'))
                if ts.tzinfo is None or not (0<=(now-ts).total_seconds()<=max_age_seconds):raise ValueError()
                if r['collector_id'] not in trusted_collectors or r['attestation'] is not True:raise ValueError()
                if r['principal_kind'] not in ('SID','UID','GID') or not isinstance(r['principal'],str) or not r['principal']:raise ValueError()
                if r['protocol'] not in PROTOCOLS or r['operation'] not in OPERATIONS or not isinstance(r['path'],str) or not r['path'].startswith('/'):raise ValueError()
                if type(r['allowed']) is not bool or not isinstance(r['evidence_id'],str) or not r['evidence_id']:raise ValueError()
                if not isinstance(r['sha256'],str) or not hmac.compare_digest(r['sha256'],digest({k:v for k,v in r.items() if k!='sha256'})):raise ValueError()
            except (ValueError,TypeError,AttributeError,KeyError):blockers.append(side+'_EVIDENCE_UNVERIFIED');continue
            key=(r['principal_kind'],r['principal'],r['protocol'],r['path'],r['operation'])
            if key in out:blockers.append(side+'_EVIDENCE_DUPLICATE');continue
            out[key]=r
        return out
    s=parse(source,'SOURCE');t=parse(target,'TARGET');used=set()
    for key,record in s.items():
        mapped=mapping.get(key[:2]);
        if mapped is None:blockers.append('IDENTITY_MAPPING_MISSING');continue
        targetkey=(*mapped,*key[2:]);other=t.get(targetkey)
        if other is None:blockers.append('TARGET_TEST_MISSING');continue
        used.add(targetkey)
        pairs.append({'source_evidence':record['evidence_id'],'target_evidence':other['evidence_id'],'path':key[3],'operation':key[4]})
        if record['allowed']!=other['allowed']:
            blockers.append('EFFECTIVE_ACCESS_DRIFT')
            differences.append({'protocol':key[2],'path':key[3],'operation':key[4],'source_allowed':record['allowed'],'target_allowed':other['allowed']})
    if set(t)-used:blockers.append('TARGET_TEST_UNMATCHED')
    return {'schema':'odmm.netapp.recipe.v2088','status':'BLOCKED','cutover_authorized':False,'blockers':sorted(set(blockers)),'differences':differences,'pairs':pairs,'warning':'Collector attestation is an input assertion; independently verify collector identity and acquisition channel.'}
