"""Bounded offline group expansion from untrusted snapshots; no directory authentication."""
import hashlib
import json
from identity_mapping_matrix import _identity, MappingMatrixError

class NestedGroupError(ValueError):
    pass

def _hash(report):
    return hashlib.sha256(json.dumps(report,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()

def review_nested_groups(snapshots, *, max_depth=16, max_nodes=4096):
    if type(max_depth) is not int or not 1 <= max_depth <= 64 or type(max_nodes) is not int or not 1 <= max_nodes <= 100000:
        raise NestedGroupError('INVALID_LIMITS')
    if not isinstance(snapshots,list) or len(snapshots)>max_nodes:
        raise NestedGroupError('INVALID_SNAPSHOTS')
    graph={}
    for snap in snapshots:
        if not isinstance(snap,dict) or set(snap)!={'identity','snapshot_ref','groups'}:
            raise NestedGroupError('INVALID_SNAPSHOT')
        try:
            key=_identity(snap['identity'])
            groups=snap['groups']
            if not isinstance(groups,list) or len(groups)>max_nodes:
                raise NestedGroupError('INVALID_GROUPS')
            links=[_identity(g) for g in groups]
        except (MappingMatrixError,TypeError,KeyError) as exc:
            raise NestedGroupError('INVALID_IDENTITY') from exc
        if any(g[2]!='group' for g in links) or len(links)!=len(set(links)):
            raise NestedGroupError('INVALID_MEMBERSHIPS')
        ref=snap['snapshot_ref']
        if not isinstance(ref,str) or not 1<=len(ref)<=128 or not ref.isascii() or not all(c.isalnum() or c in '_.:-' for c in ref):
            raise NestedGroupError('INVALID_REF')
        if key in graph: raise NestedGroupError('DUPLICATE_IDENTITY')
        graph[key]=set(links)
    findings=[]
    for subject in sorted(k for k in graph if k[2]=='user'):
        visited=set(); missing=set(); cycles=set(); truncated=False
        def walk(node, stack, depth):
            nonlocal truncated
            if node in stack:
                cycles.add(node);return
            if depth>max_depth or len(visited)>=max_nodes:
                truncated=True;return
            if node not in graph:
                missing.add(node);return
            if node in visited:return
            visited.add(node)
            for child in sorted(graph[node]): walk(child,stack+(node,),depth+1)
        for group in sorted(graph[subject]): walk(group,(),1)
        status='BLOCKED_CYCLE' if cycles else 'INDETERMINATE_LIMIT' if truncated else 'INDETERMINATE_MISSING' if missing else 'DECLARED_ONLY'
        findings.append({'subject':list(subject),'groups':[list(x) for x in sorted(visited)],'missing':[list(x) for x in sorted(missing)],'cycles':[list(x) for x in sorted(cycles)],'status':status})
    report={'schema':'odmm.nested-group-review.v1','findings':findings,'directory_verified':False,'effective_access_verified':False,'production_qualified':False,'limitations':['OPERATOR_SUPPLIED_UNAUTHENTICATED_SNAPSHOTS','NO_LIVE_DIRECTORY_QUERY','NO_EFFECTIVE_ACCESS_CERTIFICATION']}
    return {'report':report,'sha256':_hash(report)}

def verify_nested_group_review(bundle,snapshots,**kwargs):
    if not isinstance(bundle,dict) or set(bundle)!={'report','sha256'} or bundle!=review_nested_groups(snapshots,**kwargs):
        raise NestedGroupError('REPORT_MISMATCH')
    return True
