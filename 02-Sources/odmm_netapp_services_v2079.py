"""ONTAP read-only service inventory and conservative migration assessment.
Auteur: Abdelhalim Talbi. All collection is caller-supplied authenticated REST GET.
"""
from dataclasses import dataclass
from urllib.parse import quote, urlsplit, parse_qs

@dataclass(frozen=True)
class ServiceInventory:
    resources: dict
    blockers: tuple
    warnings: tuple
    evidence: dict

KINDS = {
    'lifs':'/api/network/ip/interfaces?fields=name,svm,location,enabled,state,service_policy',
    'cifs_shares':'/api/protocols/cifs/shares?fields=name,svm,path,acls',
    'nfs_export_policies':'/api/protocols/nfs/export-policies?fields=name,svm',
    'snapmirror':'/api/snapmirror/relationships?fields=source,destination,state,healthy,transfer',
    'snapshot_policies':'/api/storage/snapshot-policies?fields=name,svm,copies',
    'volumes':'/api/storage/volumes?fields=name,svm,nas,style,flexgroup,snapshot_policy,state,space',
}

def discover_services(fetch, *, max_pages=10, max_records=1000):
    """Collect bounded paginated ONTAP inventories; never infer verified ACLs or failover.
    Fetch must return JSON dict; rejects external/absolute pagination URLs.
    """
    if not callable(fetch) or not 1 <= max_pages <= 100 or not 1 <= max_records <= 100000:
        raise ValueError('INVALID_DISCOVERY_LIMITS')
    resources={}; blockers=[]; warnings=[]; evidence={}
    for kind, initial in KINDS.items():
        rows=[]; seen=set(); path=initial; pages=0
        try:
            while path:
                if path in seen: raise ValueError('PAGINATION_LOOP')
                if pages >= max_pages: raise ValueError('PAGE_LIMIT')
                seen.add(path); pages+=1
                if not path.startswith('/api/') or path.startswith('//') or urlsplit(path).scheme or urlsplit(path).netloc:
                    raise ValueError('UNTRUSTED_PAGINATION')
                obj=fetch(path)
                if not isinstance(obj,dict) or not isinstance(obj.get('records'),list): raise ValueError('INVALID_PAGE')
                for item in obj['records']:
                    if not isinstance(item,dict): raise ValueError('INVALID_RECORD')
                    rows.append(item)
                    if len(rows)>max_records: raise ValueError('RECORD_LIMIT')
                link=obj.get('_links',{}).get('next',{})
                path=link.get('href') if isinstance(link,dict) else None
                if path is not None and not isinstance(path,str): raise ValueError('INVALID_NEXT')
            resources[kind]=tuple(rows)
            evidence[kind]={'pages':pages,'records':len(rows),'source':'ONTAP_REST_READ_ONLY','validated':False}
        except Exception:
            blockers.append('NETAPP_'+kind.upper()+'_DISCOVERY_INCOMPLETE')
            resources[kind]=tuple(rows)
            evidence[kind]={'pages':pages,'records':len(rows),'source':'ONTAP_REST_READ_ONLY','validated':False,'incomplete':True}
    for kind in ('lifs','volumes'):
        if not resources[kind]: blockers.append('NETAPP_'+kind.upper()+'_EMPTY')
    if resources['volumes']:
        if any(str(v.get('style','')).lower()=='mixed' for v in resources['volumes']):
            warnings.append('NETAPP_MIXED_SECURITY_STYLE_REQUIRES_EFFECTIVE_ACCESS_TESTS')
        if any(v.get('flexgroup') for v in resources['volumes']):
            warnings.append('NETAPP_FLEXGROUP_CONSTITUENT_AND_CAPACITY_MAPPING_REQUIRED')
    if resources['snapmirror']:
        warnings.append('NETAPP_SNAPMIRROR_REPLICATION_CUTOVER_COORDINATION_REQUIRED')
    if resources['lifs']:
        warnings.append('NETAPP_LIF_FAILOVER_AND_CLIENT_RECONNECT_TEST_REQUIRED')
    return ServiceInventory(resources,tuple(sorted(set(blockers))),tuple(sorted(set(warnings))),evidence)

def prequalify_services(source, target):
    """Fail closed; no automatic cutover, even for complete REST inventory."""
    if not isinstance(source,ServiceInventory) or not isinstance(target,ServiceInventory):
        raise ValueError('INVENTORY_REQUIRED')
    blockers=['SOURCE_'+x for x in source.blockers]+['TARGET_'+x for x in target.blockers]
    for side, inv in (('SOURCE',source),('TARGET',target)):
        if not inv.resources['cifs_shares'] and not inv.resources['nfs_export_policies']:
            blockers.append(side+'_PROTOCOL_EXPORT_UNVERIFIED')
    blockers.extend(['ACL_EFFECTIVE_ACCESS_TEST_REQUIRED','CLUSTER_FAILOVER_REHEARSAL_REQUIRED',
                     'SNAPSHOT_CONSISTENCY_PROOF_REQUIRED','PERFORMANCE_BASELINE_REQUIRED'])
    return {'schema':'odmm.netapp.services.v2079','status':'BLOCKED',
            'blockers':sorted(set(blockers)),
            'warnings':sorted(set(source.warnings+target.warnings)),
            'cutover_authorized':False,
            'source_evidence':source.evidence,'target_evidence':target.evidence}
