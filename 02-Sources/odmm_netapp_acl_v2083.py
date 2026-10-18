"""Read-only ONTAP SMB share ACL / NFS export rule evidence comparison.
No claim of NTFS/NFSv4 file ACL or effective-access equivalence.
Auteur: Abdelhalim Talbi.
"""
from urllib.parse import urlsplit

KINDS = ('cifs_shares', 'nfs_export_policies')

def _safe_path(path):
    u=urlsplit(path)
    return isinstance(path,str) and path.startswith('/api/') and not path.startswith('//') and not u.scheme and not u.netloc and '\\' not in path

def collect_acl_evidence(fetch, inventory, *, max_items=2000):
    """Use only trusted inventory references, bounded collection, and read-only GET callback."""
    if not callable(fetch) or not 1 <= max_items <= 100000:
        raise ValueError('INVALID_COLLECTOR')
    evidence={}; blockers=[]; count=0
    for kind in KINDS:
        rows=[]
        for obj in inventory.resources.get(kind,()):
            count+=1
            if count>max_items:
                blockers.append('ACL_COLLECTION_LIMIT');break
            uid=obj.get('uuid')
            svm=obj.get('svm') or {}
            svm_uuid=svm.get('uuid') if isinstance(svm,dict) else None
            if not isinstance(uid,str) or not uid or not isinstance(svm_uuid,str) or not svm_uuid:
                blockers.append(kind.upper()+'_IDENTIFIER_MISSING');continue
            if kind=='cifs_shares':
                # ONTAP shares are keyed by SVM UUID and share name; do not assume a share UUID.
                from urllib.parse import quote
                name=obj.get('name')
                if not isinstance(name,str) or not name:
                    blockers.append('SMB_SHARE_NAME_MISSING');continue
                path='/api/protocols/cifs/shares/'+quote(svm_uuid,safe='')+'/'+quote(name,safe='')+'?fields=acls,name,svm,path'
            else:
                from urllib.parse import quote
                path='/api/protocols/nfs/export-policies/'+quote(uid,safe='')+'/rules?fields=clients,protocols,ro_rule,rw_rule,superuser,index'
            if not _safe_path(path):
                blockers.append('ACL_UNSAFE_PATH');continue
            try:
                page=fetch(path)
                if not isinstance(page,dict):raise ValueError('INVALID_RESPONSE')
                if kind=='cifs_shares':
                    acls=page.get('acls')
                    if not isinstance(acls,list) or not acls:raise ValueError('NO_SHARE_ACLS')
                    rows.append({'id':svm_uuid+'/'+name,'acls':acls,'complete':True})
                else:
                    rules=page.get('records')
                    if not isinstance(rules,list):raise ValueError('NO_EXPORT_RULES')
                    if page.get('_links',{}).get('next'):raise ValueError('PAGINATION_NOT_COLLECTED')
                    rows.append({'id':uid,'rules':rules,'complete':True})
            except Exception:
                blockers.append(kind.upper()+'_DETAIL_INCOMPLETE')
        evidence[kind]=rows
    return {'schema':'odmm.netapp.acl-evidence.v2083','evidence':evidence,'blockers':sorted(set(blockers)),'cutover_authorized':False}

def compare_acl_evidence(source,target):
    """Compare normalized policy text, not proof of effective permissions."""
    blockers=list(source.get('blockers',[]))+list(target.get('blockers',[])); diffs=[]
    for kind, field in [('cifs_shares','acls'),('nfs_export_policies','rules')]:
        a={x['id']:x[field] for x in source.get('evidence',{}).get(kind,[])}
        b={x['id']:x[field] for x in target.get('evidence',{}).get(kind,[])}
        if not a or not b:blockers.append(kind.upper()+'_EVIDENCE_EMPTY')
        for uid in sorted(set(a)|set(b)):
            if uid not in a or uid not in b:
                blockers.append(kind.upper()+'_OBJECT_MISSING');diffs.append({'kind':kind,'id':uid,'difference':'MISSING'})
            elif a[uid]!=b[uid]:
                blockers.append(kind.upper()+'_POLICY_DRIFT');diffs.append({'kind':kind,'id':uid,'difference':'POLICY_DRIFT'})
    blockers.append('FILE_ACL_AND_EFFECTIVE_ACCESS_NOT_PROVEN')
    return {'schema':'odmm.netapp.acl-compare.v2083','status':'BLOCKED','cutover_authorized':False,'blockers':sorted(set(blockers)),'differences':diffs}
