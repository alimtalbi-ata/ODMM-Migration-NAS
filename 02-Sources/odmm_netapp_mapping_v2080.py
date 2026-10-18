"""Conservative ONTAP namespace/service correlation, no cutover permission.
Auteur: Abdelhalim Talbi.
"""
from dataclasses import dataclass
from html import escape
import json

@dataclass(frozen=True)
class MappingReport:
    rows: tuple
    blockers: tuple
    warnings: tuple
    status: str = 'BLOCKED'
    cutover_authorized: bool = False


def _svm(v):
    if isinstance(v,dict): return str(v.get('uuid') or v.get('name') or '')
    return str(v or '')

def _path(v):
    if not isinstance(v,str) or not v.startswith('/') or '//' in v or '/..' in v or '/./' in v:
        return None
    return v.rstrip('/') or '/'

def correlate_ontap_services(inventory):
    """Map shares/exports to volume junctions, without assuming ACL equivalence.
    Incomplete or ambiguous mappings fail closed. Export policies are *not* mount paths.
    """
    r=inventory.resources
    blockers=list(inventory.blockers); warnings=list(inventory.warnings); rows=[]
    volumes=list(r.get('volumes',()))
    shares=list(r.get('cifs_shares',()))
    policies=list(r.get('nfs_export_policies',()))
    lifs=list(r.get('lifs',()))
    for vol in volumes:
        svm=_svm(vol.get('svm')); nas=vol.get('nas') or {}
        junction=_path(nas.get('path') or vol.get('junction_path') or '')
        policy=nas.get('export_policy') or vol.get('export_policy')
        style=str(nas.get('security_style') or vol.get('style') or '').lower()
        name=str(vol.get('name') or '')
        if not svm or not name or not junction:
            blockers.append('NETAPP_VOLUME_NAMESPACE_UNVERIFIED')
        if style in ('mixed','unix','ntfs'):
            warnings.append('NETAPP_SECURITY_STYLE_EFFECTIVE_ACCESS_PROOF_REQUIRED')
        else: blockers.append('NETAPP_SECURITY_STYLE_UNKNOWN')
        matching=[]
        for share in shares:
            if _svm(share.get('svm'))!=svm: continue
            sp=_path(share.get('path'))
            if sp is None:
                blockers.append('NETAPP_SHARE_PATH_INVALID'); continue
            if junction and (sp==junction or sp.startswith(junction.rstrip('/')+'/')):
                matching.append(str(share.get('name') or ''))
        svm_lifs=[l for l in lifs if _svm(l.get('svm'))==svm]
        if not svm_lifs: blockers.append('NETAPP_SVM_LIF_MAPPING_MISSING')
        if not matching and not policy: blockers.append('NETAPP_VOLUME_SERVICE_MAPPING_MISSING')
        if policy and not any(_svm(p.get('svm'))==svm and str(p.get('name'))==str(policy) for p in policies):
            blockers.append('NETAPP_EXPORT_POLICY_UNRESOLVED')
        rows.append({'svm':svm,'volume':name,'junction':junction,'security_style':style,
                     'shares':sorted(matching),'export_policy':policy,'lif_count':len(svm_lifs),
                     'acl_verified':False,'snapshot_consistent':False})
    for share in shares:
        svm=_svm(share.get('svm')); sp=_path(share.get('path'))
        if not sp or not any(x['svm']==svm and x['junction'] and (sp==x['junction'] or sp.startswith(x['junction'].rstrip('/')+'/')) for x in rows):
            blockers.append('NETAPP_ORPHAN_OR_UNMAPPED_SHARE')
    if not rows: blockers.append('NETAPP_NO_VOLUMES')
    blockers.extend(['NETAPP_ACL_EFFECTIVE_ACCESS_UNVERIFIED','NETAPP_HA_FAILOVER_UNVERIFIED',
                     'NETAPP_SNAPSHOT_COHERENCE_UNVERIFIED','NETAPP_PERFORMANCE_BASELINE_UNVERIFIED'])
    return MappingReport(tuple(rows),tuple(sorted(set(blockers))),tuple(sorted(set(warnings))))

def compare_mappings(source,target):
    s=correlate_ontap_services(source); t=correlate_ontap_services(target)
    return {'schema':'odmm.netapp.mapping.v2080','status':'BLOCKED','cutover_authorized':False,
            'source':s.rows,'target':t.rows,
            'blockers':sorted(set(['SOURCE_'+x for x in s.blockers]+['TARGET_'+x for x in t.blockers])),
            'warnings':sorted(set(s.warnings+t.warnings))}

def render_mapping_html(result):
    """Static, escaped dashboard for human review; not an authenticated server route."""
    def table(side):
        rows=result[side]
        body=''.join('<tr>'+''.join('<td>'+escape(str(r.get(k,'')))+'</td>' for k in ('svm','volume','junction','security_style','shares','export_policy','lif_count'))+'</tr>' for r in rows)
        return '<h2>'+side.title()+'</h2><table><thead><tr>'+''.join('<th>'+escape(k)+'</th>' for k in ('svm','volume','junction','security_style','shares','export_policy','lif_count'))+'</tr></thead><tbody>'+body+'</tbody></table>'
    issues=''.join('<li>'+escape(x)+'</li>' for x in result['blockers'])
    return '<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM NetApp V208.0</title><style>body{font:15px system-ui;background:#101b30;color:#eaf2ff;padding:32px}h1{color:#67d5ef}.alert{background:#5c2934;padding:16px;border-radius:12px}table{border-collapse:collapse;width:100%;margin:20px 0}td,th{padding:10px;border-bottom:1px solid #40536c;text-align:left}th{color:#67d5ef}</style><h1>ODMM · NetApp ONTAP · Préqualification V208.0</h1><p>Rapport de démonstration — aucune connexion à une appliance réelle</p><div class="alert"><strong>CUTOVER INTERDIT · BLOCKED</strong><p>Les ACL, snapshots, HA et performances nécessitent des preuves terrain.</p></div>'+table('source')+table('target')+'<h2>Bloquants</h2><ul>'+issues+'</ul><footer>Auteur : Abdelhalim Talbi</footer></html>'
