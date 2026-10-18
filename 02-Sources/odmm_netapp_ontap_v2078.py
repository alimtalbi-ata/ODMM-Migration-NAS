"""NetApp ONTAP read-only discovery and migration gate. Auteur: Abdelhalim Talbi.
No credentials persisted; caller supplies a trusted, authenticated API fetch function.
"""
from dataclasses import dataclass
from urllib.parse import quote

@dataclass(frozen=True)
class NetAppDiscovery:
    endpoint: dict
    blockers: tuple
    warnings: tuple
    evidence: dict


def discover_ontap(fetch, *, svm_uuid, volume_uuid, share_name=None, export_policy=None):
    """Fetch selected ONTAP REST resources without modifying the appliance.
    fetch(path) must return parsed dict; use least-privilege ONTAP REST account.
    Paths and response fields are deliberately narrow; unsupported versions fail closed.
    """
    if not svm_uuid or not volume_uuid or not callable(fetch):
        raise ValueError('SVM_AND_VOLUME_REQUIRED')
    if any('/' in str(x) or '?' in str(x) for x in (svm_uuid, volume_uuid)):
        raise ValueError('INVALID_IDENTIFIER')
    paths = {
      'cluster':'/api/cluster?fields=version,management_interfaces',
      'svm':f'/api/svm/svms/{quote(str(svm_uuid),safe="")}?fields=name,state,nfs, cifs'.replace('nfs, cifs','nfs,cifs'),
      'volume':f'/api/storage/volumes/{quote(str(volume_uuid),safe="")}?fields=name,svm,nas,path,style,space,snapshot_policy,state,type',
      'nodes':'/api/cluster/nodes?fields=name,state',
    }
    responses={}; blockers=[]; warnings=[]
    for key,path in paths.items():
        try:
            data=fetch(path)
            if not isinstance(data,dict): raise ValueError('INVALID_RESPONSE')
            responses[key]=data
        except Exception:
            blockers.append('NETAPP_'+key.upper()+'_DISCOVERY_UNAVAILABLE')
    svm=responses.get('svm',{}); vol=responses.get('volume',{}); cluster=responses.get('cluster',{})
    if not vol.get('nas') or not vol.get('svm'):
        blockers.append('NETAPP_VOLUME_NAS_MAPPING_UNVERIFIED')
    if not vol.get('snapshot_policy'):
        warnings.append('NETAPP_SNAPSHOT_POLICY_UNVERIFIED')
    if not vol.get('space'):
        blockers.append('NETAPP_VOLUME_CAPACITY_UNVERIFIED')
    if not svm.get('name') or not cluster.get('version'):
        blockers.append('NETAPP_ONTAP_INVENTORY_INCOMPLETE')
    if not share_name and not export_policy:
        blockers.append('NETAPP_SHARE_OR_EXPORT_NOT_IDENTIFIED')
    ep={
      'vendor':'NetApp','model':'ONTAP','firmware':str(cluster.get('version','')),
      'namespace_id':str(svm.get('name',''))+':'+str(vol.get('name','')),
      'export_or_share':share_name or export_policy or '',
      'cluster':{'topology':'scale_out' if len(responses.get('nodes',{}).get('records',[]))>1 else 'standalone'},
      'snapshots':{'policy':'source_consistent' if vol.get('snapshot_policy') else 'unknown'},
      'virtualization':{'layer':'svm_vserver'},
      'protocol':'unknown', 'identity_domain_verified':False,'acl_model':'unknown',
    }
    # Never assert failover, consistency, ACL fidelity, or protocol identity from inventory alone.
    return NetAppDiscovery(ep,tuple(sorted(set(blockers))),tuple(sorted(set(warnings))),responses)


def qualify_netapp_pair(source, target, *, workload=None, proofs=None):
    """Combines ONTAP discovery and generic NAS gate; never authorizes cutover."""
    from odmm_nas_topology_v2077 import qualify_nas_migration
    if not isinstance(source,NetAppDiscovery) or not isinstance(target,NetAppDiscovery):
        raise ValueError('DISCOVERY_REQUIRED')
    generic=qualify_nas_migration(source.endpoint,target.endpoint,workload=workload,proofs=proofs)
    return {'status':'BLOCKED' if source.blockers or target.blockers or generic.blockers else generic.status,
      'blockers':sorted(set(generic.blockers+tuple('SOURCE_'+x for x in source.blockers)+tuple('TARGET_'+x for x in target.blockers))),
      'warnings':sorted(set(generic.warnings+source.warnings+target.warnings)),
      'plan':generic.plan,'cutover_authorized':False,'vendor':'NetApp','schema':'odmm.netapp.v2078'}
