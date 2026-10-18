"""Conservative NFS/SMB ACL translation planning; never writes or certifies access.
Author: Abdelhalim Talbi.
"""
from dataclasses import asdict
from identity_acl import ACE, IdentityMap

class ACLPlanError(ValueError): pass

RIGHTS = frozenset(('read','write','execute','delete','change_acl','take_ownership'))

def plan_acl_translation(source_aces, mapping, *, source_protocol, target_protocol,
                         source_acl_complete=False, identity_verified=False,
                         target_acl_capability_verified=False):
    if source_protocol not in ('NFS','SMB') or target_protocol not in ('NFS','SMB'):
        raise ACLPlanError('UNSUPPORTED_PROTOCOL')
    if not isinstance(mapping,IdentityMap): raise ACLPlanError('INVALID_IDENTITY_MAP')
    if not isinstance(source_aces,(tuple,list)) or any(not isinstance(x,ACE) for x in source_aces):
        raise ACLPlanError('INVALID_ACES')
    translated=[]; blockers=[]; warnings=[]
    for index,ace in enumerate(source_aces):
        target=mapping.resolve(ace.principal)
        if target is None:
            blockers.append({'index':index,'reason':'UNMAPPED_PRINCIPAL','principal':asdict(ace.principal)})
            continue
        if not set(ace.rights)<=RIGHTS:
            blockers.append({'index':index,'reason':'UNKNOWN_RIGHTS'})
            continue
        translated.append({'index':index,'principal':asdict(target),'effect':ace.effect,
                           'rights':list(ace.rights),'inherited':ace.inherited,'status':'PROPOSED_NOT_APPLIED'})
        if ace.effect=='deny': warnings.append('DENY_SEMANTICS_REQUIRE_LIVE_TEST')
        if ace.inherited: warnings.append('INHERITANCE_REQUIRE_LIVE_TEST')
        if 'change_acl' in ace.rights or 'take_ownership' in ace.rights:
            warnings.append('PRIVILEGED_RIGHTS_REQUIRE_LIVE_TEST')
    if source_protocol!=target_protocol: warnings.append('CROSS_PROTOCOL_ACL_SEMANTICS_NOT_EQUIVALENT')
    if not source_acl_complete: blockers.append({'reason':'INCOMPLETE_SOURCE_ACL'})
    if not identity_verified: blockers.append({'reason':'IDENTITY_DIRECTORY_NOT_VERIFIED'})
    if not target_acl_capability_verified: blockers.append({'reason':'TARGET_ACL_CAPABILITY_NOT_VERIFIED'})
    return {'schema':'odmm.acl.translation.plan.v2004','author':'Abdelhalim Talbi',
            'source_protocol':source_protocol,'target_protocol':target_protocol,
            'proposed_aces':translated,'blockers':blockers,'warnings':sorted(set(warnings)),
            'status':'BLOCKED' if blockers else 'REQUIRES_LIVE_EFFECTIVE_ACCESS_TESTS',
            'effective_access_verified':False,'acl_fidelity_verified':False,
            'cutover_authorized':False,'writes_performed':False,'native_engine_modified':False}
