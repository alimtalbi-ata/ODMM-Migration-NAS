"""Fail-closed, offline group graph preflight. No live directory assertions.
Author: Abdelhalim Talbi.
"""
import hashlib
import json

class GroupPreflightError(ValueError):
    pass

def preflight_group_graph(groups, identities, max_depth=16):
    """Groups: {group: [member ids or group ids]}; identities: list of user ids.
    Ambiguous user/group identifiers, cycles, unresolved references and excessive
    nesting are rejected. The result is an offline model, not AD/LDAP proof.
    """
    if not isinstance(groups, dict) or not isinstance(identities, list) or not 1 <= max_depth <= 64:
        raise GroupPreflightError('INVALID_INPUT')
    if len(groups) > 10000 or len(identities) > 10000:
        raise GroupPreflightError('LIMIT_EXCEEDED')
    users = set()
    for u in identities:
        if not isinstance(u, str) or not u or len(u) > 256 or u in users:
            raise GroupPreflightError('INVALID_IDENTITY')
        users.add(u)
    names = set(groups)
    if any(not isinstance(g, str) or not g or len(g) > 256 for g in names) or names & users:
        raise GroupPreflightError('AMBIGUOUS_PRINCIPAL')
    for g, members in groups.items():
        if not isinstance(members, list) or len(members) > 10000 or any(not isinstance(m, str) or m not in users | names for m in members) or len(set(members)) != len(members):
            raise GroupPreflightError('UNRESOLVED_OR_DUPLICATE_MEMBER')
    def expand(g, active, depth):
        if g in active:
            raise GroupPreflightError('GROUP_CYCLE')
        if depth > max_depth:
            raise GroupPreflightError('MAX_DEPTH_EXCEEDED')
        members = set()
        for m in groups[g]:
            if m in users:
                members.add(m)
            else:
                members.update(expand(m, active | {g}, depth + 1))
        return members
    resolved = {g: sorted(expand(g, set(), 0)) for g in sorted(groups)}
    payload = {'schema': 'odmm.group-preflight.v2189', 'resolved_groups': resolved,
               'directory_membership_attested': False, 'ad_ldap_authentication_verified': False,
               'effective_nas_acl_verified': False, 'cutover_authorized': False}
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    return {'report': payload, 'sha256': hashlib.sha256(canonical).hexdigest()}
