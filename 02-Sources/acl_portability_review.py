"""Conservative ACL inheritance/portability review; offline and fail-closed.

No NFSv4/SMB semantic equivalence or vendor certification is implied.
"""
from acl_fidelity_review import review_acl_fidelity, ACLFidelityError
from native_acl_normalize import parse_nfs4, parse_smb, NativeACLParseError
from acl_ace_compare import _hash

class ACLPortabilityError(ValueError): pass

# Only identify well-known inheritance markers; unknown NFS letters remain opaque.
NFS_INHERITANCE = frozenset('fdin')
SMB_KNOWN_INHERITANCE_MASK = 0x1f  # OI, CI, NP, IO, INHERITED

def _inspect(text, protocol):
    try:
        aces = parse_nfs4(text) if protocol == 'NFSv4' else parse_smb(text)
    except NativeACLParseError as exc:
        raise ACLPortabilityError('UNSUPPORTED_NATIVE_ACL') from exc
    entries=[]
    for index, ace in enumerate(aces):
        if protocol=='NFSv4':
            flags=set(ace['flags'])
            # NFS4 common flags f/d/n/i (file/dir/no-propagate/inherit-only),
            # plus I in some tools for inherited; not equivalent to SMB bits.
            inherited=bool('I' in flags)
            opaque=sorted(flags - NFS_INHERITANCE - {'I'})
            flags_native=''.join(ace['flags'])
            inheritance={'file_inherit':'f' in flags,'directory_inherit':'d' in flags,
                         'no_propagate':'n' in flags,'inherit_only':'i' in flags,
                         'inherited_marker':inherited}
        else:
            try: bits=int(ace['flags'][0].removeprefix('FLAGS_0x'),16)
            except (IndexError,ValueError) as exc: raise ACLPortabilityError('BAD_SMB_FLAGS') from exc
            opaque=[f'UNKNOWN_BITS_0x{bits & ~SMB_KNOWN_INHERITANCE_MASK:08x}'] if bits & ~SMB_KNOWN_INHERITANCE_MASK else []
            flags_native=ace['flags'][0]
            inheritance={'object_inherit':bool(bits & 1),'container_inherit':bool(bits & 2),
                         'no_propagate':bool(bits & 4),'inherit_only':bool(bits & 8),
                         'inherited_marker':bool(bits & 16)}
        entries.append({'index':index,'principal':ace['principal'],'type':ace['type'],
                        'native_flags':flags_native,'inheritance':inheritance,
                        'opaque_flags':opaque})
    return entries

def review_acl_portability(source_text, target_text, *, protocol):
    if protocol not in ('NFSv4','SMB'): raise ACLPortabilityError('UNSUPPORTED_PROTOCOL')
    try: fidelity=review_acl_fidelity(source_text,target_text,protocol=protocol)
    except ACLFidelityError as exc: raise ACLPortabilityError('FIDELITY_REVIEW_FAILED') from exc
    source=_inspect(source_text,protocol); target=_inspect(target_text,protocol)
    drift=[i for i in range(max(len(source),len(target)))
           if i>=len(source) or i>=len(target) or source[i]!=target[i]]
    opaque=any(entry['opaque_flags'] for entry in source+target)
    if drift or fidelity['report']['status'].startswith('BLOCKED'):
        status='BLOCKED_ACL_PORTABILITY_DRIFT'
    elif opaque or fidelity['report']['status']!='STRUCTURAL_MATCH_ONLY':
        status='INDETERMINATE_PORTABILITY'
    else: status='STRUCTURAL_MATCH_ONLY'
    report={'schema':'odmm.acl-portability.v1','protocol':protocol,'status':status,
            'source_inheritance':source,'target_inheritance':target,
            'drift_indices':drift,'unrecognized_flags_present':opaque,
            'fidelity_sha256':fidelity['sha256'],
            'cutover_authorized':False,'production_qualified':False,'manual_review_required':True,
            'limitations':['OFFLINE_UNAUTHENTICATED_INPUT','NATIVE_SUBSET_ONLY',
                           'INHERITANCE_MARKERS_NOT_EFFECTIVE_ACCESS',
                           'NO_CROSS_PROTOCOL_SEMANTIC_EQUIVALENCE',
                           'NO_VENDOR_TRANSLATION_CERTIFICATION']}
    return {'report':report,'sha256':_hash(report)}

def verify_acl_portability(bundle, source_text, target_text, *, protocol):
    if bundle!=review_acl_portability(source_text,target_text,protocol=protocol):
        raise ACLPortabilityError('REPORT_MISMATCH')
    return True
