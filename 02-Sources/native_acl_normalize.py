"""Conservative parsers for *subset* of nfs4_getfacl/getcifsacl output.
Unrecognized lines and flags fail closed; no cross-protocol equivalence asserted.
"""
import re
from acl_ace_compare import compare_ace_snapshots

class NativeACLParseError(ValueError): pass

_NFS = re.compile(r"^([AD]):([^:]*):([^:]+):([A-Za-z]+)$")
_SMB = re.compile(r"^ACL:(S-1-(?:[0-9]+-)+[0-9]+):(ALLOWED|DENIED)/0x([0-9a-fA-F]+)/0x([0-9a-fA-F]+)$")

def parse_nfs4(text):
    if not isinstance(text,str) or len(text)>1000000: raise NativeACLParseError('INVALID_INPUT')
    result=[]
    for raw in text.splitlines():
        line=raw.strip()
        if not line or line.startswith('#'): continue
        m=_NFS.fullmatch(line)
        if not m: raise NativeACLParseError('UNSUPPORTED_NFS4_LINE')
        kind,flags,principal,rights=m.groups()
        if len(set(flags))!=len(flags) or len(set(rights))!=len(rights): raise NativeACLParseError('DUPLICATE_BITS')
        if len(principal)>256 or len(rights)>64 or len(flags)>64: raise NativeACLParseError('EXCESSIVE_FIELD')
        # Opaque native letters: never translate to POSIX/SMB rights.
        result.append({'principal':principal,'type':'ALLOW' if kind=='A' else 'DENY',
                       'rights':list(rights),'flags':list(flags),'inherited':'I' in flags})
    if not result: raise NativeACLParseError('EMPTY_ACL')
    return result

def parse_smb(text):
    if not isinstance(text,str) or len(text)>1000000: raise NativeACLParseError('INVALID_INPUT')
    result=[]
    for raw in text.splitlines():
        line=raw.strip()
        if not line: continue
        if line.startswith(('REVISION:','OWNER:','GROUP:')): continue
        m=_SMB.fullmatch(line)
        if not m: raise NativeACLParseError('UNSUPPORTED_SMB_LINE')
        principal,kind,flags,mask=m.groups()
        result.append({'principal':principal,'type':'ALLOW' if kind=='ALLOWED' else 'DENY',
                       'rights':['MASK_0x'+format(int(mask,16),'08x')],
                       'flags':['FLAGS_0x'+format(int(flags,16),'08x')],
                       'inherited':bool(int(flags,16)&0x10)})
    if not result: raise NativeACLParseError('EMPTY_ACL')
    return result

def compare_native_acl(source_text,target_text,*,protocol):
    if protocol=='NFSv4': parser=parse_nfs4
    elif protocol=='SMB': parser=parse_smb
    else: raise NativeACLParseError('UNSUPPORTED_PROTOCOL')
    left=parser(source_text); right=parser(target_text)
    result=compare_ace_snapshots(left,right,protocol=protocol)
    result['report']['limitations'].extend(['NATIVE_SUBSET_PARSER_ONLY','OPAQUE_RIGHTS_NO_SEMANTIC_TRANSLATION',
                                          'NO_CROSS_PROTOCOL_EQUIVALENCE','UNAUTHENTICATED_TEXT_INPUT'])
    from acl_ace_compare import _hash
    result['sha256']=_hash(result['report'])
    return result
