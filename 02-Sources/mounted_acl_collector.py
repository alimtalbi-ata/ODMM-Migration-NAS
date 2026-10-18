"""Conservative, read-only ACL collection on pre-mounted NFSv4/CIFS paths.
Requires installed nfs4_getfacl or getcifsacl; does not authenticate to NAS.
"""
import hashlib, os, stat, subprocess
from pathlib import Path
from protocol_evidence import normalize_acl_capture
from collector_policy import precheck, bounded_run, PolicyError

class CollectionError(RuntimeError): pass

TOOLS = {'NFSv4': 'nfs4_getfacl', 'SMB': 'getcifsacl'}

def collect_mounted_acl(root, relative_path, protocol, side, collector_id, identity_context, *, runner=None):
    if protocol not in TOOLS or side not in ('source','target'):
        raise CollectionError('unsupported protocol or side')
    if not isinstance(relative_path,str) or not relative_path or relative_path.startswith('/') or '\x00' in relative_path:
        raise CollectionError('invalid relative path')
    parts=Path(relative_path).parts
    if any(p in ('..','.') for p in parts): raise CollectionError('path traversal')
    root=Path(root).resolve(strict=True)
    if not root.is_dir(): raise CollectionError('invalid root')
    # Reject symlinks in every component; avoid following them during path inspection.
    current=root
    for part in parts:
        current=current / part
        try: mode=os.lstat(current).st_mode
        except OSError as exc: raise CollectionError('path unavailable') from exc
        if stat.S_ISLNK(mode): raise CollectionError('symlink prohibited')
    if not (current == root or root in current.parents): raise CollectionError('outside root')
    if not isinstance(collector_id,str) or not collector_id.strip() or not isinstance(identity_context,str) or not identity_context.strip():
        raise CollectionError('collector identity required')
    argv=[TOOLS[protocol],str(current)]
    try:
        if runner is None:
            policy=precheck(protocol)
            argv[0]=policy["executable"]
            result=bounded_run(argv)
        else: result=runner(argv)
        if result.returncode != 0: raise CollectionError('collector failed or unsupported mount')
        raw=result.stdout
        if not isinstance(raw,bytes) or not raw.strip() or len(raw)>4*1024*1024: raise CollectionError('empty or excessive ACL output')
    except (OSError,subprocess.TimeoutExpired,PolicyError) as exc: raise CollectionError('collector unavailable or timed out') from exc
    # Evidence is opaque: equality does not imply equivalent effective permissions.
    capture={'protocol':protocol,'side':side,'path':relative_path,'collector':collector_id,
             'identity_context':identity_context,'acl_raw_sha256':hashlib.sha256(raw).hexdigest(),
             'complete':True}
    normalize_acl_capture(capture)
    return {'capture':capture,'raw_acl':raw,'tool':TOOLS[protocol],
            'limitations':['MOUNT_PROTOCOL_NOT_ATTESTED','NO_EFFECTIVE_ACCESS_TEST','NO_ACL_SEMANTIC_EQUIVALENCE','PATH_RACE_REQUIRES_ISOLATED_MOUNT']}
