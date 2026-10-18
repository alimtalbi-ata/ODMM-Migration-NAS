"""Read-only, local mount capability probe; not a NAS API or ACL attestation.
Auteur : Abdelhalim Talbi.
"""
import json, os, stat, subprocess
from pathlib import Path

ALLOWED_FS = frozenset(('nfs','nfs4','cifs','smb3'))

def _mountinfo(path, mountinfo):
    selected = None
    for line in mountinfo.splitlines():
        parts = line.split(' - ', 1)
        if len(parts) != 2: continue
        left, right = parts
        cols = left.split(); rhs = right.split()
        if len(cols) < 5 or len(rhs) < 3: continue
        mountpoint = cols[4].replace('\\040',' ')
        if path == mountpoint or path.startswith(mountpoint.rstrip('/') + '/'):
            if selected is None or len(mountpoint) > len(selected['mountpoint']):
                selected = {'mountpoint':mountpoint,'filesystem':rhs[0], 'mount_options':cols[5] if len(cols)>5 else '', 'super_options':rhs[2]}
    return selected

def probe(path, *, mountinfo=None):
    p=Path(path)
    if p.is_symlink() or not p.is_dir(): raise ValueError('INVALID_MOUNT_PATH')
    resolved=str(p.resolve(strict=True))
    if mountinfo is None: mountinfo=Path('/proc/self/mountinfo').read_text()
    mount=_mountinfo(resolved,mountinfo)
    if not mount or mount['filesystem'] not in ALLOWED_FS: raise ValueError('NOT_NFS_OR_SMB_MOUNT')
    # Never read file contents, enumerate directories, or execute remote commands.
    # Avoid exposing mount source, server names, credentials or options in exported evidence.
    return {'schema':'odmm.mount_probe.v2052','evidence_type':'LOCAL_MOUNT_METADATA',
      'filesystem':mount['filesystem'],'mountpoint':mount['mountpoint'],
      'protocol_family':'SMB' if mount['filesystem'] in ('cifs','smb3') else 'NFS',
      'mount_readonly_declared':'ro' in mount['mount_options'].split(','),
      'vendor':'UNVERIFIED','firmware':'UNVERIFIED','acl':'UNVERIFIED',
      'identity_mapping':'UNVERIFIED','effective_access':'UNVERIFIED',
      'status':'UNVERIFIED','cutover_authorized':False}

def cli():
    import argparse
    parser=argparse.ArgumentParser(description='ODMM local mount metadata (read-only)')
    parser.add_argument('path'); parser.add_argument('--output')
    args=parser.parse_args()
    data=json.dumps(probe(args.path),indent=2,ensure_ascii=False)
    if args.output:
        out=Path(args.output)
        if out.is_symlink() or out.exists(): raise ValueError('OUTPUT_MUST_BE_NEW_REGULAR_PATH')
        fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:f.write(data+'\n')
    else: print(data)
if __name__=='__main__':cli()
