"""Read-only Linux mountinfo verification. Never infer protocol from a path name."""
from pathlib import Path
import os

class MountAttestationError(ValueError): pass

def _unescape(value):
    import re
    return re.sub(r"\\([0-7]{3})",lambda m:chr(int(m.group(1),8)),value)

def parse_mountinfo(text):
    records=[]
    for line in text.splitlines():
        left,sep,right=line.partition(' - ')
        if not sep: continue
        a=left.split(); b=right.split()
        if len(a)<6 or len(b)<3: continue
        records.append({'mountpoint':_unescape(a[4]),'fstype':b[0], 'source':_unescape(b[1]),'options':a[5].split(','),'mount_id':a[0],'parent_id':a[1],'device':a[2],'mount_root':_unescape(a[3])})
    return records

def attest_mount(root,protocol,*,mountinfo=None,require_exact_mount=True):
    root=Path(root).resolve(strict=True)
    if not root.is_dir(): raise MountAttestationError('root not directory')
    if protocol not in ('NFSv4','SMB'): raise MountAttestationError('unsupported protocol')
    if mountinfo is None:
        with open('/proc/self/mountinfo',encoding='utf-8') as f: mountinfo=f.read()
    records=parse_mountinfo(mountinfo)
    matches=[r for r in records if str(root)==r['mountpoint'] or (not require_exact_mount and str(root).startswith(r['mountpoint'].rstrip('/')+'/'))]
    if not matches: raise MountAttestationError('no matching mount')
    record=max(matches,key=lambda r:len(r['mountpoint']))
    valid={'NFSv4':{'nfs4','nfs'},'SMB':{'cifs','smb3'}}[protocol]
    if record['fstype'] not in valid: raise MountAttestationError('mount filesystem mismatch')
    if protocol=='NFSv4' and record['fstype']=='nfs' and 'vers=4' not in ','.join(record['options']):
        raise MountAttestationError('NFS version unverified')
    return {'root':str(root),'protocol':protocol,'fstype':record['fstype'],'mountpoint':record['mountpoint'],'source':record['source'],'mount_id':record['mount_id'],'device':record['device'],'mount_root':record['mount_root'],'limitations':['MOUNTINFO_NOT_CRYPTOGRAPHICALLY_ATTESTED','NO_REMOTE_SERVER_IDENTITY_VERIFICATION']}
