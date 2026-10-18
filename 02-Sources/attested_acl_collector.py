"""Fail-closed mounted ACL collection with mount checks before and after collection.
This is not race-free: pathname tools can still follow a concurrent mount/path swap.
"""
from mount_attestation import attest_mount, MountAttestationError
from mounted_acl_collector import collect_mounted_acl, CollectionError
from path_preflight import preflight_path, PathPreflightError

class AttestedCollectionError(RuntimeError):
    pass

def collect_attested_acl(root, relative_path, protocol, side, collector_id, identity_context,
                         *, runner=None, mountinfo_reader=None):
    def verify():
        data = mountinfo_reader() if mountinfo_reader is not None else None
        return attest_mount(root, protocol, mountinfo=data, require_exact_mount=True)
    try:
        before=verify()
        file_before=preflight_path(root, relative_path)
        result=collect_mounted_acl(root,relative_path,protocol,side,collector_id,identity_context,runner=runner)
        after=verify()
        file_after=preflight_path(root, relative_path)
    except (MountAttestationError, CollectionError, PathPreflightError, OSError) as exc:
        raise AttestedCollectionError('mount or ACL collection not qualified') from exc
    if any(before[k]!=after[k] for k in ('root','protocol','fstype','mountpoint','source','mount_id','device','mount_root')):
        raise AttestedCollectionError('mount changed during collection')
    if file_before != file_after:
        raise AttestedCollectionError("file identity or mode changed during ACL collection")
    result['path_identity'] = file_after
    result['mount_attestation'] = after
    result['limitations'] = [x for x in result['limitations'] if x != 'MOUNT_PROTOCOL_NOT_ATTESTED'] + [
        'MOUNTINFO_CHECK_ONLY_NOT_REMOTE_IDENTITY',
        'PATH_AND_MOUNT_RACES_NOT_ELIMINATED',
        'NO_EFFECTIVE_ACCESS_TEST',
        'FD_PREFLIGHT_ONLY_PATHNAME_TOOL_RACE_REMAINS',
        'FILE_STAT_CHECK_NOT_ATOMIC_WITH_ACL_TOOL']
    return result
