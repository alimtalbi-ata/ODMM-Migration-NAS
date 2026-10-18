"""ODMM V176.4 local POSIX staging proof of concept; NOT an NFS/SMB durability guarantee."""
import hashlib, os, stat
from pathlib import Path
from intent import IntentRegistry

class StagedRegistry(IntentRegistry):
    def stage_local(self, intent_id, owner, epoch, payload, *, allow_replace=False):
        """Write a complete single-range payload to a private staging file, fsync and rename.
        Restricted to offset=0 and full-file writes. Never automatically replay.
        """
        r=self.db.execute('SELECT * FROM write_intents WHERE intent_id=?',(intent_id,)).fetchone()
        if r is None: raise KeyError(intent_id)
        if r['owner']!=owner or r['epoch']!=epoch or r['state']!='PREPARED': return False
        op=self.db.execute('SELECT * FROM operations WHERE id=?',(r['operation_id'],)).fetchone()
        import time
        if not op or op['state']!='RUNNING' or op['owner']!=owner or op['epoch']!=epoch or (op['lease_until'] or 0)<=int(time.time()): return False
        if r['offset_bytes']!=0 or len(payload)!=r['length_bytes']: raise ValueError('ONLY_COMPLETE_FILE_SUPPORTED')
        if hashlib.sha256(payload).hexdigest()!=r['expected_sha256']: raise ValueError('PAYLOAD_HASH_MISMATCH')
        target=Path(r['target_path']); parent=target.parent
        if not parent.is_dir() or parent.is_symlink(): raise ValueError('UNSAFE_PARENT')
        if target.is_symlink(): raise ValueError('SYMLINK_TARGET')
        if target.exists() and not allow_replace: raise FileExistsError(target)
        stage=parent/('.odmm-'+intent_id+'.part')
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
        if hasattr(os,'O_NOFOLLOW'): flags|=os.O_NOFOLLOW
        fd=os.open(stage,flags,0o600)
        try:
            with os.fdopen(fd,'wb') as f:
                f.write(payload); f.flush(); os.fsync(f.fileno())
            # Recheck ownership before publishing. External concurrent writers require additional locking.
            current=self.db.execute('SELECT * FROM operations WHERE id=?',(r['operation_id'],)).fetchone()
            if not current or current['state']!='RUNNING' or current['owner']!=owner or current['epoch']!=epoch or (current['lease_until'] or 0)<=int(time.time()):
                return False
            if target.is_symlink(): raise ValueError('SYMLINK_TARGET')
            if target.exists() and not allow_replace: raise FileExistsError(target)
            os.replace(stage,target)
            dirfd=os.open(parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
            try: os.fsync(dirfd)
            finally: os.close(dirfd)
            return self.acknowledge_write(intent_id,owner,epoch)
        finally:
            if stage.exists(): stage.unlink()
