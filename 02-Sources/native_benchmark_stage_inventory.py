"""V192.7 read-only forensic inventory for interrupted evidence publication."""
import hashlib
import os
import stat
from pathlib import Path
from native_benchmark_evidence import snapshot_evidence

PREFIX = '.odmm-stage-'
MAX_ITEMS = 1000
MAX_STAGE_BYTES = 20_000_000

def inventory_stages(directory):
    """Inspect without following symbolic links, deleting, or modifying stages."""
    path = Path(os.path.abspath(directory))
    parts = path.parts
    fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        names = sorted(n for n in os.listdir(fd) if n.startswith(PREFIX))
        if len(names) > MAX_ITEMS:
            raise ValueError('STAGE_INVENTORY_LIMIT')
        entries = []
        for name in names:
            # Never open a symbolic link or nonregular entry; include its existence.
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            entry = {'name': name, 'bytes': info.st_size, 'status': 'UNSAFE_TYPE', 'sha256': None}
            if stat.S_ISREG(info.st_mode) and info.st_size <= MAX_STAGE_BYTES:
                try:
                    item_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    try:
                        opened = os.fstat(item_fd)
                        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                            entry['status'] = 'RACED'
                        else:
                            h = hashlib.sha256(); size = 0
                            while True:
                                data = os.read(item_fd, 65536)
                                if not data: break
                                size += len(data)
                                if size > MAX_STAGE_BYTES: break
                                h.update(data)
                            if size <= MAX_STAGE_BYTES and size == opened.st_size:
                                entry.update(status='PRESERVED', sha256=h.hexdigest(), bytes=size)
                            else: entry['status'] = 'SIZE_CHANGED_OR_EXCEEDED'
                    finally: os.close(item_fd)
                except (OSError, ValueError): entry['status'] = 'UNREADABLE_OR_RACED'
            elif stat.S_ISREG(info.st_mode): entry['status'] = 'TOO_LARGE'
            entries.append(entry)
        return {'schema': 'odmm.benchmark.stage_inventory.v1', 'status': 'REVIEW_REQUIRED' if entries else 'CLEAR',
                'entries': entries, 'count': len(entries), 'cleanup_authorized': False,
                'mutations_performed': False, 'cutover_authorized': False}
    finally: os.close(fd)

def cockpit_evidence_payload(journal, directory, *, keys, trusted_head=None):
    """Backend-ready read-only payload; not a deployed web route."""
    evidence = snapshot_evidence(journal, keys=keys, trusted_head=trusted_head)
    try: stages = inventory_stages(directory)
    except (OSError, ValueError):
        stages = {'schema': 'odmm.benchmark.stage_inventory.v1', 'status': 'BLOCKED', 'entries': [],
                  'count': None, 'cleanup_authorized': False, 'mutations_performed': False, 'cutover_authorized': False}
    return {'schema': 'odmm.cockpit.evidence.v1', 'evidence': evidence, 'stages': stages,
            'status': 'BLOCKED' if evidence['status'] == 'BLOCKED' or stages['status'] == 'BLOCKED' else
                      'REVIEW_REQUIRED' if stages['status'] == 'REVIEW_REQUIRED' else evidence['status'],
            'requires_human_review': stages['status'] != 'CLEAR' or evidence['status'] == 'BLOCKED',
            'cleanup_authorized': False, 'cutover_authorized': False}
