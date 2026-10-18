"""Linux IPC peer process guard: read-only, fail closed, no restart/cleanup.

/proc checks are observations, not cryptographic binary attestation. Pin a trusted
executable digest and service UID; verify process start ticks to detect PID reuse.
"""
import hashlib
import os
import re
from pathlib import Path
from ldaps_ipc_active_probe import ActiveAuditProbe

class ProcessGuard:
    def __init__(self, socket_path, *, expected_uid, expected_exe_sha256, timeout=1.0):
        if not isinstance(expected_exe_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_exe_sha256):
            raise ValueError('INVALID_EXECUTABLE_DIGEST')
        self.probe = ActiveAuditProbe(socket_path, expected_uid=expected_uid, timeout=timeout)
        self.digest = expected_exe_sha256
        self.last_identity = None

    @staticmethod
    def _process(pid):
        if type(pid) is not int or pid <= 0:
            raise ValueError('INVALID_PID')
        proc = Path('/proc') / str(pid)
        # stat comm is parenthesized and can contain spaces/parentheses.
        stat = (proc / 'stat').read_text()
        end = stat.rfind(')')
        if end < 0:
            raise ValueError('INVALID_PROC_STAT')
        fields = stat[end+2:].split()
        if len(fields) < 20:
            raise ValueError('INVALID_PROC_STAT')
        start_ticks = int(fields[19])  # field 22, after pid/comm
        exe = os.readlink(proc / 'exe')
        with open(proc / 'exe', 'rb') as f:
            digest = hashlib.file_digest(f, 'sha256').hexdigest()
        # Recheck PID birth to catch replacement during executable hashing.
        second = (proc / 'stat').read_text()
        end2 = second.rfind(')')
        if end2 < 0 or int(second[end2+2:].split()[19]) != start_ticks:
            raise ValueError('PID_REUSED_DURING_PROBE')
        return (pid, start_ticks, digest, exe)

    def check(self):
        safe = {'execution_authorized': False, 'cutover_authorized': False,
                'automatic_restart': False, 'automatic_cleanup': False}
        if os.name != 'posix' or not Path('/proc/self/stat').exists():
            return dict(safe, status='LINUX_PROC_REQUIRED')
        result = self.probe.check()
        if result['status'] != 'AUDIT_ENDPOINT_RESPONSIVE':
            return dict(safe, status=result['status'])
        try:
            pid = result['peer_pid']
            identity = self._process(pid)
            if identity[2] != self.digest:
                return dict(safe, status='EXECUTABLE_DIGEST_MISMATCH')
            if self.last_identity is not None and identity[:2] != self.last_identity:
                return dict(safe, status='PEER_RESTART_REVIEW_REQUIRED', peer_pid=pid)
            self.last_identity = identity[:2]
            return dict(safe, status='PEER_PROCESS_VERIFIED', peer_pid=pid,
                        process_start_ticks=identity[1])
        except (OSError, ValueError, IndexError, PermissionError):
            return dict(safe, status='PROCESS_EVIDENCE_UNAVAILABLE')

    def accept_restart(self, *, operator_confirmed):
        if operator_confirmed is not True:
            raise ValueError('OPERATOR_CONFIRMATION_REQUIRED')
        # Explicit reset permits next check to establish a new baseline.
        self.last_identity = None
        return {'status':'RESTART_BASELINE_RESET', 'execution_authorized':False,
                'cutover_authorized':False}
