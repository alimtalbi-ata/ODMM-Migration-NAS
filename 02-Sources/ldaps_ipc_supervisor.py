"""Fail-closed local IPC process supervisor and restart evidence.

This is an observation/control primitive, not a daemon manager. It never
removes a stale socket and never starts an unverified service automatically.
"""
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from ldaps_ipc_boundary import IPCBoundaryError


class AuditIPCSupervisor:
    def __init__(self, socket_path, *, expected_uid, max_heartbeat_age=30):
        if type(expected_uid) is not int or expected_uid < 0:
            raise IPCBoundaryError('INVALID_EXPECTED_UID')
        if type(max_heartbeat_age) is not int or max_heartbeat_age < 1:
            raise IPCBoundaryError('INVALID_HEARTBEAT_AGE')
        self.path = Path(socket_path)
        self.uid = expected_uid
        self.max_age = max_heartbeat_age

    def inspect(self, *, now=None):
        if now is None:
            now = int(time.time())
        if type(now) is not int or now < 0:
            raise IPCBoundaryError('INVALID_OBSERVATION_TIME')
        try:
            st = os.lstat(self.path)
        except FileNotFoundError:
            return self._result('SOCKET_ABSENT', None, now)
        except OSError:
            return self._result('SOCKET_UNREADABLE_MANUAL_REVIEW', None, now)
        evidence = {'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,
                    'mode':stat.S_IMODE(st.st_mode),'mtime_ns':st.st_mtime_ns,
                    'is_socket':stat.S_ISSOCK(st.st_mode)}
        if not evidence['is_socket']:
            status = 'PATH_NOT_SOCKET_MANUAL_REVIEW'
        elif st.st_uid != self.uid or st.st_mode & 0o077:
            status = 'SOCKET_SECURITY_INVALID_MANUAL_REVIEW'
        elif st.st_mtime > now + 1:
            status = 'SOCKET_CLOCK_ANOMALY_MANUAL_REVIEW'
        elif now - st.st_mtime > self.max_age:
            status = 'SOCKET_AGE_UNCERTAIN_MANUAL_REVIEW'
        else:
            # A socket's mtime does not prove process liveness.
            status = 'SOCKET_PRESENT_LIVENESS_UNVERIFIED'
        return self._result(status, evidence, now)

    def _result(self, status, evidence, now):
        report = {'schema':1,'status':status,'socket_path':str(self.path),
                  'expected_uid':self.uid,'observed_at':now,'evidence':evidence,
                  'review_allowed':False,'execution_authorized':False,
                  'cutover_authorized':False,'automatic_cleanup':False}
        report['sha256'] = hashlib.sha256(json.dumps(report,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return report

    def confirm_stale(self, *, report, operator_confirmed, now=None):
        """Read-only manual review: detect replacement/replay, never unlink."""
        if operator_confirmed is not True:
            raise IPCBoundaryError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if not isinstance(report,dict) or report.get('schema') != 1:
            raise IPCBoundaryError('INVALID_SUPERVISOR_REPORT')
        signed = {k:v for k,v in report.items() if k != 'sha256'}
        digest = hashlib.sha256(json.dumps(signed,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if digest != report.get('sha256'):
            raise IPCBoundaryError('SUPERVISOR_REPORT_TAMPERED')
        current = self.inspect(now=now)
        if current['socket_path'] != report['socket_path'] or current['expected_uid'] != report['expected_uid']:
            raise IPCBoundaryError('SUPERVISOR_SCOPE_CHANGED')
        if current['evidence'] != report['evidence']:
            raise IPCBoundaryError('SOCKET_CHANGED_SINCE_INSPECTION')
        if current['observed_at'] < report['observed_at']:
            raise IPCBoundaryError('SUPERVISOR_CLOCK_ROLLBACK')
        if current['status'] == 'SOCKET_PRESENT_LIVENESS_UNVERIFIED':
            raise IPCBoundaryError('SOCKET_NOT_STALE')
        return {'status':'MANUAL_INVESTIGATION_REQUIRED','socket_path':str(self.path),
                'automatic_cleanup':False,'execution_authorized':False,'cutover_authorized':False}
