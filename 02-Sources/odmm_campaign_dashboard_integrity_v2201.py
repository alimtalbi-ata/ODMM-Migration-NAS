"""Fail-closed dashboard consistency checks. Author: Abdelhalim Talbi."""
import re
from odmm_access_audit_v2184 import AuditError

_HEX = re.compile(r'^[0-9a-f]{64}$')

def validate_dashboard(report):
    if not isinstance(report, dict) or report.get('schema') != 'odmm.campaign-dashboard.v2196':
        raise AuditError('INVALID_DASHBOARD_SCHEMA')
    if report.get('anchored') is not True or report.get('cutover_authorized') is not False or report.get('nas_qualified') is not False:
        raise AuditError('UNSAFE_DASHBOARD_STATE')
    if not isinstance(report.get('audit_head'), str) or not _HEX.fullmatch(report['audit_head']):
        raise AuditError('INVALID_AUDIT_HEAD')
    cases = report.get('cases')
    if not isinstance(cases, list) or any(type(report.get(k)) is not int or report[k] < 0 for k in ('entries','case_count','mismatch_count')):
        raise AuditError('INVALID_DASHBOARD_COUNTERS')
    if report['case_count'] != len(cases):
        raise AuditError('CASE_COUNT_MISMATCH')
    mismatch_count = 0
    for case in cases:
        if not isinstance(case, dict) or type(case.get('seq')) is not int or case['seq'] < 1 or case['seq'] > report['entries']:
            raise AuditError('INVALID_CASE_SEQUENCE')
        if any(not isinstance(case.get(k),str) or not case[k] for k in ('case_id','identity_ref')):
            raise AuditError('INVALID_CASE_IDENTITY')
        if any(type(case.get(k)) is not bool for k in ('groups_equal','local_access_equal','mismatch')):
            raise AuditError('INVALID_CASE_FLAGS')
        expected = not (case['groups_equal'] and case['local_access_equal'])
        if case['mismatch'] != expected:
            raise AuditError('CASE_MISMATCH_INCONSISTENT')
        mismatch_count += expected
    if report['mismatch_count'] != mismatch_count:
        raise AuditError('MISMATCH_COUNT_INCONSISTENT')
    return report
