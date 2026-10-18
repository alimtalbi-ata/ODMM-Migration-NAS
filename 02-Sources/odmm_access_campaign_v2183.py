"""Isolated read-only access campaign, launched by operator under dedicated OS account.
No setuid, sudo, password handling or cutover authorization. Author: Abdelhalim Talbi.
"""
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from odmm_live_access_v2182 import AccessCase, LiveAccessError, run_readonly_case

MAX_CASES=100
MAX_BYTES=1024*1024


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def run_isolated_campaign(cases, *, timeout_seconds=30):
    """Run each case in fresh subprocess under *same* verified OS identity.

    For a dedicated account, invoke the parent process under that account;
    this function deliberately never impersonates or elevates privileges.
    """
    cases=list(cases)
    if not cases or len(cases)>MAX_CASES or any(not isinstance(c,AccessCase) for c in cases):
        raise LiveAccessError('INVALID_CAMPAIGN')
    if len({c.case_id for c in cases}) != len(cases):
        raise LiveAccessError('DUPLICATE_CASE')
    if not isinstance(timeout_seconds,(int,float)) or isinstance(timeout_seconds,bool) or not 0<timeout_seconds<=300:
        raise LiveAccessError('INVALID_TIMEOUT')
    runner=Path(__file__).with_name('odmm_access_campaign_worker_v2183.py')
    results=[]
    for case in cases:
        payload=_canonical(asdict(case))
        if len(payload)>MAX_BYTES:
            raise LiveAccessError('OVERSIZED_CASE')
        try:
            completed=subprocess.run([sys.executable, '-I', str(runner)], input=payload,
                capture_output=True, timeout=timeout_seconds, check=False,
                env={'PATH':'/usr/bin:/bin','PYTHONIOENCODING':'utf-8'}, cwd=str(runner.parent))
        except (subprocess.TimeoutExpired,OSError) as exc:
            raise LiveAccessError('WORKER_UNAVAILABLE') from exc
        if completed.returncode or len(completed.stdout)>MAX_BYTES:
            raise LiveAccessError('WORKER_FAILED_CLOSED')
        try:
            record=json.loads(completed.stdout)
            if record['report']['case_id']!=case.case_id or record['report']['execution_euid']!=case.expected_euid or record['report']['execution_egid']!=case.expected_egid:
                raise ValueError('identity mismatch')
            if hashlib.sha256(_canonical(record['report'])).hexdigest()!=record['sha256']:
                raise ValueError('digest mismatch')
            if record['report']['cutover_authorized'] is not False:
                raise ValueError('unsafe authorization')
        except (ValueError,KeyError,TypeError) as exc:
            raise LiveAccessError('INVALID_WORKER_EVIDENCE') from exc
        results.append(record)
    report={'schema':'odmm.isolated-access-campaign.v2183', 'execution_euid':os.geteuid(),
            'execution_egid':os.getegid(), 'cases':results,
            'all_local_outcomes_equal':all(r['report']['local_open_outcomes_equal'] for r in results),
            'dedicated_account_attested':False, 'nas_qualified':False,'cutover_authorized':False,
            'limitations':['NO_IMPERSONATION','NO_REMOTE_AD_LDAP_AUTHENTICATION','LOCAL_MOUNT_ONLY']}
    return {'report':report,'sha256':hashlib.sha256(_canonical(report)).hexdigest()}
