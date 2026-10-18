"""V187.9: read-only OpenSSL trust/CRL validation; fail closed. No certificate changes."""
import hashlib
import shutil
import subprocess
from pathlib import Path
from ldaps_witness_daemon import secure_file, DeploymentError

class TrustValidationError(DeploymentError):
    pass

def validate_trust(*, certfile, cafile, expected_dns, crlfile=None, intermediatefile=None, timeout=8):
    """Validate server certificate against CA with optional mandatory CRL policy.

    Without a CRL, returns explicit REVOCATION_NOT_CHECKED and cannot authorize deployment.
    """
    if not isinstance(expected_dns, str) or not expected_dns or not isinstance(timeout, (int,float)) or isinstance(timeout,bool) or not 0 < timeout <= 30:
        raise TrustValidationError('INVALID_TRUST_POLICY')
    if not shutil.which('openssl'):
        raise TrustValidationError('OPENSSL_UNAVAILABLE')
    try:
        paths=[secure_file(certfile),secure_file(cafile)]
        if crlfile is not None: paths.append(secure_file(crlfile))
        if intermediatefile is not None: paths.append(secure_file(intermediatefile))
        if len(set(p.resolve() for p in paths)) != len(paths):
            raise TrustValidationError('TRUST_FILES_NOT_DISTINCT')
        args=['openssl','verify','-purpose','sslserver','-verify_hostname',expected_dns,'-CAfile',str(paths[1])]
        if intermediatefile is not None: args+=['-untrusted',str(secure_file(intermediatefile))]
        if crlfile is not None: args+=['-CRLfile',str(secure_file(crlfile)),'-crl_check_all']
        args.append(str(paths[0]))
        result=subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
        if result.returncode != 0:
            raise TrustValidationError('CHAIN_OR_REVOCATION_REJECTED')
        return {'status':'TRUST_VALIDATED' if crlfile else 'CHAIN_VALIDATED_REVOCATION_UNKNOWN',
                'revocation':'CRL_CHECKED' if crlfile else 'NOT_CHECKED',
                'certificate_sha256':hashlib.sha256(paths[0].read_bytes()).hexdigest(),
                'deployment_authorized':False,'restart_authorized':False,'cutover_authorized':False}
    except TrustValidationError: raise
    except (OSError,subprocess.TimeoutExpired,ValueError) as exc:
        raise TrustValidationError('TRUST_VALIDATION_UNAVAILABLE') from exc

def supervised_rollback_plan(*, prior_certificate_sha256, failed_certificate_sha256, operator_confirmed, second_reviewer_confirmed):
    """Return an immutable-intent manual runbook, never act on service or files."""
    for value in (prior_certificate_sha256,failed_certificate_sha256):
        if not isinstance(value,str) or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
            raise TrustValidationError('INVALID_FINGERPRINT')
    if prior_certificate_sha256==failed_certificate_sha256:
        raise TrustValidationError('IDENTICAL_CERTIFICATES')
    if operator_confirmed is not True or second_reviewer_confirmed is not True:
        raise TrustValidationError('TWO_REVIEWS_REQUIRED')
    return {'status':'MANUAL_ROLLBACK_PLAN_READY','prior_certificate_sha256':prior_certificate_sha256,
            'failed_certificate_sha256':failed_certificate_sha256,
            'steps':['Freeze new witness publications','Check independently held witness ledger integrity',
                     'Verify archived certificate trust, CRL and key under supervision',
                     'Restore prior certificate and key in a maintenance window',
                     'Restart service manually and test live mTLS',
                     'Verify independent witness state and preserve incident evidence'],
            'automatic_rollback':False,'automatic_restart':False,'deployment_authorized':False,'cutover_authorized':False}
