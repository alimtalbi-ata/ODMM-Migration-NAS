"""V187.8: fail-closed, read-only mTLS certificate rotation preflight.

This is a preflight, NOT a CA chain or revocation validator; TLS verifies peer
identity on connection. Rotation requires a separate supervised deployment.
"""
import hashlib
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from ldaps_witness_daemon import secure_file, DeploymentError

class CertificateRotationError(DeploymentError):
    pass

def inspect_candidate(*, certfile, keyfile, cafile, expected_dns, minimum_days=14, now=None):
    """Check staged PEM material without replacing any live certificate."""
    if not isinstance(expected_dns,str) or not expected_dns or not isinstance(minimum_days,int) or isinstance(minimum_days,bool) or minimum_days<0:
        raise CertificateRotationError('INVALID_POLICY')
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
        certpath=secure_file(certfile)
        keypath=secure_file(keyfile,secret=True)
        capath=secure_file(cafile)
        if len({certpath.resolve(),keypath.resolve(),capath.resolve()})!=3:
            raise CertificateRotationError('CERTIFICATE_FILES_NOT_DISTINCT')
        cert=x509.load_pem_x509_certificate(certpath.read_bytes())
        key=serialization.load_pem_private_key(keypath.read_bytes(),password=None)
        x509.load_pem_x509_certificate(capath.read_bytes())
        pub=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        expected=cert.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        if pub!=expected:
            raise CertificateRotationError('CERTIFICATE_KEY_MISMATCH')
        current=now if now is not None else datetime.now(timezone.utc)
        if current.tzinfo is None:raise CertificateRotationError('NAIVE_CLOCK')
        start=cert.not_valid_before_utc
        end=cert.not_valid_after_utc
        if current<start:raise CertificateRotationError('CERTIFICATE_NOT_YET_VALID')
        if end<=current:raise CertificateRotationError('CERTIFICATE_EXPIRED')
        if end-current<timedelta(days=minimum_days):raise CertificateRotationError('RENEWAL_WINDOW_TOO_SHORT')
        san=cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        if expected_dns not in san.get_values_for_type(x509.DNSName):
            raise CertificateRotationError('EXPECTED_DNS_MISSING')
        eku=cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            raise CertificateRotationError('SERVER_AUTH_MISSING')
        return {'status':'CANDIDATE_PREFLIGHT_OK','fingerprint_sha256':cert.fingerprint(hashes.SHA256()).hex(),
                'not_after':end.isoformat(),'dns':expected_dns,'deployment_authorized':False,
                'restart_authorized':False,'cutover_authorized':False,
                'limitations':'No CA chain, CRL, OCSP, or live handshake verification'}
    except CertificateRotationError:raise
    except Exception as exc:
        raise CertificateRotationError('CERTIFICATE_PREFLIGHT_FAILED') from exc

def supervised_rotation_plan(*, candidate, operator_confirmed, second_reviewer_confirmed):
    if candidate.get('status')!='CANDIDATE_PREFLIGHT_OK':
        raise CertificateRotationError('CANDIDATE_NOT_VERIFIED')
    if operator_confirmed is not True or second_reviewer_confirmed is not True:
        raise CertificateRotationError('TWO_REVIEWS_REQUIRED')
    return {'status':'MANUAL_ROTATION_PLAN_READY','fingerprint_sha256':candidate['fingerprint_sha256'],
            'steps':['Back up current cert/key outside the service',
                     'Verify CA chain and revocation with enterprise PKI',
                     'Stage new certificate and key with 0600 permissions',
                     'Arrange maintenance window and restart systemd service',
                     'Verify live mTLS handshake and witness ledger integrity',
                     'Rollback certificates manually if health checks fail'],
            'automatic_deployment':False,'automatic_restart':False,'cutover_authorized':False}
