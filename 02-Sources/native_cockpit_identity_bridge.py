"""V193.3: trusted server-side identity mapping and externally pinned audit verification.

The web server must authenticate the session and provide claims through a private
server-to-server interface. This module never trusts browser-supplied headers.
"""
import hashlib
import hmac
import json
import re
from native_benchmark_cockpit_adapter import serve_evidence
from native_cockpit_audit_operations import verify_access_audit

HEX64 = re.compile(r'^[0-9a-f]{64}$')
ALLOWED_GROUPS = {'odmm:evidence:read': 'evidence_viewer',
                  'odmm:security:audit': 'security_auditor',
                  'odmm:admin': 'odmm_admin'}


def server_principal(claims, *, expected_issuer, expected_audience):
    """Map already-validated middleware claims; NOT an OIDC token verifier."""
    if not isinstance(claims, dict) or claims.get('server_verified') is not True:
        raise PermissionError('SERVER_VERIFICATION_REQUIRED')
    if claims.get('iss') != expected_issuer or claims.get('aud') != expected_audience:
        raise PermissionError('IDENTITY_CONTEXT_MISMATCH')
    subject = claims.get('sub')
    groups = claims.get('groups')
    if not isinstance(subject, str) or not 1 <= len(subject) <= 256 or not isinstance(groups, list):
        raise PermissionError('IDENTITY_INVALID')
    if not all(isinstance(group, str) for group in groups):
        raise PermissionError('GROUPS_INVALID')
    roles = sorted({ALLOWED_GROUPS[group] for group in groups if group in ALLOWED_GROUPS})
    if not roles:
        raise PermissionError('EVIDENCE_VIEW_DENIED')
    return {'authenticated': True, 'subject': subject, 'roles': roles}


def verify_external_anchor(db_path, anchor, *, audit_key):
    """Compare a trusted out-of-band anchor (not a local, caller-controlled file)."""
    if not isinstance(anchor, dict) or anchor.get('schema') != 'odmm.cockpit.audit.anchor.v1':
        raise ValueError('TRUSTED_ANCHOR_INVALID')
    head = anchor.get('head_sha256')
    count = anchor.get('count')
    if not isinstance(head, str) or not HEX64.fullmatch(head) or type(count) is not int or count < 0:
        raise ValueError('TRUSTED_ANCHOR_INVALID')
    # Independently verify the complete chain and its exact trusted prefix.
    # This preflight is informational: the append path rechecks the prefix under
    # BEGIN IMMEDIATE to close the verification-to-write race.
    from native_cockpit_audit_operations import verify_access_audit_prefix
    return verify_access_audit_prefix(db_path, audit_key=audit_key,
                                      checkpoint_count=count, checkpoint_head=head)


def serve_verified_evidence(manifest, *, verified_claims, issuer, audience,
                            trusted_anchor, manifest_keys, audit_db, audit_key,
                            representation='json', trusted_manifest_sha256=None):
    principal = server_principal(verified_claims, expected_issuer=issuer,
                                 expected_audience=audience)
    verify_external_anchor(audit_db, trusted_anchor, audit_key=audit_key)
    return serve_evidence(manifest, principal=principal, manifest_keys=manifest_keys,
                          audit_db=audit_db, audit_key=audit_key,
                          representation=representation,
                          trusted_manifest_sha256=trusted_manifest_sha256,
                          trusted_audit_head=trusted_anchor['head_sha256'],
                          trusted_checkpoint_count=trusted_anchor['count'])
