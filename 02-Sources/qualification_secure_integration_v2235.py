"""Production entry points for custody and review; author Abdelhalim Talbi.

Deployment must expose these wrappers exclusively; Python cannot prevent imports of
legacy functions in other code. Custody evidence must live outside this host.
"""
from pathlib import Path
from qualification_review_portal_v2216 import attach_review_portal
from qualification_review_coordination_v2220 import recover_anchor_supervised
from qualification_rotation_workflow_v2234 import guarded_recovery_rotation
from qualification_witness_rotation_v2232 import rotation_status


def attach_production_review_portal(app, *, trusted_origins, anchor_path, **kwargs):
    """Reject insecure portal configuration instead of silently downgrading."""
    if not isinstance(trusted_origins, (tuple, list, set)) or not trusted_origins:
        raise ValueError('PRODUCTION_TRUSTED_ORIGINS_REQUIRED')
    if any(not isinstance(o, str) or not o.startswith('https://') or '/' in o[8:] for o in trusted_origins):
        raise ValueError('PRODUCTION_ORIGIN_INVALID')
    if not anchor_path or not Path(anchor_path).is_file():
        raise ValueError('PRODUCTION_ANCHOR_REQUIRED')
    if 'strict_approval' in kwargs:
        raise ValueError('PRODUCTION_STRICT_APPROVAL_IMMUTABLE')
    return attach_review_portal(app, trusted_origins=tuple(trusted_origins),
                                anchor_path=anchor_path, strict_approval=True, **kwargs)


def recover_production_anchor(db_path, anchor_path, *, custody_ack_path, custody_witness_path,
                              custody_path, audit_path, external_receipt_path, custodian_key,
                              custodian, operator, **kwargs):
    """Require all custody inputs for production recovery, never bypass verification."""
    mandatory = (custody_ack_path, custody_witness_path, custody_path, audit_path,
                 external_receipt_path, custodian_key, custodian, operator)
    if any(not value for value in mandatory):
        raise ValueError('PRODUCTION_CUSTODY_CONFIGURATION_REQUIRED')
    if 'secure_custody' in kwargs:
        raise ValueError('PRODUCTION_SECURE_CUSTODY_IMMUTABLE')
    return recover_anchor_supervised(db_path, anchor_path, custody_ack_path=custody_ack_path,
        custody_witness_path=custody_witness_path, custody_path=custody_path,
        audit_path=audit_path, external_receipt_path=external_receipt_path,
        custodian_key=custodian_key, custodian=custodian, operator=operator,
        secure_custody=True, **kwargs)


def rotate_production_witness(current, candidate, rotation_path, *, independent_current_witness,
                              independent_ack_sha256, secret):
    """Refuse non-committed transitions; serialized guard does the actual commit."""
    if not independent_current_witness or not independent_ack_sha256:
        raise ValueError('PRODUCTION_INDEPENDENT_ACK_REQUIRED')
    return guarded_recovery_rotation(current, candidate, rotation_path, secret=secret,
        independent_current_witness=independent_current_witness,
        independent_ack_sha256=independent_ack_sha256)
