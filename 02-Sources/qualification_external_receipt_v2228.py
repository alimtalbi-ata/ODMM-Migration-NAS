"""Verify a separately retained custody receipt. Author: Abdelhalim Talbi.

A receipt is only useful when issued and retained by an independent trusted custodian.
This module validates an HMAC receipt; it does not provide remote storage.
"""
import hashlib
import hmac
import json
from pathlib import Path
from qualification_recovery_custody_v2226 import verify_custody

DOMAIN = b'ODMM-EXTERNAL-CUSTODY-RECEIPT-V2228\0'

def receipt_payload(custody_record, *, custodian, reference):
    if not isinstance(custodian, str) or not custodian.strip() or not isinstance(reference, str) or not reference.strip():
        raise ValueError('INVALID_CUSTODIAN_REFERENCE')
    return {'schema': 'odmm.external.receipt.v2228', 'custodian': custodian,
            'reference': reference, 'custody_sha256': hashlib.sha256(
                json.dumps(custody_record, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}

def issue_receipt(custody_record, *, custodian, reference, custodian_key):
    """For test/independent custodian side ONLY, not for production application issuance."""
    payload = receipt_payload(custody_record, custodian=custodian, reference=reference)
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    return {'payload': payload, 'mac': hmac.new(custodian_key, DOMAIN + raw, hashlib.sha256).hexdigest()}

def verify_external_receipt(audit_path, custody_path, receipt_path, *, secret, custodian_key, custodian):
    verify_custody(audit_path, custody_path, secret)
    try:
        custody = json.loads(Path(custody_path).read_text())
        receipt = json.loads(Path(receipt_path).read_text())
        if not isinstance(receipt, dict) or set(receipt) != {'payload', 'mac'}:
            raise ValueError()
        p = receipt['payload']
        if not isinstance(p, dict) or set(p) != {'schema', 'custodian', 'reference', 'custody_sha256'} or p['schema'] != 'odmm.external.receipt.v2228' or p['custodian'] != custodian:
            raise ValueError()
        expected = receipt_payload(custody, custodian=p['custodian'], reference=p['reference'])
        if p != expected or not isinstance(receipt['mac'], str):
            raise ValueError()
        raw = json.dumps(p, sort_keys=True, separators=(',', ':')).encode()
        if not hmac.compare_digest(receipt['mac'], hmac.new(custodian_key, DOMAIN + raw, hashlib.sha256).hexdigest()):
            raise ValueError()
        return {'verified': True, 'custodian': custodian, 'reference': p['reference']}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ValueError('EXTERNAL_CUSTODY_RECEIPT_UNVERIFIED') from exc
