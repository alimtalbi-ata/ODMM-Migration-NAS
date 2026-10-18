import json
import pytest
from qualification_review_security_v2217 import review_head
from qualification_recovery_custody_v2226 import export_custody
from qualification_external_receipt_v2228 import issue_receipt, verify_external_receipt
from qualification_review_coordination_v2220 import recover_anchor_supervised
KEY=b'k'*32
CUSTODIAN_KEY=b'z'*32

def scenario(tmp_path):
    db=tmp_path/'db'; anchor=tmp_path/'anchor'; audit=tmp_path/'audit'; custody=tmp_path/'custody'; receipt=tmp_path/'receipt'
    head=review_head(db, KEY)
    record=export_custody(audit,custody,KEY)
    receipt.write_text(json.dumps(issue_receipt(record,custodian='independent-store',reference='ref-1',custodian_key=CUSTODIAN_KEY)))
    return db,anchor,audit,custody,receipt,head

def test_receipt_valid(tmp_path):
    db,anchor,audit,custody,receipt,head=scenario(tmp_path)
    assert verify_external_receipt(audit,custody,receipt,secret=KEY,custodian_key=CUSTODIAN_KEY,custodian='independent-store')['verified']

def test_receipt_tamper_blocks_recovery(tmp_path):
    db,anchor,audit,custody,receipt,head=scenario(tmp_path)
    value=json.loads(receipt.read_text());value['payload']['reference']='altered';receipt.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='EXTERNAL_CUSTODY_RECEIPT_UNVERIFIED'):
        recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac=head['head_mac'],expected_count=head['count'],audit_path=audit,operator='op',custody_path=custody,external_receipt_path=receipt,custodian_key=CUSTODIAN_KEY,custodian='independent-store')
    assert not anchor.exists()

def test_missing_receipt_blocks(tmp_path):
    db,anchor,audit,custody,receipt,head=scenario(tmp_path);receipt.unlink()
    with pytest.raises(ValueError,match='EXTERNAL_CUSTODY_RECEIPT_UNVERIFIED'):
        recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac=head['head_mac'],expected_count=head['count'],audit_path=audit,operator='op',custody_path=custody,external_receipt_path=receipt,custodian_key=CUSTODIAN_KEY,custodian='independent-store')
    assert not anchor.exists()

def test_receipt_config_requires_custodian_key(tmp_path):
    db,anchor,audit,custody,receipt,head=scenario(tmp_path)
    with pytest.raises(ValueError,match='EXTERNAL_RECEIPT_CONFIGURATION_INCOMPLETE'):
        recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac=head['head_mac'],expected_count=head['count'],audit_path=audit,operator='op',custody_path=custody,external_receipt_path=receipt)
