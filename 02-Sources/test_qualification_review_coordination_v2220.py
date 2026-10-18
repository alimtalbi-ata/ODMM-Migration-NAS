import tempfile
from pathlib import Path
import pytest
from fastapi import HTTPException
from qualification_review_coordination_v2220 import exclusive_lock, recover_anchor_supervised
from qualification_review_security_v2217 import review_head, verify_anchor

KEY = b'k' * 32

def test_exclusive_lock_rejects_concurrent_writer():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'review.lock'
        with exclusive_lock(path):
            with pytest.raises(HTTPException) as err:
                with exclusive_lock(path, timeout=0.01):
                    pass
            assert err.value.status_code == 503
        assert not path.exists()

def test_stale_lock_not_removed():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'review.lock'
        path.write_text('stale')
        with pytest.raises(HTTPException):
            with exclusive_lock(path, timeout=0):
                pass
        assert path.read_text() == 'stale'

def test_recovery_requires_external_confirmation():
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / 'review.sqlite'
        anchor = Path(d) / 'anchor.json'
        head = review_head(db, KEY)
        with pytest.raises(ValueError, match='CONFIRMATION_MISMATCH'):
            recover_anchor_supervised(db, anchor, secret=KEY, expected_head_mac='wrong', expected_count=0)
        assert not anchor.exists()
        result = recover_anchor_supervised(db, anchor, secret=KEY, expected_head_mac=head['head_mac'], expected_count=0)
        assert result['cutover_authorized'] is False
        assert verify_anchor(db, anchor, KEY)

def test_recovery_rejects_bool_count():
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / 'review.sqlite'
        anchor = Path(d) / 'anchor.json'
        with pytest.raises(ValueError):
            recover_anchor_supervised(db, anchor, secret=KEY, expected_head_mac='GENESIS', expected_count=False)
