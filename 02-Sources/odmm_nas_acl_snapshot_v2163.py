"""Read-only transactionally consistent, fully verified ACL history page.
Author: Abdelhalim Talbi. Local SQLite only; external CAS anchor must be checked by caller.
"""
import hashlib
import hmac
import json
from contextlib import closing
from odmm_nas_acl_export_v2148 import verify_export


def verified_snapshot_page(history, *, cursor=0, limit=50, batch_size=256):
    if type(cursor) is not int or cursor < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('INVALID_PAGE')
    if type(batch_size) is not int or not 1 <= batch_size <= 4096:
        raise ValueError('INVALID_BATCH_SIZE')
    with closing(history._db()) as db:
        db.execute('BEGIN')  # WAL read snapshot: writers may append, view remains stable.
        head = db.execute('SELECT seq,chain_mac FROM acl_audit_history ORDER BY seq DESC LIMIT 1').fetchone()
        expected_seq, previous = 1, 'GENESIS'
        scan = db.execute('SELECT seq,digest,previous,chain_mac,report FROM acl_audit_history ORDER BY seq')
        while True:
            rows = scan.fetchmany(batch_size)
            if not rows: break
            for seq,digest,prev,mac,raw in rows:
                if seq != expected_seq or prev != previous:
                    raise ValueError('AUDIT_SEQUENCE_OR_LINK_INVALID')
                if not hmac.compare_digest(hashlib.sha256(raw.encode()).hexdigest(), digest):
                    raise ValueError('AUDIT_DIGEST_INVALID')
                expected = hmac.new(history.key, (prev+'|'+digest).encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, mac):
                    raise ValueError('AUDIT_HMAC_INVALID')
                try:
                    if not verify_export(json.loads(raw), history.key):
                        raise ValueError('AUDIT_SIGNATURE_INVALID')
                except (TypeError, KeyError, json.JSONDecodeError) as exc:
                    raise ValueError('AUDIT_REPORT_INVALID') from exc
                expected_seq += 1
                previous = mac
        if head and (expected_seq - 1 != head[0] or previous != head[1]):
            raise ValueError('AUDIT_HEAD_INVALID')
        page_rows = db.execute('SELECT seq,report FROM acl_audit_history WHERE seq>? ORDER BY seq LIMIT ?', (cursor, limit+1)).fetchall()
        items=[]
        for seq, raw in page_rows[:limit]:
            doc=json.loads(raw)
            items.append({'seq':seq,'protocol':doc.get('protocol'),'report_count':len(doc.get('reports',[])),'cutover_authorized':False})
        more=len(page_rows)>limit
        result={'schema':'odmm.nas.acl.snapshot.v2163','items':items,
                'next_cursor':items[-1]['seq'] if more and items else None,
                'verified_head_seq':head[0] if head else 0,
                'verified_head_mac':head[1] if head else 'GENESIS',
                'integrity_valid':True,'cutover_authorized':False,
                'external_anchor_verified':False}
        db.execute('COMMIT')
        return result
