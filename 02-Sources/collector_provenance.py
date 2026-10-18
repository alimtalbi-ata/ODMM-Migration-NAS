"""Offline authenticated evidence envelopes; shared-key trust is explicitly limited."""
import hashlib, hmac, json, sqlite3, time
from protocol_evidence import canonical_json, normalize_acl_capture

class EvidenceRejected(ValueError): pass

def sign_capture(capture, collector_id, nonce, issued_at, key):
    normalize_acl_capture(capture)
    if not isinstance(collector_id,str) or not collector_id.strip() or not isinstance(nonce,str) or len(nonce)<16 or type(issued_at) is not int:
        raise EvidenceRejected('invalid envelope metadata')
    if not isinstance(key,bytes) or len(key)<32: raise EvidenceRejected('weak signing key')
    payload={'schema':'odmm.collector-envelope.v1','capture':capture,'collector_id':collector_id,'nonce':nonce,'issued_at':issued_at}
    payload['hmac_sha256']=hmac.new(key,canonical_json(payload),hashlib.sha256).hexdigest()
    return payload

class ProvenanceRegistry:
    def __enter__(self): return self
    def __exit__(self,exc_type,exc,tb): self.close()
    def __init__(self, db_path, keys, max_age=300):
        self.db=sqlite3.connect(db_path,timeout=10,isolation_level=None)
        self.db.execute('PRAGMA busy_timeout=10000')
        self.db.execute('CREATE TABLE IF NOT EXISTS seen_envelopes (collector_id TEXT NOT NULL, nonce TEXT NOT NULL, digest TEXT NOT NULL, accepted_at INTEGER NOT NULL, PRIMARY KEY(collector_id,nonce))')
        self.keys=keys; self.max_age=max_age
    def close(self): self.db.close()
    def verify_and_record(self,envelope,now=None):
        if not isinstance(envelope,dict): raise EvidenceRejected('invalid envelope')
        required={'schema','capture','collector_id','nonce','issued_at','hmac_sha256'}
        if set(envelope)!=required or envelope['schema']!='odmm.collector-envelope.v1': raise EvidenceRejected('schema mismatch')
        collector=envelope['collector_id']; key=self.keys.get(collector) if isinstance(collector,str) else None
        if not isinstance(key,bytes) or len(key)<32: raise EvidenceRejected('untrusted collector')
        if not isinstance(envelope['nonce'],str) or len(envelope['nonce'])<16 or type(envelope['issued_at']) is not int: raise EvidenceRejected('invalid metadata')
        now=int(time.time()) if now is None else now
        if abs(now-envelope['issued_at'])>self.max_age: raise EvidenceRejected('stale evidence')
        digest=envelope['hmac_sha256']
        if not isinstance(digest,str) or len(digest)!=64: raise EvidenceRejected('invalid signature')
        signed={k:v for k,v in envelope.items() if k!='hmac_sha256'}
        expected=hmac.new(key,canonical_json(signed),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected,digest): raise EvidenceRejected('signature mismatch')
        normalized=normalize_acl_capture(envelope['capture'])
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('INSERT INTO seen_envelopes VALUES (?,?,?,?)',(collector,envelope['nonce'],digest,now))
            self.db.execute('COMMIT')
        except sqlite3.IntegrityError as exc:
            self.db.execute('ROLLBACK'); raise EvidenceRejected('replayed nonce') from exc
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
        return {'status':'AUTHENTICATED_ENVELOPE_ONLY','collector_id':collector,'evidence_sha256':normalized['evidence_sha256'],'effective_access_certified':False,'limitations':['SHARED_KEY_NOT_HARDWARE_ATTESTATION','NO_NAS_ACCESS_PROOF','NO_EFFECTIVE_ACCESS_PROBE']}
