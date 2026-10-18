import sqlite3
from datetime import datetime,timezone
import pytest
from odmm_collector_registry_v2092 import ExternalKeyRegistry
from odmm_trust_v2091 import ExternalSecretResolver
from odmm_netapp_collector_v2089 import sign_envelope,CollectorError

KEY=b'K'*32

def setup(tmp_path):
    backend={('node','key1'):KEY,('node','key2'):b'B'*32}
    reg=ExternalKeyRegistry(tmp_path/'external.db',ExternalSecretResolver(lambda c,k:backend[(c,k)]))
    reg.register_key_ref('node','key1')
    return reg,backend

def envelope(kid='key1',nonce='unique',key=KEY):
    return sign_envelope({'ok':True},collector_id='node',key_id=kid,secret=key,nonce=nonce,issued_at=datetime.now(timezone.utc).isoformat())

def test_accept_replay_and_restart(tmp_path):
    reg,backend=setup(tmp_path)
    assert reg.verify_once(envelope())=={'ok':True}
    again=ExternalKeyRegistry(tmp_path/'external.db',reg.resolver)
    with pytest.raises(CollectorError,match='REPLAY_DETECTED'):again.verify_once(envelope())

def test_no_secret_in_db(tmp_path):
    reg,_=setup(tmp_path)
    assert KEY not in (tmp_path/'external.db').read_bytes()
    with sqlite3.connect(reg.path) as db:
        assert 'keys' not in {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}

def test_rotation_and_revocation(tmp_path):
    reg,backend=setup(tmp_path)
    reg.register_key_ref('node','key2')
    reg.revoke_key('node','key1')
    with pytest.raises(CollectorError,match='UNKNOWN_OR_REVOKED_KEY'):reg.verify_once(envelope())
    assert reg.verify_once(envelope('key2','second',backend[('node','key2')]))=={'ok':True}

def test_backend_outage_fails_closed(tmp_path):
    reg,backend=setup(tmp_path)
    backend.clear()
    with pytest.raises(CollectorError,match='SECRET_BACKEND_UNAVAILABLE'):reg.verify_once(envelope())

def test_legacy_database_rejected(tmp_path):
    path=tmp_path/'old.db'
    with sqlite3.connect(path) as db:db.execute('CREATE TABLE keys(secret BLOB)')
    with pytest.raises(CollectorError,match='LEGACY_SECRET_DATABASE'):ExternalKeyRegistry(path,ExternalSecretResolver(lambda c,k:KEY))

def test_secret_api_disabled(tmp_path):
    reg,_=setup(tmp_path)
    with pytest.raises(CollectorError,match='SECRET_STORAGE_FORBIDDEN'):reg.register_key('node','x',KEY)
