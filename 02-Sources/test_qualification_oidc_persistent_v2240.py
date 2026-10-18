import json
import pytest
from qualification_jwks_persistent_v2239 import PersistentJWKSRotation
from qualification_jwks_witness_v2240 import create_witness_file, issue_witness
from qualification_oidc_persistent_v2240 import WitnessedJWKSRotation
from test_qualification_jwks_persistent_v2239 import key
from qualification_jwks_rotation_v2238 import jwks_digest

SECRET=b'K'*32

def setup(tmp_path):
    jwks={'keys':[key('a')]}
    p=dict(path=tmp_path/'keys.sqlite',issuer='https://id.example',audience='odmm',initial_jwks=jwks)
    manager=PersistentJWKSRotation(**p)
    witness=tmp_path/'independent.json'
    create_witness_file(manager.state,witness_path=witness,secret=SECRET)
    return p, witness

def test_restart_with_witness(tmp_path):
    p,w=setup(tmp_path)
    assert WitnessedJWKSRotation(witness_path=w,witness_secret=SECRET,**p).state['generation']==0

def test_missing_witness_fails(tmp_path):
    p,w=setup(tmp_path); w.unlink()
    with pytest.raises(ValueError,match='UNAVAILABLE'):
        WitnessedJWKSRotation(witness_path=w,witness_secret=SECRET,**p)

def test_tampered_witness_fails(tmp_path):
    p,w=setup(tmp_path); value=json.loads(w.read_text()); value['generation']=9; w.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='MISMATCH'):
        WitnessedJWKSRotation(witness_path=w,witness_secret=SECRET,**p)

def test_stale_witness_after_rotation_fails(tmp_path):
    p,w=setup(tmp_path); manager=PersistentJWKSRotation(**p)
    new={'keys':[p['initial_jwks']['keys'][0],key('b')]}
    manager.rotate(jwks=new,expected_generation=0,expected_sha256=jwks_digest(new),expected_previous_sha256=jwks_digest(p['initial_jwks']))
    with pytest.raises(ValueError,match='MISMATCH'):
        WitnessedJWKSRotation(witness_path=w,witness_secret=SECRET,**p)

def test_wrong_secret_fails(tmp_path):
    p,w=setup(tmp_path)
    with pytest.raises(ValueError,match='MISMATCH'):
        WitnessedJWKSRotation(witness_path=w,witness_secret=b'X'*32,**p)

def test_no_overwrite_witness(tmp_path):
    p,w=setup(tmp_path)
    with pytest.raises(ValueError,match='EXISTS'):
        create_witness_file(PersistentJWKSRotation(**p).state,witness_path=w,secret=SECRET)
