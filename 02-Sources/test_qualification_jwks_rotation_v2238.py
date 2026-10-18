import base64
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from qualification_jwks_rotation_v2238 import PinnedJWKSRotation, jwks_digest

def jwk(kid, key):
    p=key.public_key().public_numbers()
    b=lambda n:base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8,'big')).rstrip(b'=').decode()
    return {'kty':'RSA','kid':kid,'alg':'RS256','n':b(p.n),'e':b(p.e)}

@pytest.fixture
def fixture():
    a=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    b=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    one={'keys':[jwk('old',a)]}; both={'keys':[jwk('old',a),jwk('new',b)]}
    manager=PinnedJWKSRotation(issuer='https://id.example',audience='odmm',jwks=one)
    return manager,one,both,a,b

def rotate(m, old, new, **kwargs):
    return m.rotate(jwks=new,expected_generation=m.state['generation'],expected_previous_sha256=jwks_digest(old),expected_sha256=jwks_digest(new),**kwargs)

def test_overlap_success(fixture):
    m,one,both,*_=fixture
    assert rotate(m,one,both)['generation']==1
    assert m.state['key_count']==2

def test_drop_old_key_rejected(fixture):
    m,one,both,*_=fixture
    with pytest.raises(ValueError,match='OVERLAP'):
        rotate(m,one,{'keys':[both['keys'][1]]})
    assert m.state['generation']==0

def test_stale_generation_rejected(fixture):
    m,one,both,*_=fixture
    with pytest.raises(ValueError,match='STALE'):
        m.rotate(jwks=both,expected_generation=3,expected_previous_sha256=jwks_digest(one),expected_sha256=jwks_digest(both))

def test_digest_mismatch_rejected(fixture):
    m,one,both,*_=fixture
    with pytest.raises(ValueError,match='DIGEST'):
        m.rotate(jwks=both,expected_generation=0,expected_previous_sha256=jwks_digest(one),expected_sha256='0'*64)

def test_kid_reuse_rejected(fixture):
    m,one,both,a,b=fixture
    with pytest.raises(ValueError,match='KID_REUSE'):
        rotate(m,one,{'keys':[jwk('old',b)]})

def test_invalid_candidate_preserves_state(fixture):
    m,one,both,*_=fixture
    invalid={'keys':[{'kid':'bad','kty':'oct'}]}
    with pytest.raises(ValueError): rotate(m,one,invalid)
    assert m.state['jwks_sha256']==jwks_digest(one)

def test_retire_requires_explicit_no_overlap(fixture):
    m,one,both,*_=fixture
    rotate(m,one,both)
    new_only={'keys':[both['keys'][1]]}
    assert rotate(m,both,new_only,require_overlap=False)['generation']==2
