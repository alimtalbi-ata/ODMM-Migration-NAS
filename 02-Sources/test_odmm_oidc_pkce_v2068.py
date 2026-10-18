import base64,hashlib,json,time
from urllib.parse import urlsplit,parse_qs
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
from odmm_oidc_pkce_v2068 import PKCETransactions,verify_id_token,OIDCVerificationError,_b64

@pytest.fixture
def signed():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048);pub=key.public_key().public_numbers()
    jwks={'keys':[{'kty':'RSA','kid':'test','use':'sig','alg':'RS256','n':_b64(pub.n.to_bytes((pub.n.bit_length()+7)//8,'big')),'e':_b64(pub.e.to_bytes((pub.e.bit_length()+7)//8,'big'))}]}
    def make(**overrides):
        claims={'iss':'https://idp.example','aud':'odmm','sub':'user1','nonce':'n'*20,'iat':1000,'exp':1400,'groups':['odmm-admin']};claims.update(overrides)
        data=_b64(json.dumps({'alg':'RS256','kid':'test'}).encode())+'.'+_b64(json.dumps(claims).encode())
        sig=key.sign(data.encode(),padding.PKCS1v15(),hashes.SHA256())
        return data+'.'+_b64(sig)
    return make,jwks

def test_pkce_and_replay():
    store=PKCETransactions(clock=lambda:1000)
    result=store.begin(authorize_endpoint='https://idp.example/authorize',client_id='odmm',redirect_uri='https://odmm.example/callback')
    q=parse_qs(urlsplit(result['url']).query)
    assert q['code_challenge_method']==['S256'] and len(q['nonce'][0])>=16
    txn=store.consume(state=result['state'],code='code123')
    assert _b64(hashlib.sha256(txn['code_verifier'].encode()).digest())==q['code_challenge'][0]
    assert txn['nonce']==q['nonce'][0]
    with pytest.raises(OIDCVerificationError):store.consume(state=result['state'],code='code123')

def test_expired_state():
    t=[1000];s=PKCETransactions(clock=lambda:t[0],ttl=30);r=s.begin(authorize_endpoint='https://idp.example/auth',client_id='odmm',redirect_uri='https://odmm.example/callback');t[0]=1031
    with pytest.raises(OIDCVerificationError):s.consume(state=r['state'],code='x')

def test_verify_signature_and_claims(signed):
    make,jwks=signed
    assert verify_id_token(make(),jwks=jwks,issuer='https://idp.example',audience='odmm',nonce='n'*20,clock=lambda:1100)['sub']=='user1'
    for override in ({'nonce':'wrong'},{'iss':'https://evil.example'},{'aud':'other'},{'exp':1001},{'iat':1500},{'sub':''},{'aud':['odmm','other']},{'nbf':1300}):
        with pytest.raises(OIDCVerificationError):verify_id_token(make(**override),jwks=jwks,issuer='https://idp.example',audience='odmm',nonce='n'*20,clock=lambda:1100)

def test_tamper_and_algorithm(signed):
    make,jwks=signed;token=make();parts=token.split('.')
    for bad in [parts[0]+'.'+_b64(b'{"sub":"attacker"}')+'.'+parts[2],token[:-3]+'abc','abc.def.ghi']:
        with pytest.raises(OIDCVerificationError):verify_id_token(bad,jwks=jwks,issuer='https://idp.example',audience='odmm',nonce='n'*20,clock=lambda:1100)
    header=_b64(json.dumps({'alg':'none','kid':'test'}).encode())
    with pytest.raises(OIDCVerificationError):verify_id_token(header+'.'+parts[1]+'.'+parts[2],jwks=jwks,issuer='https://idp.example',audience='odmm',nonce='n'*20,clock=lambda:1100)

def test_unknown_key(signed):
    make,jwks=signed
    with pytest.raises(OIDCVerificationError):verify_id_token(make(),jwks={'keys':[]},issuer='https://idp.example',audience='odmm',nonce='n'*20,clock=lambda:1100)

def test_verified_token_to_session(signed,tmp_path):
    from odmm_session_registry_v2062 import SessionRegistry
    from odmm_oidc_pkce_v2068 import verified_id_token_to_session
    make,jwks=signed
    registry=SessionRegistry(tmp_path/'sessions.db',key=b'K'*32,clock=lambda:1100)
    token=verified_id_token_to_session(registry,make(),jwks=jwks,issuer='https://idp.example',audience='odmm',nonce='n'*20,clock=lambda:1100)
    assert registry.resolve(token)=={'actor':'https://idp.example|user1','role':'admin'}
