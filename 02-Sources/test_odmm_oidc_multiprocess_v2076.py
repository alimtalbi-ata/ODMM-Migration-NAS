"""Cross-process OIDC PKCE qualification. Auteur: Abdelhalim Talbi."""
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor
from urllib.parse import urlsplit,parse_qs
from odmm_oidc_transactions_v2071 import SQLitePKCETransactions
from odmm_oidc_pkce_v2068 import OIDCVerificationError

KEY=b"shared-32-byte-secret-key-for-test!"[:32]
BIND="browser-binding-unique-123456789"
def _consume(args):
    path,state=args
    try:
        result=SQLitePKCETransactions(path,key=KEY).consume(state=state,code="code",browser_binding=BIND)
        return bool(result.get("nonce"))
    except OIDCVerificationError:return False

def test_real_multiprocess_single_consumer(tmp_path):
    path=str(tmp_path/"shared.db")
    store=SQLitePKCETransactions(path,key=KEY)
    started=store.begin(authorize_endpoint="https://idp.example/authorize",client_id="odmm",redirect_uri="https://odmm.example/callback",browser_binding=BIND)
    with ProcessPoolExecutor(max_workers=6,mp_context=mp.get_context("spawn")) as pool:
        result=list(pool.map(_consume,[(path,started["state"])]*18))
    assert sum(result)==1

def test_restart_process_preserves_unconsumed_transaction(tmp_path):
    path=str(tmp_path/"shared.db")
    started=SQLitePKCETransactions(path,key=KEY).begin(authorize_endpoint="https://idp.example/authorize",client_id="odmm",redirect_uri="https://odmm.example/callback",browser_binding=BIND)
    with ProcessPoolExecutor(max_workers=1,mp_context=mp.get_context("spawn")) as pool:
        assert pool.submit(_consume,(path,started["state"])).result()
    assert not _consume((path,started["state"]))
