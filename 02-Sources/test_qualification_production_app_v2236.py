"""Deployment boundary tests; no real OIDC provider is asserted."""
import pytest
from fastapi import FastAPI
from qualification_production_app_v2236 import create_production_review_app, assert_production_route_inventory
from qualification_review_security_v2217 import write_anchor
from qualification_decisions_v2215 import review_status

S=b'production-test-secret-'*3

def auth(req):
    return {'subject':'operator','roles':['qualification:read','qualification:write','qualification:approve']}

def build(tmp_path):
    import sqlite3
    db=tmp_path/'qualification.db'; reviews=tmp_path/'reviews.db'; anchor=tmp_path/'anchor.json'
    sqlite3.connect(db).close()
    # review_head initializes journal as required by existing code
    write_anchor(reviews,anchor,S)
    return dict(authenticate=auth, db_path=db,review_db_path=reviews,
                required_checks=['check-a'],secret=S,trusted_origins=['https://odmm.example'],anchor_path=anchor)

def test_isolated_routes(tmp_path):
    app=create_production_review_app(**build(tmp_path))
    assert assert_production_route_inventory(app)
    assert app.state.odmm_production_review_isolated
    assert not any('openapi' in r.path or 'docs' in r.path for r in app.routes)

def test_tampered_anchor_fails_startup(tmp_path):
    kw=build(tmp_path)
    kw['anchor_path'].write_text('broken')
    with pytest.raises(ValueError,match='ANCHOR_UNVERIFIED'):
        create_production_review_app(**kw)

def test_missing_database_fails_startup(tmp_path):
    kw=build(tmp_path); kw['db_path'].unlink()
    with pytest.raises(ValueError,match='DATABASE_REQUIRED'):
        create_production_review_app(**kw)

def test_route_injection_detected(tmp_path):
    app=create_production_review_app(**build(tmp_path))
    app.add_api_route('/legacy/recover', lambda: {}, methods=['POST'])
    with pytest.raises(ValueError,match='ROUTE_INVENTORY_MISMATCH'):
        assert_production_route_inventory(app)

def test_missing_authenticator(tmp_path):
    kw=build(tmp_path); kw['authenticate']=None
    with pytest.raises(ValueError,match='AUTHENTICATOR_REQUIRED'):
        create_production_review_app(**kw)
