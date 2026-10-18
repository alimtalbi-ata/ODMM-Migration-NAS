"""HTTP integration regression for V216.5 composition root."""
import tempfile
from pathlib import Path
from unittest.mock import patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_operations_security import Principal
from odmm_operations_app import create_nas_acl_cas_operations_app
from test_odmm_nas_acl_snapshot_v2163 import KEY, document


def test_composition_http_auth_anchor_and_tamper():
    with tempfile.TemporaryDirectory() as tmp:
        anchor = [None]
        def read_anchor(): return anchor[0]
        def cas_anchor(expected, replacement):
            if anchor[0] != expected: return False
            anchor[0] = replacement
            return True
        def resolver(request):
            role = request.headers.get('x-test-role', 'viewer')
            return Principal(subject='test', roles=frozenset({role}), verified=True)
        noop = lambda *a, **kw: None
        patches = [patch('odmm_operations_app.create_nas_integrated_operations_app',return_value=FastAPI())]
        for module, name in [('odmm_nas_acl_portal_v2147','attach_acl_audit_portal'),
                             ('odmm_nas_acl_export_v2148','attach_acl_signed_export'),
                             ('odmm_nas_acl_history_v2149','attach_acl_history'),
                             ('odmm_nas_acl_anchor_v2150','attach_anchor_status'),
                             ('odmm_nas_acl_cas_v2152','attach_acl_recovery_status'),
                             ('odmm_nas_acl_scale_v2153','attach_acl_scale_status'),
                             ('odmm_nas_acl_stream_v2154','attach_acl_stream_status'),
                             ('odmm_nas_acl_operations_v2157','attach_operations_diagnostics'),
                             ('odmm_nas_acl_verified_page_v2158','attach_verified_page')]:
            patches.append(patch(f'{module}.{name}',side_effect=noop))
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in patches:stack.enter_context(p)
            app = create_nas_acl_cas_operations_app(history_path=Path(tmp)/'h.db',registry_path=Path(tmp)/'r.db',
                resolve_verified_principal=resolver,nas_providers={},access_providers={},provenance_providers={},
                consistency_providers={},acl_providers={},audit_hmac_key=KEY,anchor_hmac_key=KEY,
                read_anchor=read_anchor,cas_anchor=cas_anchor)
        a=app.state.odmm_acl_anchored_history
        a.bootstrap_empty();a.record(document())
        c=TestClient(app);url='/api/v1/operations/nas-acl-audit/verified-snapshot'
        assert c.get(url).status_code==403
        response=c.get(url,headers={'x-test-role':'auditor'})
        assert response.status_code==200 and response.json()['external_anchor_verified'] is True
        assert response.json()['verified_head_seq']==1
        assert c.get(url+'?limit=101',headers={'x-test-role':'auditor'}).status_code==400
        anchor[0]=None
        assert c.get(url,headers={'x-test-role':'auditor'}).status_code==503
