"""V196.9 composition root: same mandatory authorization for portal and API.

No implicit authentication: hosting service must provide a VERIFIED principal
resolver (OIDC/session verification). No write routes are installed.
"""
from odmm_operations_api import attach_readonly_routes
from odmm_operations_portal import attach_operations_portal
from odmm_operations_security import make_request_authorizer


def create_operations_app(*, registry_path, resolve_verified_principal):
    if not callable(resolve_verified_principal):
        raise ValueError('VERIFIED_PRINCIPAL_RESOLVER_REQUIRED')
    from fastapi import FastAPI
    app = FastAPI(title='ODMM Operations', version='196.9')
    authorize = make_request_authorizer(resolve_verified_principal)
    attach_readonly_routes(app, registry_path=registry_path, authorize=authorize)
    attach_operations_portal(app, authorize=authorize)
    return app


def create_oidc_operations_app(*, registry_path, issuer, audience, jwks, role_claim='roles'):
    """Create read-only app with pinned-JWKS bearer authentication."""
    from odmm_oidc_verifier import OIDCVerifier
    verifier=OIDCVerifier(issuer=issuer,audience=audience,jwks=jwks,role_claim=role_claim)
    return create_operations_app(registry_path=registry_path,resolve_verified_principal=verifier.resolve_request)


def create_netapp_operations_app(*, registry_path, resolve_verified_principal, get_netapp_inventories):
    """Single authenticated operations portal with additional read-only NetApp routes."""
    from odmm_operations_security import make_request_authorizer
    from odmm_netapp_portal_v2081 import attach_netapp_preflight
    app=create_operations_app(registry_path=registry_path,resolve_verified_principal=resolve_verified_principal)
    attach_netapp_preflight(app,authorize=make_request_authorizer(resolve_verified_principal),get_inventories=get_netapp_inventories)
    return app


def create_netapp_full_operations_app(*, registry_path, resolve_verified_principal, get_netapp_inventories, get_netapp_differences):
    """Compose existing Operations + NetApp preflight + differences using one verified authorizer.

    Evidence providers are server-side only. No cutover or mutation routes.
    """
    if not callable(get_netapp_inventories) or not callable(get_netapp_differences):
        raise ValueError('NETAPP_SERVER_PROVIDERS_REQUIRED')
    from odmm_netapp_cockpit_v2085 import attach_netapp_differences
    app=create_netapp_operations_app(registry_path=registry_path,
        resolve_verified_principal=resolve_verified_principal,
        get_netapp_inventories=get_netapp_inventories)
    attach_netapp_differences(app,authorize=make_request_authorizer(resolve_verified_principal),
        get_evidence=get_netapp_differences)
    return app


def create_nas_qualification_operations_app(*, registry_path, resolve_verified_principal, nas_providers):
    """Mount NAS qualification on the existing authenticated Operations app.

    All three inventory providers must be supplied server-side; no default mock
    data or unauthenticated fallback is installed.
    """
    from odmm_nas_pair_portal_v2134 import attach_nas_pair_portal
    app=create_operations_app(registry_path=registry_path,
        resolve_verified_principal=resolve_verified_principal)
    attach_nas_pair_portal(app,
        authorize=make_request_authorizer(resolve_verified_principal),providers=nas_providers)
    return app


def create_nas_access_operations_app(*, registry_path, resolve_verified_principal, nas_providers, access_providers):
    """Compose NAS namespace and access audit on the same authorized Operations app."""
    from odmm_nas_probe_adapters_v2138 import attach_nas_access_audit
    app=create_nas_qualification_operations_app(registry_path=registry_path,
        resolve_verified_principal=resolve_verified_principal,nas_providers=nas_providers)
    attach_nas_access_audit(app,authorize=make_request_authorizer(resolve_verified_principal),providers=access_providers)
    return app


def create_nas_audit_dashboard_app(*, registry_path, resolve_verified_principal, nas_providers, access_providers):
    """Compose V213.9 dashboard on existing authenticated ODMM Operations portal."""
    from odmm_nas_transport_v2139 import attach_nas_access_dashboard
    app=create_nas_access_operations_app(registry_path=registry_path,
        resolve_verified_principal=resolve_verified_principal,
        nas_providers=nas_providers,access_providers=access_providers)
    attach_nas_access_dashboard(app,authorize=make_request_authorizer(resolve_verified_principal),providers=access_providers)
    return app


def create_nas_detailed_audit_app(*, registry_path, resolve_verified_principal, nas_providers, access_providers):
    """Single authenticated Operations app with dashboard and read-only detail pages."""
    from odmm_nas_access_detail_v2142 import attach_nas_access_detail
    app=create_nas_audit_dashboard_app(registry_path=registry_path,
        resolve_verified_principal=resolve_verified_principal,
        nas_providers=nas_providers,access_providers=access_providers)
    attach_nas_access_detail(app,authorize=make_request_authorizer(resolve_verified_principal),providers=access_providers)
    return app


def create_nas_integrated_operations_app(*, registry_path, resolve_verified_principal, nas_providers, access_providers, provenance_providers, consistency_providers):
    """Single Operations portal, all NAS dashboards, and read-only export."""
    from odmm_operations_security import make_request_authorizer
    from odmm_nas_provenance_portal_v2144 import attach_provenance_dashboard
    from odmm_nas_audit_export_v2145 import attach_nas_consistency_export
    app=create_nas_detailed_audit_app(registry_path=registry_path,resolve_verified_principal=resolve_verified_principal,nas_providers=nas_providers,access_providers=access_providers)
    authorize=make_request_authorizer(resolve_verified_principal)
    attach_provenance_dashboard(app,authorize=authorize,providers=provenance_providers)
    attach_nas_consistency_export(app,authorize=authorize,providers=consistency_providers)
    return app


def create_nas_acl_integrated_operations_app(*, registry_path, resolve_verified_principal, nas_providers, access_providers, provenance_providers, consistency_providers, acl_providers, audit_hmac_key):
    """V214.8: compose all read-only NAS pages, including ACL export; no mock fallback."""
    from odmm_nas_acl_portal_v2147 import attach_acl_audit_portal
    from odmm_nas_acl_export_v2148 import attach_acl_signed_export
    app=create_nas_integrated_operations_app(registry_path=registry_path,resolve_verified_principal=resolve_verified_principal,nas_providers=nas_providers,access_providers=access_providers,provenance_providers=provenance_providers,consistency_providers=consistency_providers)
    auth=make_request_authorizer(resolve_verified_principal)
    attach_acl_audit_portal(app,authorize=auth,providers=acl_providers)
    attach_acl_signed_export(app,authorize=auth,providers=acl_providers,hmac_key=audit_hmac_key)
    return app


def create_nas_acl_history_operations_app(*, history_path, registry_path, resolve_verified_principal, nas_providers, access_providers, provenance_providers, consistency_providers, acl_providers, audit_hmac_key):
    """V214.9: ACL export history persisted atomically before delivery."""
    from odmm_nas_acl_history_v2149 import AuditHistory, attach_acl_history
    from odmm_nas_acl_portal_v2147 import attach_acl_audit_portal
    from odmm_nas_acl_export_v2148 import attach_acl_signed_export
    app=create_nas_integrated_operations_app(registry_path=registry_path,resolve_verified_principal=resolve_verified_principal,nas_providers=nas_providers,access_providers=access_providers,provenance_providers=provenance_providers,consistency_providers=consistency_providers)
    auth=make_request_authorizer(resolve_verified_principal)
    history=AuditHistory(history_path,audit_hmac_key)
    attach_acl_audit_portal(app,authorize=auth,providers=acl_providers)
    attach_acl_signed_export(app,authorize=auth,providers=acl_providers,hmac_key=audit_hmac_key,record_export=history.record)
    attach_acl_history(app,authorize=auth,history=history)
    return app


def create_nas_acl_cas_operations_app(*, history_path, registry_path, resolve_verified_principal, nas_providers, access_providers, provenance_providers, consistency_providers, acl_providers, audit_hmac_key, anchor_hmac_key, read_anchor, cas_anchor):
    """Composition Operations with authenticated CAS-backed audit and recovery status."""
    from odmm_nas_acl_history_v2149 import AuditHistory, attach_acl_history
    from odmm_nas_acl_cas_v2152 import CASAnchoredHistory, attach_acl_recovery_status
    from odmm_nas_acl_export_v2148 import attach_acl_signed_export
    from odmm_nas_acl_portal_v2147 import attach_acl_audit_portal
    from odmm_nas_acl_anchor_v2150 import attach_anchor_status
    from odmm_operations_security import make_request_authorizer
    app=create_nas_integrated_operations_app(registry_path=registry_path,resolve_verified_principal=resolve_verified_principal,nas_providers=nas_providers,access_providers=access_providers,provenance_providers=provenance_providers,consistency_providers=consistency_providers)
    auth=make_request_authorizer(resolve_verified_principal)
    from odmm_nas_acl_stream_v2154 import StreamingAuditHistory, attach_acl_stream_status
    history=StreamingAuditHistory(history_path,audit_hmac_key)
    anchored=CASAnchoredHistory(history,read_anchor=read_anchor,cas_anchor=cas_anchor,anchor_key=anchor_hmac_key)
    attach_acl_audit_portal(app,authorize=auth,providers=acl_providers)
    attach_acl_signed_export(app,authorize=auth,providers=acl_providers,hmac_key=audit_hmac_key,record_export=anchored.record)
    attach_acl_history(app,authorize=auth,history=anchored)
    attach_anchor_status(app,authorize=auth,anchored_history=anchored)
    attach_acl_recovery_status(app,authorize=auth,anchored_history=anchored)
    from odmm_nas_acl_scale_v2153 import attach_acl_scale_status
    attach_acl_scale_status(app,authorize=auth,anchored_history=anchored)
    attach_acl_stream_status(app,authorize=auth,anchored_history=anchored)
    from odmm_nas_acl_operations_v2157 import attach_operations_diagnostics
    attach_operations_diagnostics(app,authorize=auth,anchored_history=anchored)
    from odmm_nas_acl_verified_page_v2158 import attach_verified_page
    attach_verified_page(app,authorize=auth,anchored_history=anchored)
    from odmm_nas_acl_verified_snapshot_v2164 import attach_verified_snapshot
    attach_verified_snapshot(app,authorize=make_request_authorizer(resolve_verified_principal, permission='audit:read'),anchored_history=anchored)
    app.state.odmm_acl_anchored_history=anchored
    return app

# V216.5 integration is installed by create_nas_acl_cas_operations_app above.
